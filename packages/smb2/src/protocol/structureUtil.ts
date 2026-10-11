import Value from "./Value.js";
import Structure from "./Structure.js";
import StructureField from "./StructureField.js";
import { SmbError } from "../errors.js";

// ms between the Windows FILETIME epoch (1601-01-01) and the Unix epoch.
const filetimeEpochOffsetMs = 11644473600000;

// The most entries one list response may carry. A real one is
// bounded by the client's OutputBufferLength (64 KiB), far below this.
export const MAX_LIST_ENTRIES = 65536;

// Server data that does not fit its own offsets and lengths.
export const malformed = (what: string) => new SmbError(`malformed ${what}`);

const isLength = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export const parseStructure = (buffer: Buffer, structure: Structure) => {
  let offset = 0;
  const data: any = {};
  const structureFieldNames = Object.keys(structure);
  for (const structureFieldName of structureFieldNames) {
    const structureField = structure[structureFieldName];

    let size: number;
    if (structureField.sizeFieldName) {
      size = data[structureField.sizeFieldName] as number;
      if (typeof size === "undefined") throw new Error(`invalid_size_field_name: ${structureField.sizeFieldName}`);
    } else if (typeof structureField.size === "number") {
      size = structureField.size;
    } else throw new Error(`unknown_field_size`);
    if (!isLength(size)) throw malformed(`structure: field ${structureFieldName} has size ${String(size)}`);

    structureField.count = typeof structureField.count === "number" ?
      structureField.count :
      1;
    if (structureField.countFieldName) {
      structureField.count = data[structureField.countFieldName] as number;
      if (typeof structureField.count === "undefined") throw new Error(`invalid_count_field_name: ${structureField.countFieldName}`);
    }
    if (!isLength(structureField.count)) throw malformed(`structure: field ${structureFieldName} has count ${String(structureField.count)}`);

    // A field may run past the end of the buffer: an SMB2 ERROR response
    // has a short ERROR body that is parsed with the command's own
    // structure, so fixed fields read short and a variable-length field
    // keeps only the bytes present. parseValue never reads past them.
    const value = buffer.slice(offset, offset + (size * structureField.count));
    data[structureFieldName] = parseValue(value, structureField);
    offset += size * structureField.count;
  }

  return data;
};

export const parseNumber = (buffer: Buffer, structureField: StructureField) => {
  if (structureField.size === 2 && buffer.length === 2) {
    return structureField.signedness === "Unsigned" ?
      buffer.readUInt16LE(0) :
      buffer.readInt16LE(0);
  }
  if (structureField.size === 4 && buffer.length === 4) {
    return structureField.signedness === "Unsigned" ?
      buffer.readUInt32LE(0) :
      buffer.readInt32LE(0);
  }
  if (structureField.size === 8 && buffer.length === 8) {
    return structureField.signedness === "Unsigned" ?
      buffer.readBigUInt64LE(0) :
      buffer.readBigInt64LE(0);
  }

  let result = 0;
  for (let index = 0; index < buffer.length; index++) {
    result += buffer.readUInt8(index) << (index * 8);
  }
  return result;
};

export const parseValue = (buffer: Buffer, structureField: StructureField): Value => {
  if (structureField.count > 1) {
    // No more elements than the bytes present, whatever the count says.
    const count = Math.min(structureField.count, structureField.size > 0 ? Math.ceil(buffer.length / structureField.size) : 0);
    const entryBuffers: Buffer[] = [];
    for (let index = 0; index < count; index++) {
      const entryBuffer = buffer.slice(index * structureField.size, (index + 1) * structureField.size);
      entryBuffers.push(entryBuffer);
    }
    return entryBuffers.map(entryBuffer => parseValue(entryBuffer, { ...structureField, count: 1 }));
  }

  let value: Value = buffer;
  if (structureField.type === String) value = parseString(buffer, structureField);
  else if (structureField.type === Number) value = parseNumber(buffer, structureField);
  return value;
};

export const parseString = (buffer: Buffer, structureField: StructureField) => {
  return buffer.slice(0, structureField.size).toString(structureField.encoding);
};

export const parseDate = (buffer: Buffer) => {
  const milliseconds = Number(buffer.readBigUInt64LE(0) / 10000n);
  return new Date(milliseconds - filetimeEpochOffsetMs);
};

export const parseEnumValue = (enumObject: any, value: number | string) => {
  return Object.keys(enumObject)
    .find(x => enumObject[x] === value);
};

export const parseEnumValues = (enumObject: any, value: number) => {
  return Object.keys(enumObject)
    .filter(x => (enumObject[x] & value) !== 0);
};

export const parseList = <EntryType = any>(buffer: Buffer, parser: (entryBuffer: Buffer) => EntryType) => {
  if (buffer.length === 0) return [];

  let currentOffset = 0;
  let nextEntryOffset = -1;

  const list: EntryType[] = [];
  while (nextEntryOffset !== 0) {
    if (list.length >= MAX_LIST_ENTRIES) throw malformed(`list: more than ${MAX_LIST_ENTRIES} entries`);
    if (currentOffset + 4 > buffer.length) {
      throw malformed(`list: entry at offset ${currentOffset} is past the end of the ${buffer.length}-byte buffer`);
    }
    nextEntryOffset = buffer.readUInt32LE(currentOffset);
    // Forward past this entry's own NextEntryOffset, and room for the next one's.
    if (nextEntryOffset !== 0 && (nextEntryOffset < 4 || currentOffset + nextEntryOffset + 4 > buffer.length)) {
      throw malformed(`list: NextEntryOffset ${nextEntryOffset} at offset ${currentOffset} does not fit the ${buffer.length}-byte buffer`);
    }

    const entryBufferStart = currentOffset + 4;
    const entryBufferEnd = nextEntryOffset === 0 ?
      buffer.length :
      currentOffset + nextEntryOffset;
    const entryBuffer = buffer.slice(entryBufferStart, entryBufferEnd);

    list.push(parser(entryBuffer));

    currentOffset += nextEntryOffset;
  }

  return list;
};

export const serializeStructure = (structure: Structure, data: any) => {
  const normalizedData: { [fieldName: string]: { value?: Buffer; size?: number; } } = {};
  const structureFieldNames = Object.keys(structure);
  for (const structureFieldName of structureFieldNames) {
    const structureField = structure[structureFieldName];

    const value = typeof data[structureFieldName] !== "undefined" ?
      data[structureFieldName] :
      structureField.defaultValue || 0;

    normalizedData[structureFieldName] = {};

    if (structureField.sizeFieldName) {
      structureField.size = Buffer.isBuffer(value) ?
        value.length :
        0;

      const referencedStructureField = structure[structureField.sizeFieldName];
      normalizedData[structureField.sizeFieldName].value = serializeValue(
        structureField.size,
        referencedStructureField
      );
    }

    structureField.count = typeof structureField.count === "number" ?
      structureField.count :
      1;
    if (structureField.countFieldName) {
      structureField.count = Array.isArray(value) ?
        value.length :
        0;

      const referencedStructureField = structure[structureField.countFieldName];
      normalizedData[structureField.countFieldName].value = serializeValue(
        structureField.count,
        referencedStructureField
      );
    }

    normalizedData[structureFieldName].value = serializeValue(value, structureField);
    normalizedData[structureFieldName].size = structureField.size * structureField.count;
  }

  const normalizedFields = structureFieldNames.map(x => normalizedData[x]);
  const bufferSize = normalizedFields.reduce((prev, current) => prev + current.size, 0);
  const buffer = Buffer.allocUnsafe(bufferSize);

  let offset = 0;
  for (const normalizedField of normalizedFields) {
    normalizedField.value.copy(buffer, offset);

    offset += normalizedField.size;
  }

  return buffer;
};

export const serializeValue = (value: Value, structureField: StructureField): Buffer => {
  if (structureField.count > 1 && Array.isArray(value)) {
    const buffers = value.map(listEntry => serializeValue(listEntry, { ...structureField, count: 1 }));
    return Buffer.concat(buffers);
  }
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return serializeString(value, structureField);
  if (Array.isArray(value)) return Buffer.from(value as ArrayLike<number>);

  const bignumberValue = BigInt(value);
  const result = Buffer.allocUnsafe(structureField.size);
  for (let index = 0; index < structureField.size; index++) {
    const offset = BigInt(index * 8);
    const byte = 0xffn & (bignumberValue >> offset);
    result.writeUInt8(Number(byte), index);
  }

  return result;
};

export const serializeDate = (date: Date) => {
  const milliseconds = date.getTime() + filetimeEpochOffsetMs;
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeBigInt64LE(BigInt(milliseconds) * 10000n, 0);
  return buffer;
};

export const serializeString = (value: string, structureField: StructureField) => {
  return Buffer.from(value, structureField.encoding);
};