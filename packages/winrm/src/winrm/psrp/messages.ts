// PSRP message header (MS-PSRP 2.2.1): 40 bytes, little-endian, then the
// CLIXML data as UTF-8. The two GUIDs travel in .NET byte order (the first
// three fields little-endian), as pypsrp packs uuid.bytes_le.
import { PSRemotingError } from '../errors.js';

export const Destination = { client: 1, server: 2 } as const;
export type Destination = (typeof Destination)[keyof typeof Destination];

// Every message type of MS-PSRP 2.2.1, by its wire value.
export const MessageType = {
  SESSION_CAPABILITY: 0x00010002,
  INIT_RUNSPACEPOOL: 0x00010004,
  PUBLIC_KEY: 0x00010005,
  ENCRYPTED_SESSION_KEY: 0x00010006,
  PUBLIC_KEY_REQUEST: 0x00010007,
  CONNECT_RUNSPACEPOOL: 0x00010008,
  RUNSPACEPOOL_INIT_DATA: 0x0002100b,
  RESET_RUNSPACE_STATE: 0x0002100c,
  SET_MAX_RUNSPACES: 0x00021002,
  SET_MIN_RUNSPACES: 0x00021003,
  RUNSPACE_AVAILABILITY: 0x00021004,
  RUNSPACEPOOL_STATE: 0x00021005,
  CREATE_PIPELINE: 0x00021006,
  GET_AVAILABLE_RUNSPACES: 0x00021007,
  USER_EVENT: 0x00021008,
  APPLICATION_PRIVATE_DATA: 0x00021009,
  GET_COMMAND_METADATA: 0x0002100a,
  RUNSPACEPOOL_HOST_CALL: 0x00021100,
  RUNSPACEPOOL_HOST_RESPONSE: 0x00021101,
  PIPELINE_INPUT: 0x00041002,
  END_OF_PIPELINE_INPUT: 0x00041003,
  PIPELINE_OUTPUT: 0x00041004,
  ERROR_RECORD: 0x00041005,
  PIPELINE_STATE: 0x00041006,
  DEBUG_RECORD: 0x00041007,
  VERBOSE_RECORD: 0x00041008,
  WARNING_RECORD: 0x00041009,
  PROGRESS_RECORD: 0x00041010,
  INFORMATION_RECORD: 0x00041011,
  PIPELINE_HOST_CALL: 0x00041100,
  PIPELINE_HOST_RESPONSE: 0x00041101,
} as const;
export type MessageType = (typeof MessageType)[keyof typeof MessageType];

const TYPE_NAMES = new Map<number, string>(Object.entries(MessageType).map(([name, value]) => [value, name]));

// The name of a message type for messages and logs; unknown values print in hex.
export function messageTypeName(type: number): string {
  return TYPE_NAMES.get(type) ?? `0x${type.toString(16).padStart(8, '0')}`;
}

export const EMPTY_GUID = '00000000-0000-0000-0000-000000000000';
export const MESSAGE_HEADER_BYTES = 40;
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface PsrpMessage {
  destination: Destination;
  messageType: number;
  // Runspace pool id and pipeline id, canonical lower-case text; the
  // pipeline id is EMPTY_GUID for a pool message.
  rpid: string;
  pid: string;
  // The CLIXML text (UTF-8 on the wire, without a byte order mark).
  data: string;
}

// A GUID's 16 bytes in .NET (little-endian) order.
export function guidToBytes(guid: string): Buffer {
  if (!GUID.test(guid)) throw new PSRemotingError(`PSRP: not a GUID: ${JSON.stringify(guid)}`);
  const hex = Buffer.from(guid.replace(/-/g, ''), 'hex');
  const out = Buffer.alloc(16);
  out[0] = hex[3] as number;
  out[1] = hex[2] as number;
  out[2] = hex[1] as number;
  out[3] = hex[0] as number;
  out[4] = hex[5] as number;
  out[5] = hex[4] as number;
  out[6] = hex[7] as number;
  out[7] = hex[6] as number;
  hex.copy(out, 8, 8, 16);
  return out;
}

// The canonical lower-case text of a GUID given in .NET byte order.
export function guidFromBytes(bytes: Buffer): string {
  if (bytes.length !== 16) throw new PSRemotingError(`PSRP: a GUID is 16 bytes, not ${bytes.length}`);
  const hex = (b: Buffer) => b.toString('hex');
  const d1 = hex(Buffer.from([bytes[3] as number, bytes[2] as number, bytes[1] as number, bytes[0] as number]));
  const d2 = hex(Buffer.from([bytes[5] as number, bytes[4] as number]));
  const d3 = hex(Buffer.from([bytes[7] as number, bytes[6] as number]));
  return `${d1}-${d2}-${d3}-${hex(bytes.subarray(8, 10))}-${hex(bytes.subarray(10, 16))}`;
}

export function encodeMessage(message: PsrpMessage): Buffer {
  const header = Buffer.alloc(MESSAGE_HEADER_BYTES);
  header.writeUInt32LE(message.destination, 0);
  header.writeUInt32LE(message.messageType >>> 0, 4);
  guidToBytes(message.rpid).copy(header, 8);
  guidToBytes(message.pid).copy(header, 24);
  return Buffer.concat([header, Buffer.from(message.data, 'utf8')]);
}

export function decodeMessage(bytes: Buffer): PsrpMessage {
  if (bytes.length < MESSAGE_HEADER_BYTES) {
    throw new PSRemotingError(`PSRP: message of ${bytes.length} bytes is shorter than its ${MESSAGE_HEADER_BYTES}-byte header`);
  }
  const destination = bytes.readUInt32LE(0);
  if (destination !== Destination.client && destination !== Destination.server) {
    throw new PSRemotingError(`PSRP: message destination ${destination} is neither client (1) nor server (2)`);
  }
  let data = bytes.subarray(MESSAGE_HEADER_BYTES);
  // A server message may start its data with a UTF-8 byte order mark.
  if (data.length >= 3 && data.subarray(0, 3).equals(UTF8_BOM)) data = data.subarray(3);
  return {
    destination,
    messageType: bytes.readUInt32LE(4),
    rpid: guidFromBytes(bytes.subarray(8, 24)),
    pid: guidFromBytes(bytes.subarray(24, 40)),
    data: data.toString('utf8'),
  };
}
