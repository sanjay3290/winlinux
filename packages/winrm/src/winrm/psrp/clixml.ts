// CLIXML (MS-PSRP 2.2.5): the serialization every PSRP message body uses.
// The reader turns the common CLIXML elements into plain JavaScript values
// and PSObject, and never throws on an element it does not know (it
// becomes kind 'unknown' with its XML). The writer produces the subset the
// client sends. A new RefId and TNRef space starts with every call
// (2.2.5.3.3), which is one message.
import { XMLBuilder, XMLParser, XMLValidator } from 'fast-xml-parser';
import { PSRemotingError } from '../errors.js';

export const CLIXML_NS = 'http://schemas.microsoft.com/powershell/2004/04';

// --- Values ---

export interface PSDateTime {
  kind: 'datetime';
  iso: string; // the text as sent, with its 7-digit fraction and offset
  date: Date;
}
export interface PSDuration {
  kind: 'duration';
  iso: string; // xs:duration, as sent
}
// The client keeps the ciphertext; it does not decrypt it yet.
export interface PSSecureString {
  kind: 'securestring';
  encrypted: string; // base64 as sent
}
export type PSDictionary = Map<PSValue, PSValue>;

export type PSObjectKind = 'object' | 'guid' | 'uri' | 'version' | 'xml' | 'scriptblock' | 'unknown';

export interface PSObject {
  kind: PSObjectKind;
  typeNames: string[]; // TN, most derived first; empty when none was sent
  toStringValue?: string; // ToString
  adapted: Map<string, PSValue>; // Props
  extended: Map<string, PSValue>; // MS
  // The text of a tagged primitive (guid, uri, version, xml, scriptblock),
  // or the value of an extended primitive or enum (2.2.5.2.5, 2.2.5.2.7),
  // or the container of an object that also carries properties.
  value?: PSValue;
  // kind 'unknown': the element as it was sent.
  xml?: string;
}

export type PSValue = null | boolean | number | bigint | string | Buffer | PSDateTime | PSDuration | PSSecureString | PSObject | PSValue[] | PSDictionary;

export interface PSProgressRecord {
  activity: string;
  activityId: number;
  currentOperation: string | null;
  parentActivityId: number;
  percentComplete: number;
  type: string; // Processing or Completed
  secondsRemaining: number;
  statusDescription: string;
}

export interface PSErrorRecord {
  message: string;
  fullyQualifiedErrorId: string;
  category: number; // ErrorCategory_Category (System.Management.Automation.ErrorCategory)
  categoryInfo: string; // ErrorCategory_Message, as PowerShell prints it after "+ CategoryInfo"
  targetName: string;
  exceptionType?: string;
  scriptStackTrace?: string;
  invocationInfo?: PSObject;
  record: PSObject; // the whole object, for anything above
}

export interface PSInformationRecord {
  messageData: PSValue;
  source: string;
  timeGenerated?: PSDateTime;
  tags: string[];
  user: string;
  computer: string;
  record: PSObject;
}

export function isPSObject(value: PSValue): value is PSObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !Buffer.isBuffer(value) && !(value instanceof Map) && 'typeNames' in value;
}

function tagged(kind: Exclude<PSObjectKind, 'object' | 'unknown'>, value: string): PSObject {
  return { kind, typeNames: [], adapted: new Map(), extended: new Map(), value };
}

// Constructors for the values the client writes.
export const psGuid = (text: string): PSObject => tagged('guid', text);
export const psUri = (text: string): PSObject => tagged('uri', text);
export const psVersion = (text: string): PSObject => tagged('version', text);
export const psXml = (text: string): PSObject => tagged('xml', text);
export const psScriptBlock = (text: string): PSObject => tagged('scriptblock', text);
export function psDateTime(date: Date): PSDateTime {
  return { kind: 'datetime', iso: date.toISOString(), date };
}
// An enum (2.2.5.2.7): the type names, the name as ToString and the value.
export function psEnum(typeNames: string[], name: string, value: number): PSObject {
  return { kind: 'object', typeNames, toStringValue: name, adapted: new Map(), extended: new Map(), value };
}
// A complex object with extended properties (MS), as the PSRP message
// bodies are written.
export function psObject(extended: Record<string, PSValue> | Map<string, PSValue>, typeNames: string[] = [], toString?: string): PSObject {
  const out: PSObject = { kind: 'object', typeNames, adapted: new Map(), extended: extended instanceof Map ? extended : new Map(Object.entries(extended)) };
  if (toString !== undefined) out.toStringValue = toString;
  return out;
}

// --- String escaping (2.2.5.3.2) ---
// Characters XML cannot carry (controls, lone surrogates, U+FFFE and
// U+FFFF) go out as _xHHHH_ per UTF-16 code unit. An underscore that
// would start such a sequence is written as _x005F_, so a text that
// contains a literal "_x000A_" survives the round trip.
// A surrogate pair (an astral character) is valid XML and stays as it is;
// the first alternative matches it so the second only sees lone ones.
const ESCAPED = /[\ud800-\udbff][\udc00-\udfff]|[\u0000-\u001f\u007f-\u009f\ud800-\udfff\ufffe\uffff]|_(?=x[0-9A-Fa-f]{4}_)/g;
export function escapeClixmlString(text: string): string {
  return text.replace(ESCAPED, (c) => (c.length === 2 ? c : `_x${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}_`));
}
export function unescapeClixmlString(text: string): string {
  return text.replace(/_x([0-9A-Fa-f]{4})_/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

// --- Reading ---

type Attrs = Record<string, string>;
// fast-xml-parser's ordered node: one tag key with the children, and ':@' with the attributes.
type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  textNodeName: '#text',
  preserveOrder: true,
  parseTagValue: false,
  trimValues: false,
  processEntities: true,
  removeNSPrefix: true,
});
const builder = new XMLBuilder({ ignoreAttributes: false, attributeNamePrefix: '@', textNodeName: '#text', preserveOrder: true, suppressEmptyNode: true });

interface Element {
  tag: string;
  attrs: Attrs;
  children: Element[];
  text: string;
  node: Node; // for the XML of an unknown element
}

function toElement(node: Node): Element | null {
  const tag = Object.keys(node).find((k) => k !== ':@');
  if (tag === undefined) return null;
  const attrs = (node[':@'] as Attrs | undefined) ?? {};
  const raw = node[tag];
  const kids = Array.isArray(raw) ? (raw as Node[]) : [];
  const children: Element[] = [];
  let text = '';
  for (const kid of kids) {
    if ('#text' in kid) text += String(kid['#text']);
    else {
      const child = toElement(kid);
      if (child) children.push(child);
    }
  }
  const clean: Attrs = {};
  for (const [k, v] of Object.entries(attrs)) clean[k.startsWith('@') ? k.slice(1) : k] = String(v);
  return { tag, attrs: clean, children, text, node };
}

const INT_TAGS = new Set(['By', 'SB', 'U16', 'I16', 'U32', 'I32']);
const BIG_TAGS = new Set(['U64', 'I64']);
const FLOAT_TAGS = new Set(['Sg', 'Db']);
const CONTAINER_TAGS = new Set(['LST', 'IE', 'STK', 'QUE', 'DCT']);
const TAGGED: Record<string, Exclude<PSObjectKind, 'object' | 'unknown'>> = { G: 'guid', URI: 'uri', Version: 'version', XD: 'xml', SBK: 'scriptblock' };

function parseFloatText(text: string): number {
  if (text === 'INF') return Infinity;
  if (text === '-INF') return -Infinity;
  if (text === 'NaN') return NaN;
  return Number(text);
}

class Reader {
  private readonly objects = new Map<string, PSValue>();
  private readonly typeNames = new Map<string, string[]>();

  read(el: Element): PSValue {
    const text = el.text;
    switch (el.tag) {
      case 'S':
        return unescapeClixmlString(text);
      case 'C':
        return String.fromCodePoint(Number(text));
      case 'B':
        return text.trim().toLowerCase() === 'true';
      case 'DT':
        return { kind: 'datetime', iso: text, date: new Date(text) };
      case 'TS':
        return { kind: 'duration', iso: text };
      case 'D':
        return text;
      case 'BA':
        return Buffer.from(text, 'base64');
      case 'Nil':
        return null;
      case 'SS':
        return { kind: 'securestring', encrypted: text };
      case 'PR':
        return progressRecordObject(this.progress(el));
      case 'Ref': {
        const id = el.attrs['RefId'] ?? '';
        if (!this.objects.has(id)) throw new PSRemotingError(`CLIXML: Ref to unknown RefId ${id}`);
        return this.objects.get(id) as PSValue;
      }
      case 'Obj':
        return this.object(el);
      case 'Objs':
        return el.children.map((c) => this.read(c));
    }
    if (INT_TAGS.has(el.tag)) return Number(text);
    if (BIG_TAGS.has(el.tag)) return BigInt(text.trim());
    if (FLOAT_TAGS.has(el.tag)) return parseFloatText(text.trim());
    if (CONTAINER_TAGS.has(el.tag)) return this.container(el);
    const kind = TAGGED[el.tag];
    if (kind) return tagged(kind, unescapeClixmlString(text));
    return { kind: 'unknown', typeNames: [], adapted: new Map(), extended: new Map(), xml: builder.build([el.node]) as string };
  }

  readAll(root: Element[]): PSValue[] {
    const out: PSValue[] = [];
    for (const el of root) {
      const value = this.read(el);
      if (el.tag === 'Objs') out.push(...(value as PSValue[]));
      else out.push(value);
    }
    return out;
  }

  private container(el: Element): PSValue {
    if (el.tag !== 'DCT') return el.children.map((c) => this.read(c));
    const map: PSDictionary = new Map();
    for (const entry of el.children) {
      if (entry.tag !== 'En') continue;
      let key: PSValue = null;
      let value: PSValue = null;
      for (const field of entry.children) {
        if (field.attrs['N'] === 'Key') key = this.read(field);
        else if (field.attrs['N'] === 'Value') value = this.read(field);
      }
      map.set(key, value);
    }
    return map;
  }

  private object(el: Element): PSValue {
    const refId = el.attrs['RefId'];
    const obj: PSObject = { kind: 'object', typeNames: [], adapted: new Map(), extended: new Map() };
    // Register before reading the children, so a child Ref to this object resolves.
    if (refId !== undefined) this.objects.set(refId, obj);
    let container: PSValue | undefined;
    for (const child of el.children) {
      switch (child.tag) {
        case 'TN': {
          obj.typeNames = child.children.filter((t) => t.tag === 'T').map((t) => unescapeClixmlString(t.text));
          const id = child.attrs['RefId'];
          if (id !== undefined) this.typeNames.set(id, obj.typeNames);
          break;
        }
        case 'TNRef':
          obj.typeNames = this.typeNames.get(child.attrs['RefId'] ?? '') ?? [];
          break;
        case 'ToString':
          obj.toStringValue = unescapeClixmlString(child.text);
          break;
        case 'Props':
          for (const p of child.children) obj.adapted.set(unescapeClixmlString(p.attrs['N'] ?? ''), this.read(p));
          break;
        case 'MS':
          for (const p of child.children) obj.extended.set(unescapeClixmlString(p.attrs['N'] ?? ''), this.read(p));
          break;
        default:
          if (CONTAINER_TAGS.has(child.tag)) container = this.read(child);
          else obj.value = this.read(child); // extended primitive or enum value
      }
    }
    // A plain container (2.2.5.2.6) is the array or map itself, so a list
    // of strings is a string[]; one with properties keeps them, with the
    // container as its value.
    if (container !== undefined) {
      if (obj.adapted.size === 0 && obj.extended.size === 0) {
        if (refId !== undefined) this.objects.set(refId, container);
        return container;
      }
      obj.value = container;
    }
    return obj;
  }

  private progress(el: Element): PSProgressRecord {
    const field = (tag: string): Element | undefined => el.children.find((c) => c.tag === tag);
    const num = (tag: string): number => Number(field(tag)?.text ?? '-1');
    const str = (tag: string): string => unescapeClixmlString(field(tag)?.text ?? '');
    // CurrentOperation is the third child: Nil when absent (2.2.5.1.25).
    const third = el.children[2];
    const currentOperation = third && third.tag !== 'Nil' && !['PI', 'PC', 'T', 'SR', 'SD'].includes(third.tag) ? unescapeClixmlString(third.text) : null;
    return {
      activity: str('AV'),
      activityId: num('AI'),
      currentOperation,
      parentActivityId: num('PI'),
      percentComplete: num('PC'),
      type: str('T'),
      secondsRemaining: num('SR'),
      statusDescription: str('SD'),
    };
  }
}

export const PROGRESS_RECORD_TYPE = 'System.Management.Automation.ProgressRecord';

function progressRecordObject(record: PSProgressRecord): PSObject {
  return psObject(
    {
      Activity: record.activity,
      ActivityId: record.activityId,
      CurrentOperation: record.currentOperation,
      ParentActivityId: record.parentActivityId,
      PercentComplete: record.percentComplete,
      RecordType: record.type,
      SecondsRemaining: record.secondsRemaining,
      StatusDescription: record.statusDescription,
    },
    [PROGRESS_RECORD_TYPE, 'System.Object'],
  );
}

// Strips an XML declaration and wraps the document, so a message whose
// data holds several top-level elements still parses.
export function deserializeClixml(xml: string): PSValue[] {
  const body = xml.replace(/^﻿/, '').replace(/^\s*<\?xml[^>]*\?>/, '');
  const wrapped = `<clixml-root>${body}</clixml-root>`;
  // The parser is lenient; the validator is not.
  const valid = XMLValidator.validate(wrapped);
  if (valid !== true) throw new PSRemotingError(`CLIXML: not well-formed: ${valid.err.msg}`);
  let doc: unknown;
  try {
    doc = parser.parse(wrapped);
  } catch (err) {
    throw new PSRemotingError(`CLIXML: not well-formed: ${(err as Error).message}`);
  }
  const root = Array.isArray(doc) ? (doc as Node[]).map(toElement).find((e) => e?.tag === 'clixml-root') : null;
  if (!root) throw new PSRemotingError('CLIXML: empty document');
  return new Reader().readAll(root.children);
}

// --- Typed records from PSObject (2.2.3.15, 2.2.3.16, 2.2.2.26) ---

const str = (v: PSValue | undefined): string => (typeof v === 'string' ? v : v === null || v === undefined ? '' : isPSObject(v) ? (v.toStringValue ?? '') : String(v));
const prop = (obj: PSObject, name: string): PSValue | undefined => (obj.extended.has(name) ? obj.extended.get(name) : obj.adapted.get(name));

export const ERROR_RECORD_TYPE = 'System.Management.Automation.ErrorRecord';

export function toErrorRecord(obj: PSObject): PSErrorRecord {
  const exception = prop(obj, 'Exception') ?? null;
  const exceptionMessage = isPSObject(exception) ? str(prop(exception, 'Message')) : str(exception);
  const detailsMessage = str(prop(obj, 'ErrorDetails_Message'));
  const out: PSErrorRecord = {
    message: detailsMessage || exceptionMessage || obj.toStringValue || '',
    fullyQualifiedErrorId: str(prop(obj, 'FullyQualifiedErrorId')),
    category: Number(prop(obj, 'ErrorCategory_Category') ?? 0),
    categoryInfo: str(prop(obj, 'ErrorCategory_Message')),
    targetName: str(prop(obj, 'ErrorCategory_TargetName')),
    record: obj,
  };
  if (isPSObject(exception) && exception.typeNames.length > 0) out.exceptionType = exception.typeNames[0] as string;
  const stack = prop(obj, 'ScriptStackTrace');
  if (typeof stack === 'string' && stack.length > 0) out.scriptStackTrace = stack;
  const invocation = prop(obj, 'InvocationInfo') ?? null;
  if (isPSObject(invocation)) out.invocationInfo = invocation;
  return out;
}

// Warning, verbose and debug records (2.2.3.16).
export function toInformationalMessage(obj: PSObject): string {
  return str(prop(obj, 'InformationalRecord_Message') ?? obj.toStringValue ?? null);
}

export const INFORMATION_RECORD_TYPE = 'System.Management.Automation.InformationRecord';

export function toInformationRecord(obj: PSObject): PSInformationRecord {
  const tags = prop(obj, 'Tags');
  const time = prop(obj, 'TimeGenerated');
  const out: PSInformationRecord = {
    messageData: prop(obj, 'MessageData') ?? null,
    source: str(prop(obj, 'Source')),
    tags: Array.isArray(tags) ? tags.map((t) => str(t)) : [],
    user: str(prop(obj, 'User')),
    computer: str(prop(obj, 'Computer')),
    record: obj,
  };
  if (typeof time === 'object' && time !== null && 'kind' in time && time.kind === 'datetime') out.timeGenerated = time;
  return out;
}

export function toProgressRecord(obj: PSObject): PSProgressRecord {
  const n = (name: string): number => Number(prop(obj, name) ?? -1);
  const current = prop(obj, 'CurrentOperation');
  return {
    activity: str(prop(obj, 'Activity')),
    activityId: n('ActivityId'),
    currentOperation: current === null || current === undefined ? null : str(current),
    parentActivityId: n('ParentActivityId'),
    percentComplete: n('PercentComplete'),
    type: str(prop(obj, 'RecordType')),
    secondsRemaining: n('SecondsRemaining'),
    statusDescription: str(prop(obj, 'StatusDescription')),
  };
}

// --- Writing ---

const ARRAY_TYPES = ['System.Object[]', 'System.Array', 'System.Object'];
const HASHTABLE_TYPES = ['System.Collections.Hashtable', 'System.Object'];

function xmlText(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function xmlAttr(text: string): string {
  return xmlText(text).replace(/"/g, '&quot;');
}

class Writer {
  private nextRef = 0;
  private nextTypeRef = 0;
  private readonly refs = new Map<object, number>();
  private readonly typeRefs = new Map<string, number>();

  write(value: PSValue, name?: string): string {
    const n = name === undefined ? '' : ` N="${xmlAttr(escapeClixmlString(name))}"`;
    if (value === null || value === undefined) return `<Nil${n}/>`;
    if (typeof value === 'string') return `<S${n}>${xmlText(escapeClixmlString(value))}</S>`;
    if (typeof value === 'boolean') return `<B${n}>${value}</B>`;
    if (typeof value === 'bigint') return `<I64${n}>${value}</I64>`;
    if (typeof value === 'number') {
      if (Number.isInteger(value)) return value >= -2147483648 && value <= 2147483647 ? `<I32${n}>${value}</I32>` : `<I64${n}>${value}</I64>`;
      const text = value === Infinity ? 'INF' : value === -Infinity ? '-INF' : Number.isNaN(value) ? 'NaN' : String(value);
      return `<Db${n}>${text}</Db>`;
    }
    if (Buffer.isBuffer(value)) return `<BA${n}>${value.toString('base64')}</BA>`;
    if (value instanceof Date) return `<DT${n}>${value.toISOString()}</DT>`;
    if (Array.isArray(value)) return this.ref(value, n) ?? this.open(value, n, ARRAY_TYPES, () => `<LST>${value.map((v) => this.write(v)).join('')}</LST>`);
    if (value instanceof Map) return this.ref(value, n) ?? this.open(value, n, HASHTABLE_TYPES, () => `<DCT>${this.entries(value)}</DCT>`);
    if ('kind' in value) {
      switch (value.kind) {
        case 'datetime':
          return `<DT${n}>${xmlText(value.iso)}</DT>`;
        case 'duration':
          return `<TS${n}>${xmlText(value.iso)}</TS>`;
        case 'securestring':
          return `<SS${n}>${xmlText(value.encrypted)}</SS>`;
        case 'guid':
          return `<G${n}>${xmlText(String(value.value))}</G>`;
        case 'uri':
          return `<URI${n}>${xmlText(escapeClixmlString(String(value.value)))}</URI>`;
        case 'version':
          return `<Version${n}>${xmlText(String(value.value))}</Version>`;
        case 'xml':
          return `<XD${n}>${xmlText(escapeClixmlString(String(value.value)))}</XD>`;
        case 'scriptblock':
          return `<SBK${n}>${xmlText(escapeClixmlString(String(value.value)))}</SBK>`;
        case 'unknown':
          throw new PSRemotingError('CLIXML: cannot write an unknown element back');
        case 'object':
          return this.ref(value, n) ?? this.complex(value, n);
      }
    }
    throw new PSRemotingError(`CLIXML: cannot serialize ${typeof value}`);
  }

  private ref(value: object, n: string): string | null {
    const id = this.refs.get(value);
    return id === undefined ? null : `<Ref${n} RefId="${id}"/>`;
  }

  private entries(map: PSDictionary): string {
    return [...map.entries()].map(([k, v]) => `<En>${this.write(k, 'Key')}${this.write(v, 'Value')}</En>`).join('');
  }

  // The container takes its RefId before its children take theirs, as
  // PowerShell numbers them (depth first, parent first).
  private open(value: object, n: string, typeNames: string[], body: () => string): string {
    const id = this.nextRef++;
    this.refs.set(value, id);
    const types = this.types(typeNames);
    return `<Obj${n} RefId="${id}">${types}${body()}</Obj>`;
  }

  private types(typeNames: string[]): string {
    if (typeNames.length === 0) return '';
    const key = typeNames.join('\n');
    const seen = this.typeRefs.get(key);
    if (seen !== undefined) return `<TNRef RefId="${seen}"/>`;
    const id = this.nextTypeRef++;
    this.typeRefs.set(key, id);
    return `<TN RefId="${id}">${typeNames.map((t) => `<T>${xmlText(escapeClixmlString(t))}</T>`).join('')}</TN>`;
  }

  private complex(obj: PSObject, n: string): string {
    const id = this.nextRef++;
    this.refs.set(obj, id);
    let body = this.types(obj.typeNames);
    if (obj.toStringValue !== undefined) body += `<ToString>${xmlText(escapeClixmlString(obj.toStringValue))}</ToString>`;
    if (obj.value !== undefined) {
      const inner = obj.value;
      // A container value goes out bare inside the object, not as a nested Obj.
      if (Array.isArray(inner)) body += `<LST>${inner.map((v) => this.write(v)).join('')}</LST>`;
      else if (inner instanceof Map) body += `<DCT>${this.entries(inner)}</DCT>`;
      else body += this.write(inner);
    }
    if (obj.adapted.size > 0) body += `<Props>${[...obj.adapted.entries()].map(([k, v]) => this.write(v, k)).join('')}</Props>`;
    if (obj.extended.size > 0) body += `<MS>${[...obj.extended.entries()].map(([k, v]) => this.write(v, k)).join('')}</MS>`;
    return `<Obj${n} RefId="${id}">${body}</Obj>`;
  }
}

// One value as CLIXML, the way a PSRP message body carries it: a bare
// top-level element, no Objs wrapper and no namespace, as the spec
// examples and pypsrp send.
export function serializeClixml(value: PSValue): string {
  return new Writer().write(value);
}

// --- JSON view ---

// A PSObject becomes an object of its adapted plus extended properties,
// "@type" the first type name, "@toString" the ToString text, "@value"
// an extended primitive or enum value. A second visit of the same object
// in one tree is cut to {"@ref": true}. bigint, decimal and 64-bit values
// are decimal strings; dates are ISO text; bytes are base64.
export function toJson(value: PSValue, seen = new Set<object>()): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (Array.isArray(value)) {
    if (seen.has(value)) return { '@ref': true };
    seen.add(value);
    const out = value.map((v) => toJson(v, seen));
    seen.delete(value);
    return out;
  }
  if (value instanceof Map) {
    if (seen.has(value)) return { '@ref': true };
    seen.add(value);
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) out[typeof k === 'string' ? k : String(toJson(k, seen))] = toJson(v, seen);
    seen.delete(value);
    return out;
  }
  switch (value.kind) {
    case 'datetime':
      return value.iso;
    case 'duration':
      return value.iso;
    case 'securestring':
      return { '@type': 'System.Security.SecureString' };
    case 'guid':
    case 'uri':
    case 'version':
    case 'xml':
    case 'scriptblock':
      return value.value;
    case 'unknown':
      return { '@type': 'unknown', '@xml': value.xml };
    case 'object': {
      if (seen.has(value)) return { '@ref': true };
      seen.add(value);
      const out: Record<string, unknown> = {};
      if (value.typeNames[0] !== undefined) out['@type'] = value.typeNames[0];
      if (value.toStringValue !== undefined) out['@toString'] = value.toStringValue;
      if (value.value !== undefined) out['@value'] = toJson(value.value, seen);
      for (const [k, v] of value.adapted) out[k] = toJson(v, seen);
      for (const [k, v] of value.extended) out[k] = toJson(v, seen);
      seen.delete(value);
      return out;
    }
  }
}
