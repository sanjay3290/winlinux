import { XMLParser } from 'fast-xml-parser';
import { WinRMFaultError, WinRMProtocolError } from './errors.js';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  textNodeName: '#text',
  parseTagValue: false,
  trimValues: true,
  removeNSPrefix: true,
});

type XmlNode = Record<string, unknown>;

function asNode(value: unknown): XmlNode | null {
  return typeof value === 'object' && value !== null ? (value as XmlNode) : null;
}

function asArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function textOf(value: unknown): string {
  if (typeof value === 'string') return value;
  const node = asNode(value);
  const text = node?.['#text'];
  return typeof text === 'string' ? text : '';
}

function attrOf(value: unknown, name: string): string {
  const node = asNode(value);
  const attr = node?.[`@${name}`];
  return typeof attr === 'string' ? attr : '';
}

interface ParsedBody {
  body: XmlNode;
  raw: string;
}

function parseBody(xml: string): ParsedBody {
  let doc: unknown;
  try {
    doc = parser.parse(xml);
  } catch (err) {
    throw new WinRMProtocolError(`WinRM response is not valid XML: ${(err as Error).message}`);
  }
  const envelope = asNode(asNode(doc)?.['Envelope']);
  const body = asNode(envelope?.['Body']);
  if (!body) throw new WinRMProtocolError('WinRM response has no SOAP Body');
  return { body, raw: xml };
}

// Returns the fault when the response carries one, else null.
export function parseSoapFault(xml: string): WinRMFaultError | null {
  const { body, raw } = parseBody(xml);
  const fault = asNode(body['Fault']);
  if (!fault) return null;
  const code = asNode(fault['Code']);
  const subcode = asNode(code?.['Subcode']);
  const reasonNode = asNode(fault['Reason']);
  const detail = asNode(fault['Detail']);
  const wsmanFault = asNode(detail?.['WSManFault']);
  const reason = textOf(reasonNode?.['Text']) || '(no error message in fault)';
  const wsmanCodeRaw = attrOf(wsmanFault, 'Code');
  const wsmanCode = wsmanCodeRaw !== '' && Number.isFinite(Number(wsmanCodeRaw)) ? Number(wsmanCodeRaw) : null;
  const faultCode = textOf(code?.['Value']) || null;
  const faultSubcode = textOf(subcode?.['Value']) || null;
  const machine = attrOf(wsmanFault, 'Machine') || null;
  return new WinRMFaultError(
    `WinRM SOAP fault${faultSubcode ? ` (${faultSubcode})` : ''}${wsmanCode !== null ? ` [code ${wsmanCode}]` : ''}: ${reason}`,
    faultCode,
    faultSubcode,
    reason,
    wsmanCode,
    machine,
    raw,
  );
}

function throwIfFault(xml: string): ParsedBody {
  const fault = parseSoapFault(xml);
  if (fault) throw fault;
  return parseBody(xml);
}

export function parseCreateShellResponse(xml: string): string {
  const { body } = throwIfFault(xml);
  // Preferred: transfer/ResourceCreated reference parameters.
  const created = asNode(body['ResourceCreated']);
  const refParams = asNode(created?.['ReferenceParameters']);
  const selectorSet = asNode(refParams?.['SelectorSet']);
  for (const selector of asArray(selectorSet?.['Selector'])) {
    if (attrOf(selector, 'Name') === 'ShellId') {
      const id = textOf(selector);
      if (id) return id;
    }
  }
  // Fallback: rsp:Shell/rsp:ShellId shape.
  const shell = asNode(body['Shell']);
  const fallback = textOf(shell?.['ShellId']);
  if (fallback) return fallback;
  throw new WinRMProtocolError('Create shell response carries no ShellId');
}

export function parseCommandResponse(xml: string): string {
  const { body } = throwIfFault(xml);
  const response = asNode(body['CommandResponse']);
  const id = textOf(response?.['CommandId']);
  if (!id) throw new WinRMProtocolError('Command response carries no CommandId');
  return id;
}

export interface ReceivePoll {
  stdout: Buffer;
  stderr: Buffer;
  done: boolean;
  exitCode: number | null;
}

const COMMAND_STATE_DONE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done';

export function parseReceiveResponse(xml: string): ReceivePoll {
  const { body } = throwIfFault(xml);
  const response = asNode(body['ReceiveResponse']);
  if (!response) throw new WinRMProtocolError('Receive response has no ReceiveResponse element');
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  for (const stream of asArray(response['Stream'])) {
    const text = textOf(stream);
    if (!text) continue;
    const buf = Buffer.from(text, 'base64');
    if (attrOf(stream, 'Name') === 'stderr') stderr.push(buf);
    else stdout.push(buf);
  }
  let done = false;
  let exitCode: number | null = null;
  for (const state of asArray(response['CommandState'])) {
    if (attrOf(state, 'State') === COMMAND_STATE_DONE) {
      done = true;
      const raw = textOf(asNode(state)?.['ExitCode']);
      if (raw === '' || !Number.isInteger(Number(raw))) {
        throw new WinRMProtocolError('Command finished without a usable ExitCode');
      }
      exitCode = Number(raw);
    }
  }
  return { stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), done, exitCode };
}

// A PSRP ReceiveResponse (MS-PSRP 3.1.5.3.8): every rsp:Stream named
// stdout, in order, each with the CommandId it carries (none: the pool),
// and whether a CommandState/Done closed the pipeline. Any other stream
// name is discarded, and Done needs no ExitCode: a PSRP pipeline ends with
// a PIPELINE_STATE message instead.
export interface PsrpReceivePoll {
  streams: Array<{ commandId?: string; data: Buffer }>;
  done: boolean;
}

export function parsePsrpReceiveResponse(xml: string): PsrpReceivePoll {
  const { body } = throwIfFault(xml);
  const response = asNode(body['ReceiveResponse']);
  if (!response) throw new WinRMProtocolError('Receive response has no ReceiveResponse element');
  const streams: PsrpReceivePoll['streams'] = [];
  for (const stream of asArray(response['Stream'])) {
    if (attrOf(stream, 'Name') !== 'stdout') continue;
    const text = textOf(stream);
    if (!text) continue;
    const commandId = attrOf(stream, 'CommandId');
    streams.push({ ...(commandId ? { commandId } : {}), data: Buffer.from(text, 'base64') });
  }
  const done = asArray(response['CommandState']).some((state) => attrOf(state, 'State') === COMMAND_STATE_DONE);
  return { streams, done };
}

// Assembles Receive polls into the final command result.
export class ReceiveAccumulator {
  private out: Buffer[] = [];
  private err: Buffer[] = [];
  private finished = false;
  private code: number | null = null;

  push(poll: ReceivePoll): void {
    if (poll.stdout.length > 0) this.out.push(poll.stdout);
    if (poll.stderr.length > 0) this.err.push(poll.stderr);
    if (poll.done) {
      this.finished = true;
      this.code = poll.exitCode;
    }
  }

  get done(): boolean {
    return this.finished;
  }

  result(): { stdout: string; stderr: string; exitCode: number } {
    if (!this.finished || this.code === null) throw new WinRMProtocolError('Command output is incomplete: no Done state seen');
    return {
      stdout: Buffer.concat(this.out).toString('utf8'),
      stderr: Buffer.concat(this.err).toString('utf8'),
      exitCode: this.code,
    };
  }
}
