import { XMLBuilder } from 'fast-xml-parser';

export const RESOURCE_URI_SHELL_CMD = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd';
export const ANONYMOUS_ROLE = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous';
export const MAX_ENVELOPE_SIZE = 153600;
export const SIGNAL_TERMINATE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate';
// Room left for the SOAP header and body markup of a Send. A Send
// envelope is about 1.3 KB without its data; 4 KB covers a host name of
// 253 characters and long ids.
export const SEND_ENVELOPE_OVERHEAD = 4096;
// The most stdin bytes one Send carries. They travel as base64 (4 bytes
// for every 3), so the envelope stays under MAX_ENVELOPE_SIZE.
export const SEND_CHUNK_BYTES = Math.floor((MAX_ENVELOPE_SIZE - SEND_ENVELOPE_OVERHEAD) / 4) * 3;

const ACTION = {
  create: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
  command: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
  receive: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
  send: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send',
  signal: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
  delete: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
} as const;

export interface EnvelopeBase {
  to: string;
  messageId: string;
  operationTimeout: string;
}

interface HeaderArgs extends EnvelopeBase {
  action: string;
  shellId?: string;
  options?: Array<{ name: string; value: string }>;
  body: unknown;
}

const builder = new XMLBuilder({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  textNodeName: '#text',
  format: false,
  suppressBooleanAttributes: false,
});

function buildEnvelope(args: HeaderArgs): string {
  const header: Record<string, unknown> = {
    'wsa:To': args.to,
    'wsman:ResourceURI': { '@mustUnderstand': 'true', '#text': RESOURCE_URI_SHELL_CMD },
    'wsa:ReplyTo': { 'wsa:Address': { '@mustUnderstand': 'true', '#text': ANONYMOUS_ROLE } },
    'wsman:MaxEnvelopeSize': { '@mustUnderstand': 'true', '#text': String(MAX_ENVELOPE_SIZE) },
    'wsa:MessageID': `uuid:${args.messageId}`,
    'wsman:Locale': { '@mustUnderstand': 'false', '@xml:lang': 'en-US' },
    'wsman:OperationTimeout': args.operationTimeout,
    'wsa:Action': { '@mustUnderstand': 'true', '#text': args.action },
  };
  if (args.shellId) {
    header['wsman:SelectorSet'] = { 'wsman:Selector': { '@Name': 'ShellId', '#text': args.shellId } };
  }
  if (args.options) {
    header['wsman:OptionSet'] = {
      'wsman:Option': args.options.map((o) => ({ '@Name': o.name, '#text': o.value })),
    };
  }
  const doc = {
    's:Envelope': {
      '@xmlns:s': 'http://www.w3.org/2003/05/soap-envelope',
      '@xmlns:wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
      '@xmlns:wsman': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
      '@xmlns:rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
      's:Header': header,
      's:Body': args.body,
    },
  };
  return `<?xml version="1.0" encoding="UTF-8"?>${builder.build(doc)}`;
}

export function buildCreateShellRequest(args: EnvelopeBase & { workingDirectory?: string }): string {
  const shell: Record<string, unknown> = {
    'rsp:InputStreams': 'stdin',
    'rsp:OutputStreams': 'stdout stderr',
  };
  if (args.workingDirectory !== undefined) shell['rsp:WorkingDirectory'] = args.workingDirectory;
  return buildEnvelope({
    ...args,
    action: ACTION.create,
    options: [
      { name: 'WINRS_NOPROFILE', value: 'FALSE' },
      { name: 'WINRS_CODEPAGE', value: '65001' },
    ],
    body: { 'rsp:Shell': shell },
  });
}

// consoleModeStdin false gives the program a plain pipe as stdin, which a
// Send feeds; the default TRUE is a console, as before.
export function buildCommandRequest(
  args: EnvelopeBase & { shellId: string; command: string; args?: string[]; consoleModeStdin?: boolean },
): string {
  const line: Record<string, unknown> = { 'rsp:Command': args.command };
  if (args.args && args.args.length > 0) line['rsp:Arguments'] = [...args.args];
  return buildEnvelope({
    ...args,
    action: ACTION.command,
    options: [
      { name: 'WINRS_CONSOLEMODE_STDIN', value: args.consoleModeStdin === false ? 'FALSE' : 'TRUE' },
      { name: 'WINRS_SKIP_CMD_SHELL', value: 'FALSE' },
    ],
    body: { 'rsp:CommandLine': line },
  });
}

export function buildReceiveRequest(args: EnvelopeBase & { shellId: string; commandId: string }): string {
  return buildEnvelope({
    ...args,
    action: ACTION.receive,
    body: { 'rsp:Receive': { 'rsp:DesiredStream': { '@CommandId': args.commandId, '#text': 'stdout stderr' } } },
  });
}

// rsp:Send (MS-WSMV 3.1.4.13): bytes for the command's stdin, base64.
// End="true" closes stdin after these bytes; the data may be empty then.
export function buildSendRequest(
  args: EnvelopeBase & { shellId: string; commandId: string; data: Buffer; end?: boolean },
): string {
  const stream: Record<string, unknown> = { '@Name': 'stdin', '@CommandId': args.commandId };
  if (args.end) stream['@End'] = 'true';
  stream['#text'] = args.data.toString('base64');
  return buildEnvelope({ ...args, action: ACTION.send, body: { 'rsp:Send': { 'rsp:Stream': stream } } });
}

export function buildSignalRequest(args: EnvelopeBase & { shellId: string; commandId: string }): string {
  return buildEnvelope({
    ...args,
    action: ACTION.signal,
    body: { 'rsp:Signal': { '@CommandId': args.commandId, 'rsp:Code': SIGNAL_TERMINATE } },
  });
}

export function buildDeleteShellRequest(args: EnvelopeBase & { shellId: string }): string {
  return buildEnvelope({ ...args, action: ACTION.delete, body: {} });
}
