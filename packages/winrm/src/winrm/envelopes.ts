import { XMLBuilder } from 'fast-xml-parser';

export const RESOURCE_URI_SHELL_CMD = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd';
// PSRP (MS-PSRP 3.1.5.3.1): the resource URI names the session
// configuration; Microsoft.PowerShell is the default one on every server.
export const PSRP_RESOURCE_URI_BASE = 'http://schemas.microsoft.com/powershell/';
export const PSRP_DEFAULT_CONFIGURATION = 'Microsoft.PowerShell';
export const PSRP_CREATION_XML_NS = 'http://schemas.microsoft.com/powershell';
// MS-WSMV namespace of the wsmv:SessionId header (MS-WSMV 3.1.4.1.37).
const WSMV_NS = 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd';
export const ANONYMOUS_ROLE = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous';
export const MAX_ENVELOPE_SIZE = 153600;
export const SIGNAL_TERMINATE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate';
// Stops a PSRP pipeline (MS-PSRP 3.1.5.3.9 spells it crtl_c; pypsrp sends
// ctrl_c; the live gate settles it).
export const PSRP_SIGNAL_CTRL_C = 'powershell/signal/ctrl_c';
export const PSRP_SIGNAL_CRTL_C = 'powershell/signal/crtl_c';

export function psrpResourceUri(configurationName = PSRP_DEFAULT_CONFIGURATION): string {
  if (!/^[A-Za-z0-9._-]+$/.test(configurationName)) {
    throw new RangeError(`PSRP configuration name is not valid: ${JSON.stringify(configurationName)}`);
  }
  return PSRP_RESOURCE_URI_BASE + configurationName;
}
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
  // The shell resource; default the WinRS cmd shell. PSRP passes
  // psrpResourceUri(configurationName).
  resourceUri?: string;
  // wsmv:SessionId (MS-WSMV 3.1.4.1.37), one value for a client session, so
  // the server can tie a Reconnect or Connect to it (MS-PSRP 3.1.4.9). The
  // header is left out when undefined, so WinRS envelopes are unchanged.
  sessionId?: string;
}

export interface EnvelopeOption {
  name: string;
  value: string;
  // MustComply="true" (MS-PSRP 3.1.5.3.1 for protocolversion).
  mustComply?: boolean;
}

interface HeaderArgs extends EnvelopeBase {
  action: string;
  shellId?: string;
  options?: EnvelopeOption[];
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
    'wsman:ResourceURI': { '@mustUnderstand': 'true', '#text': args.resourceUri ?? RESOURCE_URI_SHELL_CMD },
    'wsa:ReplyTo': { 'wsa:Address': { '@mustUnderstand': 'true', '#text': ANONYMOUS_ROLE } },
    'wsman:MaxEnvelopeSize': { '@mustUnderstand': 'true', '#text': String(MAX_ENVELOPE_SIZE) },
    'wsa:MessageID': `uuid:${args.messageId}`,
    'wsman:Locale': { '@mustUnderstand': 'false', '@xml:lang': 'en-US' },
    'wsman:OperationTimeout': args.operationTimeout,
    'wsa:Action': { '@mustUnderstand': 'true', '#text': args.action },
  };
  if (args.sessionId !== undefined) {
    header['wsmv:SessionId'] = { '@mustUnderstand': 'false', '#text': `uuid:${args.sessionId}` };
  }
  if (args.shellId) {
    header['wsman:SelectorSet'] = { 'wsman:Selector': { '@Name': 'ShellId', '#text': args.shellId } };
  }
  if (args.options) {
    header['wsman:OptionSet'] = {
      'wsman:Option': args.options.map((o) => ({ '@Name': o.name, ...(o.mustComply ? { '@MustComply': 'true' } : {}), '#text': o.value })),
    };
  }
  const doc = {
    's:Envelope': {
      '@xmlns:s': 'http://www.w3.org/2003/05/soap-envelope',
      '@xmlns:wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
      '@xmlns:wsman': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
      '@xmlns:rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
      // Declared only when a header uses it, so WinRS envelopes stay as they were.
      ...(args.sessionId !== undefined ? { '@xmlns:wsmv': WSMV_NS } : {}),
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

// --- PSRP (MS-PSRP 3.1.5.3): the same operations with PowerShell bodies. ---
// Every builder takes `resourceUri` from psrpResourceUri() and the optional
// `sessionId` through EnvelopeBase. The WinRS builders above are untouched.

// Create (MS-PSRP 3.1.5.3.1): the pool GUID as the ShellId attribute, the
// protocolversion option with MustComply, streams `stdin pr` / `stdout`,
// and the first fragments (SESSION_CAPABILITY, INIT_RUNSPACEPOOL) as base64
// creationXml. IdleTimeOut is sent only when given.
export function buildPsrpCreateRequest(
  args: EnvelopeBase & { shellId: string; protocolVersion: string; creationXml: Buffer; idleTimeoutMs?: number },
): string {
  const shell: Record<string, unknown> = {
    '@ShellId': args.shellId,
    'rsp:InputStreams': 'stdin pr',
    'rsp:OutputStreams': 'stdout',
  };
  if (args.idleTimeoutMs !== undefined) shell['rsp:IdleTimeOut'] = `PT${args.idleTimeoutMs / 1000}S`;
  shell['creationXml'] = { '@xmlns': PSRP_CREATION_XML_NS, '#text': args.creationXml.toString('base64') };
  // The shell does not exist yet: its id travels as the attribute, not as
  // a SelectorSet.
  const { shellId: _shellId, ...base } = args;
  return buildEnvelope({
    ...base,
    action: ACTION.create,
    options: [{ name: 'protocolversion', value: args.protocolVersion, mustComply: true }],
    body: { 'rsp:Shell': shell },
  });
}

// Command (MS-PSRP 3.1.5.3.3): an empty rsp:Command and the first fragment
// of CREATE_PIPELINE as base64 rsp:Arguments. The client names the
// CommandId, which is the pipeline id (PID) of the PSRP messages.
export function buildPsrpCommandRequest(args: EnvelopeBase & { shellId: string; commandId: string; arguments: Buffer }): string {
  return buildEnvelope({
    ...args,
    action: ACTION.command,
    body: { 'rsp:CommandLine': { '@CommandId': args.commandId, 'rsp:Command': '', 'rsp:Arguments': args.arguments.toString('base64') } },
  });
}

// Receive (MS-PSRP 3.1.5.3.7): stdout of the pool (no CommandId) or of one
// pipeline.
export function buildPsrpReceiveRequest(args: EnvelopeBase & { shellId: string; commandId?: string }): string {
  const stream: Record<string, unknown> = {};
  if (args.commandId !== undefined) stream['@CommandId'] = args.commandId;
  stream['#text'] = 'stdout';
  return buildEnvelope({ ...args, action: ACTION.receive, body: { 'rsp:Receive': { 'rsp:DesiredStream': stream } } });
}

// Send (MS-PSRP 3.1.5.3.5): fragments for the pool or a pipeline on
// `stdin` (input, remaining CREATE_PIPELINE fragments) or `pr` (host
// responses). Several whole fragments may share one Stream element; the
// caller concatenates them.
export function buildPsrpSendRequest(args: EnvelopeBase & { shellId: string; stream: 'stdin' | 'pr'; commandId?: string; data: Buffer }): string {
  const stream: Record<string, unknown> = { '@Name': args.stream };
  if (args.commandId !== undefined) stream['@CommandId'] = args.commandId;
  stream['#text'] = args.data.toString('base64');
  return buildEnvelope({ ...args, action: ACTION.send, body: { 'rsp:Send': { 'rsp:Stream': stream } } });
}

// Signal (MS-PSRP 3.1.5.3.9) with the PowerShell code; the default is the
// spelling pypsrp sends.
export function buildPsrpSignalRequest(args: EnvelopeBase & { shellId: string; commandId: string; code?: string }): string {
  return buildEnvelope({
    ...args,
    action: ACTION.signal,
    body: { 'rsp:Signal': { '@CommandId': args.commandId, 'rsp:Code': args.code ?? PSRP_SIGNAL_CTRL_C } },
  });
}
