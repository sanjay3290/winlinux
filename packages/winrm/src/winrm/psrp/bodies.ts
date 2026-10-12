// The PSRP message bodies the client writes and the server replies the
// client reads (MS-PSRP 2.2.2), as CLIXML. Used here: open a pool, run a
// pipeline, read its state. The host is null.
import { isPSObject, psEnum, psObject, psVersion, serializeClixml, toErrorRecord, type PSErrorRecord, type PSObject, type PSValue } from './clixml.js';

export const PROTOCOL_VERSION = '2.3';
export const PS_VERSION = '2.0';
export const SERIALIZATION_VERSION = '1.1.0.1';

const ENUM = (name: string) => [`System.Management.Automation.${name}`, 'System.Enum', 'System.ValueType', 'System.Object'];
const THREAD_OPTIONS = ENUM('Runspaces.PSThreadOptions');
const APARTMENT_STATE = ['System.Threading.ApartmentState', 'System.Enum', 'System.ValueType', 'System.Object'];
const REMOTE_STREAM_OPTIONS = ENUM('RemoteStreamOptions');
const PIPELINE_RESULT_TYPES = ENUM('Runspaces.PipelineResultTypes');

// SESSION_CAPABILITY (2.2.2.1): the client omits TimeZone.
export function sessionCapabilityBody(): string {
  return serializeClixml(psObject({ protocolversion: psVersion(PROTOCOL_VERSION), PSVersion: psVersion(PS_VERSION), SerializationVersion: psVersion(SERIALIZATION_VERSION) }));
}

// HostInfo (2.2.3.14) with no host: every "null" flag true, no default data.
export function nullHostInfo(): PSObject {
  return psObject({ _isHostNull: true, _isHostUINull: true, _isHostRawUINull: true, _useRunspaceHost: true });
}

// INIT_RUNSPACEPOOL (2.2.2.2): one runspace, default thread options, the
// apartment state PowerShell sends (Unknown), the host, no arguments.
export function initRunspacePoolBody(host: PSObject = nullHostInfo()): string {
  return serializeClixml(
    psObject({
      MinRunspaces: 1,
      MaxRunspaces: 1,
      PSThreadOptions: psEnum(THREAD_OPTIONS, 'Default', 0),
      ApartmentState: psEnum(APARTMENT_STATE, 'Unknown', 2),
      HostInfo: host,
      ApplicationArguments: null,
    }),
  );
}

export interface PSCommand {
  // A cmdlet name, or script text when isScript is true.
  name: string;
  isScript?: boolean;
  parameters?: Array<{ name?: string; value: PSValue }>;
  // Merge the error stream into the output (PipelineResultTypes Output),
  // as the shell does for Out-String; default none.
  mergeErrorToOutput?: boolean;
}

export interface CreatePipelineOptions {
  noInput: boolean;
  addToHistory?: boolean;
  host?: PSObject;
}

const resultType = (name: 'None' | 'Output', value: number): PSObject => psEnum(PIPELINE_RESULT_TYPES, name, value);

// One command of the pipeline (2.2.3.12): the merge fields of the
// PipelineResultTypes, and Args as {N, V} pairs (2.2.3.13).
function commandObject(command: PSCommand): PSObject {
  const none = () => resultType('None', 0);
  const merge = command.mergeErrorToOutput ? resultType('Output', 2) : none();
  return psObject({
    Cmd: command.name,
    IsScript: command.isScript === true,
    UseLocalScope: null,
    MergeMyResult: none(),
    MergeToResult: none(),
    MergePreviousResults: none(),
    MergeError: merge,
    MergeWarning: none(),
    MergeVerbose: none(),
    MergeDebug: none(),
    MergeInformation: none(),
    Args: (command.parameters ?? []).map((p) => psObject({ N: p.name ?? null, V: p.value })),
  });
}

// CREATE_PIPELINE (2.2.2.10) with the PowerShell object of 2.2.3.11.
export function createPipelineBody(commands: PSCommand[], opts: CreatePipelineOptions): string {
  return serializeClixml(
    psObject({
      NoInput: opts.noInput,
      ApartmentState: psEnum(APARTMENT_STATE, 'Unknown', 2),
      RemoteStreamOptions: psEnum(REMOTE_STREAM_OPTIONS, 'AddInvocationInfoToErrorRecord', 1),
      AddToHistory: opts.addToHistory === true,
      HostInfo: opts.host ?? nullHostInfo(),
      PowerShell: psObject({
        Cmds: commands.map(commandObject),
        IsNested: false,
        History: null,
        RedirectShellErrorOutputPipe: true,
      }),
      IsNested: false,
    }),
  );
}

// PIPELINE_INPUT (2.2.2.17): one value per message.
export function pipelineInputBody(value: PSValue): string {
  return serializeClixml(value);
}

// --- Replies ---

// RunspacePoolState (2.2.3.4) and PSInvocationState (2.2.3.5).
export const RunspacePoolStateValue = { BeforeOpen: 0, Opening: 1, Opened: 2, Closed: 3, Closing: 4, Broken: 5, NegotiationSent: 6, NegotiationSucceeded: 7, Connecting: 8, Disconnected: 9 } as const;
export const PSInvocationStateValue = { NotStarted: 0, Running: 1, Stopping: 2, Stopped: 3, Completed: 4, Failed: 5, Disconnected: 6 } as const;

function numberProp(obj: PSValue, name: string): number | undefined {
  if (!isPSObject(obj)) return undefined;
  const value = obj.extended.get(name) ?? obj.adapted.get(name) ?? null;
  if (typeof value === 'number') return value;
  if (isPSObject(value) && typeof value.value === 'number') return value.value; // an enum
  return undefined;
}

function errorRecordProp(obj: PSValue, name: string): PSErrorRecord | undefined {
  if (!isPSObject(obj)) return undefined;
  const value = obj.extended.get(name) ?? null;
  return isPSObject(value) ? toErrorRecord(value) : undefined;
}

// SESSION_CAPABILITY from the server: its protocol version text.
export function readSessionCapability(obj: PSValue): { protocolVersion: string } {
  const version = isPSObject(obj) ? (obj.extended.get('protocolversion') ?? null) : null;
  const text = isPSObject(version) ? String(version.value ?? '') : typeof version === 'string' ? version : '';
  return { protocolVersion: text };
}

// RUNSPACEPOOL_STATE (2.2.2.9).
export function readRunspacePoolState(obj: PSValue): { state: number; error?: PSErrorRecord } {
  const state = numberProp(obj, 'RunspaceState') ?? -1;
  const error = errorRecordProp(obj, 'ExceptionAsErrorRecord');
  return error ? { state, error } : { state };
}

// PIPELINE_STATE (2.2.2.21).
export function readPipelineState(obj: PSValue): { state: number; error?: PSErrorRecord } {
  const state = numberProp(obj, 'PipelineState') ?? -1;
  const error = errorRecordProp(obj, 'ExceptionAsErrorRecord');
  return error ? { state, error } : { state };
}

// Version text "a.b[.c[.d]]" compared numerically, part by part.
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (Number.isNaN(x) || Number.isNaN(y)) return Number.isNaN(x) ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
