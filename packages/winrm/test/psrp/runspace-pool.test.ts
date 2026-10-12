// The runspace pool and pipeline state machines (MS-PSRP 3.1.4),
// driven by the scripted server: open, the version refusal, Broken, every
// stream, Failed, Stopped, stop before the CommandResponse, the fault
// rules, a CREATE_PIPELINE above one fragment, input back-pressure, a
// server message split across Receives, and the operation-timeout retry.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { openRunspacePool, type PSStreamEvent } from '../../src/winrm/psrp/runspace-pool.js';
import { MessageType } from '../../src/winrm/psrp/messages.js';
import { isPSObject, type PSObject, type PSValue } from '../../src/winrm/psrp/clixml.js';
import { PSRemotingError, WinRMFaultError } from '../../src/winrm/errors.js';
import { challengeStub, CREDENTIALS } from '../helpers/stub-auth.js';
import { APP_DATA, CAPS_23, DEFAULT_OPEN, OPERATION_TIMEOUT_FAULT, errorRecord, errorRecordMessage, pipelineState, poolState, startScriptedPsrp, wsmanFault, type ReceiveAnswer, type ScriptedPsrp } from '../helpers/scripted-psrp.js';

const open = (server: ScriptedPsrp, extra: Record<string, unknown> = {}) =>
  openRunspacePool({ host: '127.0.0.1', port: server.port, authProvider: challengeStub({ seal: true }), credentials: CREDENTIALS, operationTimeoutMs: 2000, ...extra });

const obj = (v: PSValue | undefined): PSObject => {
  assert.ok(v !== undefined && isPSObject(v), `a PSObject, got ${String(v)}`);
  return v;
};
const msg = (server: ScriptedPsrp, type: number) => server.received.filter((m) => m.messageType === type);
const OUTPUT = (data: string) => ({ type: MessageType.PIPELINE_OUTPUT, data });
const COMPLETED: ReceiveAnswer = [{ type: MessageType.PIPELINE_STATE, data: pipelineState(4) }];
async function collect(pipeline: AsyncIterable<PSStreamEvent>): Promise<PSStreamEvent[]> {
  const out: PSStreamEvent[] = [];
  for await (const e of pipeline) out.push(e);
  return out;
}

describe('open and close', () => {
  it('sends SESSION_CAPABILITY and INIT_RUNSPACEPOOL in the Create, reaches Opened, keeps the server data, and Delete closes', async () => {
    const server = await startScriptedPsrp();
    const pool = await open(server);
    try {
      assert.equal(pool.state, 'Opened');
      assert.equal(pool.serverProtocolVersion, '2.3');
      assert.deepEqual(server.actions, ['Create', 'Receive', 'Receive']);
      assert.equal(server.shellIds[0], server.shellIds[0]?.toUpperCase(), 'the ShellId attribute is upper case');
      assert.equal(pool.shellId, server.shellIds[0]);
      const [caps, init] = server.received;
      assert.equal(caps?.messageType, MessageType.SESSION_CAPABILITY);
      assert.equal(caps?.pid, '00000000-0000-0000-0000-000000000000');
      assert.equal(caps?.rpid, pool.shellId.toLowerCase());
      assert.equal(obj(obj(caps?.value).extended.get('protocolversion')).value, '2.3');
      assert.equal(init?.messageType, MessageType.INIT_RUNSPACEPOOL);
      const initObj = obj(init?.value);
      assert.equal(initObj.extended.get('MinRunspaces'), 1);
      assert.equal(initObj.extended.get('MaxRunspaces'), 1);
      assert.equal(obj(initObj.extended.get('PSThreadOptions')).toStringValue, 'Default');
      assert.equal(obj(initObj.extended.get('HostInfo')).extended.get('_isHostNull'), true);
      assert.equal(initObj.extended.get('ApplicationArguments'), null);
      const appData = obj(pool.applicationPrivateData ?? null).extended.get('ApplicationPrivateData') as Map<PSValue, PSValue>;
      assert.ok(appData instanceof Map, 'APPLICATION_PRIVATE_DATA is kept');
    } finally {
      await pool.close();
      await pool.close();
      await server.close();
    }
    assert.equal(server.actions.at(-1), 'Delete');
    assert.equal(server.actions.filter((a) => a === 'Delete').length, 1, 'close is idempotent');
    assert.equal(pool.state, 'Closed');
  });

  it('refuses a 2.1 server with the exact message and deletes the shell', async () => {
    const server = await startScriptedPsrp({ pool: [[{ type: MessageType.SESSION_CAPABILITY, data: CAPS_23.replace('2.3', '2.1') }]] });
    try {
      await assert.rejects(open(server), (err: unknown) => {
        assert.ok(err instanceof PSRemotingError, String(err));
        assert.equal(err.message, 'the server speaks PSRP 2.1; winlinux needs 2.2 or newer (PowerShell 3.0+)');
        return true;
      });
      assert.deepEqual(server.actions, ['Create', 'Receive', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('accepts a 2.2 server', async () => {
    const server = await startScriptedPsrp({ pool: [[{ type: MessageType.SESSION_CAPABILITY, data: CAPS_23.replace('2.3', '2.2') }], DEFAULT_OPEN[1] as ReceiveAnswer] });
    const pool = await open(server);
    assert.equal(pool.serverProtocolVersion, '2.2');
    await pool.close();
    await server.close();
  });

  it('a Broken pool with an error record fails the open with the record message', async () => {
    const server = await startScriptedPsrp({
      pool: [[{ type: MessageType.SESSION_CAPABILITY, data: CAPS_23 }], [{ type: MessageType.RUNSPACEPOOL_STATE, data: poolState(5, errorRecord('ExceptionAsErrorRecord', 'no runspace for you')) }]],
    });
    try {
      await assert.rejects(open(server), (err: unknown) => err instanceof PSRemotingError && /runspace pool is broken: no runspace for you/.test(err.message));
      assert.equal(server.actions.at(-1), 'Delete');
    } finally {
      await server.close();
    }
  });

  it('a fault on a pool Receive during open breaks the pool and deletes the shell (3.1.5.3.13)', async () => {
    const server = await startScriptedPsrp({ pool: [[{ type: MessageType.SESSION_CAPABILITY, data: CAPS_23 }], { fault: wsmanFault(2150858843, 'The request is not valid.') }] });
    try {
      await assert.rejects(open(server), (err: unknown) => err instanceof WinRMFaultError && err.wsmanCode === 2150858843);
      assert.deepEqual(server.actions, ['Create', 'Receive', 'Receive', 'Delete']);
    } finally {
      await server.close();
    }
  });

  it('retries a pool Receive that times out (operation timeout fault)', async () => {
    const server = await startScriptedPsrp({ pool: ['timeout', DEFAULT_OPEN[0] as ReceiveAnswer, 'timeout', DEFAULT_OPEN[1] as ReceiveAnswer] });
    const pool = await open(server);
    assert.equal(pool.state, 'Opened');
    assert.equal(server.actions.filter((a) => a === 'Receive').length, 4);
    await pool.close();
    await server.close();
  });
});

describe('a pipeline', () => {
  it('sends CREATE_PIPELINE with the client CommandId and the script, and yields every stream in order until Completed', async () => {
    const server = await startScriptedPsrp({
      pipelines: [
        [
          [OUTPUT('<S>hello</S>'), { type: MessageType.WARNING_RECORD, data: '<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.WarningRecord</T><T>System.Object</T></TN><ToString>careful</ToString><MS><S N="InformationalRecord_Message">careful</S></MS></Obj>' }],
          [
            { type: MessageType.ERROR_RECORD, data: errorRecordMessage('oops', 'Oops,Script') },
            { type: MessageType.VERBOSE_RECORD, data: '<Obj RefId="0"><MS><S N="InformationalRecord_Message">v</S></MS></Obj>' },
            { type: MessageType.DEBUG_RECORD, data: '<Obj RefId="0"><MS><S N="InformationalRecord_Message">d</S></MS></Obj>' },
            { type: MessageType.INFORMATION_RECORD, data: '<Obj RefId="0"><MS><S N="MessageData">hi</S><S N="Source">Write-Host</S><S N="User">u</S><S N="Computer">c</S></MS></Obj>' },
            { type: MessageType.PROGRESS_RECORD, data: '<PR><AV>Copy</AV><AI>1</AI><Nil/><PI>-1</PI><PC>50</PC><T>Processing</T><SR>-1</SR><SD>half</SD></PR>' },
            OUTPUT('<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T><T>System.Object</T></TN><Props><I32 N="Id">4</I32></Props></Obj>'),
            OUTPUT(''),
          ],
          COMPLETED,
        ],
      ],
    });
    const pool = await open(server);
    try {
      const pipeline = pool.invoke('Get-Process | Select -First 1', { addToHistory: true });
      const events = await collect(pipeline);
      assert.deepEqual(
        events.map((e) => e.stream),
        ['output', 'warning', 'error', 'verbose', 'debug', 'information', 'progress', 'output', 'output'],
      );
      assert.equal((events[0] as { value: PSValue }).value, 'hello');
      assert.equal((events[1] as { message: string }).message, 'careful');
      const error = events[2] as { record: { message: string; fullyQualifiedErrorId: string } };
      assert.equal(error.record.message, 'oops');
      assert.equal(error.record.fullyQualifiedErrorId, 'Oops,Script');
      assert.equal((events[5] as { record: { source: string } }).record.source, 'Write-Host');
      assert.equal((events[6] as { record: { percentComplete: number } }).record.percentComplete, 50);
      assert.equal(obj((events[7] as { value: PSValue }).value).adapted.get('Id'), 4);
      assert.equal((events[8] as { value: PSValue }).value, null, 'empty data is a null output');
      const result = await pipeline.result();
      assert.equal(result.state, 'Completed');
      assert.equal(pipeline.state, 'Completed');
      assert.equal(result.output.length, 3);
      assert.equal(result.errors.length, 1);
      assert.equal(result.reason, undefined);
      // What went out.
      assert.deepEqual(server.actions, ['Create', 'Receive', 'Receive', 'Command', 'Receive', 'Receive', 'Receive']);
      const [create] = msg(server, MessageType.CREATE_PIPELINE);
      assert.ok(create);
      assert.equal(create.pid, pipeline.id, 'the pipeline id is the PID');
      assert.equal(server.commandIds[0], pipeline.id.toUpperCase(), 'and the CommandId');
      const createObj = obj(create.value);
      assert.equal(createObj.extended.get('NoInput'), true);
      assert.equal(createObj.extended.get('AddToHistory'), true);
      assert.equal(obj(createObj.extended.get('RemoteStreamOptions')).toStringValue, 'AddInvocationInfoToErrorRecord');
      const ps = obj(createObj.extended.get('PowerShell'));
      const cmds = ps.extended.get('Cmds') as PSValue[];
      assert.equal(cmds.length, 1);
      const cmd = obj(cmds[0]);
      assert.equal(cmd.extended.get('Cmd'), 'Get-Process | Select -First 1');
      assert.equal(cmd.extended.get('IsScript'), true);
      assert.equal(obj(cmd.extended.get('MergeError')).toStringValue, 'None');
      assert.deepEqual(cmd.extended.get('Args'), []);
      assert.equal(server.sends.length, 0, 'one fragment: no Send');
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('outString appends Out-String -Stream -Width n as a second command; invokeCommand sends parameters as {N, V}', async () => {
    const server = await startScriptedPsrp({ pipelines: [[COMPLETED], [COMPLETED]] });
    const pool = await open(server);
    try {
      await pool.invoke('Get-Date', { outString: { width: 100 } }).result();
      await pool.invokeCommand([{ name: 'Get-ChildItem', parameters: [{ name: 'Path', value: 'C:\\' }, { value: 'positional' }], mergeErrorToOutput: true }]).result();
      const [first, second] = msg(server, MessageType.CREATE_PIPELINE);
      const cmdsOf = (m: { value: PSValue } | undefined) => obj(obj(m?.value).extended.get('PowerShell')).extended.get('Cmds') as PSValue[];
      const outString = obj(cmdsOf(first)[1]);
      assert.equal(outString.extended.get('Cmd'), 'Out-String');
      assert.equal(outString.extended.get('IsScript'), false);
      assert.deepEqual(
        (outString.extended.get('Args') as PSValue[]).map((a) => [obj(a).extended.get('N'), obj(a).extended.get('V')]),
        [
          ['Stream', true],
          ['Width', 100],
        ],
      );
      const gci = obj(cmdsOf(second)[0]);
      assert.equal(obj(gci.extended.get('MergeError')).toStringValue, 'Output');
      assert.deepEqual(
        (gci.extended.get('Args') as PSValue[]).map((a) => [obj(a).extended.get('N'), obj(a).extended.get('V')]),
        [
          ['Path', 'C:\\'],
          [null, 'positional'],
        ],
      );
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('Failed carries the ExceptionAsErrorRecord as the reason', async () => {
    const server = await startScriptedPsrp({ pipelines: [[[{ type: MessageType.PIPELINE_STATE, data: pipelineState(5, errorRecord('ExceptionAsErrorRecord', 'the host does not support Read-Host', 'HostFunctionNotImplemented')) }]]] });
    const pool = await open(server);
    try {
      const result = await pool.invoke('Read-Host x').result();
      assert.equal(result.state, 'Failed');
      assert.ok(result.reason && 'fullyQualifiedErrorId' in result.reason);
      assert.equal(result.reason.message, 'the host does not support Read-Host');
      assert.equal(pool.state, 'Opened', 'the pool survives a failed pipeline');
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('stop() cuts the Receive, sends Signal ctrl_c, and resolves on Stopped; the pool runs the next pipeline', async () => {
    const server = await startScriptedPsrp({
      pipelines: [[[OUTPUT('<S>1</S>')], { afterSignal: [{ type: MessageType.PIPELINE_STATE, data: pipelineState(3) }] }], [[OUTPUT('<S>again</S>')], COMPLETED]],
    });
    const pool = await open(server);
    try {
      const pipeline = pool.invoke('Start-Sleep 60');
      const events: PSStreamEvent[] = [];
      const reading = (async () => {
        for await (const e of pipeline) events.push(e);
      })();
      // Wait for the server to hold the second Receive.
      const deadline = Date.now() + 3000;
      while (server.actions.filter((a) => a === 'Receive').length < 4) {
        if (Date.now() > deadline) throw new Error('the pipeline Receives did not start');
        await new Promise((r) => setTimeout(r, 10));
      }
      const started = Date.now();
      await pipeline.stop();
      assert.ok(Date.now() - started < 1500, 'stop did not wait for the operation timeout');
      await reading;
      assert.equal(pipeline.state, 'Stopped');
      assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
      assert.deepEqual(events.map((e) => e.stream), ['output']);
      assert.equal((await pipeline.result()).state, 'Stopped');
      assert.equal(pool.state, 'Opened');
      const next = await pool.invoke('$x').result();
      assert.deepEqual(next.output, ['again']);
      await pipeline.stop();
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('an InvokeOptions signal stops the pipeline the same way', async () => {
    const server = await startScriptedPsrp({ pipelines: [[{ afterSignal: [{ type: MessageType.PIPELINE_STATE, data: pipelineState(3) }] }]] });
    const pool = await open(server);
    try {
      const abort = new AbortController();
      const pipeline = pool.invoke('Start-Sleep 60', { signal: abort.signal });
      setTimeout(() => abort.abort(), 100);
      assert.equal((await pipeline.result()).state, 'Stopped');
      assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('stop() before the CommandResponse waits for it, then signals (3.1.4.4 step 1)', async () => {
    const server = await startScriptedPsrp({ command: { delayMs: 300 }, pipelines: [[{ afterSignal: [{ type: MessageType.PIPELINE_STATE, data: pipelineState(3) }] }]] });
    const pool = await open(server);
    try {
      const pipeline = pool.invoke('Start-Sleep 60');
      await pipeline.stop();
      assert.equal(pipeline.state, 'Stopped');
      const command = server.actions.indexOf('Command');
      const signal = server.actions.indexOf('Signal');
      assert.ok(command >= 0 && signal > command, `Signal after Command: ${server.actions.join(',')}`);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('a fault on the Command makes the pipeline Failed with the fault as reason, and no Signal goes out', async () => {
    const server = await startScriptedPsrp({ command: { fault: 'The request is not valid.' } });
    const pool = await open(server);
    try {
      const result = await pool.invoke('x').result();
      assert.equal(result.state, 'Failed');
      assert.ok(result.reason instanceof WinRMFaultError);
      assert.equal(server.signals.length, 0);
      assert.equal(pool.state, 'Opened');
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('a fault on a pipeline Receive makes it Failed and sends Signal (3.1.5.3.13)', async () => {
    const server = await startScriptedPsrp({ pipelines: [[[OUTPUT('<S>a</S>')], { fault: wsmanFault(2150858843, 'The request is not valid.') }]] });
    const pool = await open(server);
    try {
      const result = await pool.invoke('x').result();
      assert.equal(result.state, 'Failed');
      assert.ok(result.reason instanceof WinRMFaultError);
      assert.deepEqual(result.output, ['a']);
      assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('a CREATE_PIPELINE above one fragment goes by Command then Send on stdin, and the server reassembles the script', async () => {
    const server = await startScriptedPsrp({ pipelines: [[COMPLETED]] });
    const pool = await open(server);
    try {
      const script = `'${'x'.repeat(70_000)}'`;
      await pool.invoke(script).result();
      assert.ok(server.sends.length >= 1, 'at least one Send');
      assert.ok(server.sends.every((s) => s.stream === 'stdin' && s.commandId === server.commandIds[0]));
      const [create] = msg(server, MessageType.CREATE_PIPELINE);
      const cmds = obj(obj(create?.value).extended.get('PowerShell')).extended.get('Cmds') as PSValue[];
      assert.equal(obj(cmds[0]).extended.get('Cmd'), script);
      assert.deepEqual(server.actions.slice(3, 5), ['Command', 'Send']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('input values go out one PIPELINE_INPUT per value, the next only after the SendResponse, then END_OF_PIPELINE_INPUT', async () => {
    const server = await startScriptedPsrp({ pipelines: [[COMPLETED]], sendDelayMs: (nth) => (nth === 1 ? 300 : 0) });
    const pool = await open(server);
    try {
      const pulled: number[] = [];
      async function* input(): AsyncIterable<PSValue> {
        for (const v of [1, 2]) {
          pulled.push(Date.now());
          yield v;
        }
      }
      const result = await pool.invoke('$input | Measure-Object', { input: input() }).result();
      assert.equal(result.state, 'Completed');
      const [first, second] = pulled;
      assert.ok(first !== undefined && second !== undefined && second - first >= 250, 'the second value waited for the first SendResponse');
      assert.deepEqual(
        server.received.filter((m) => m.messageType === MessageType.PIPELINE_INPUT).map((m) => m.value),
        [1, 2],
      );
      assert.equal(msg(server, MessageType.END_OF_PIPELINE_INPUT).length, 1);
      const [create] = msg(server, MessageType.CREATE_PIPELINE);
      assert.equal(obj(create?.value).extended.get('NoInput'), false);
      assert.deepEqual(server.sends.map((s) => s.stream), ['stdin', 'stdin', 'stdin']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('a large output split into fragments across several Receives arrives complete and in order', async () => {
    const big = 'y'.repeat(200_000);
    const server = await startScriptedPsrp({ pipelines: [[[OUTPUT(`<S>${big}</S>`), OUTPUT('<S>tail</S>')], COMPLETED]], fragmentBytes: 32768, fragmentsPerReceive: 3 });
    const pool = await open(server);
    try {
      const result = await pool.invoke('big').result();
      assert.equal(result.state, 'Completed');
      assert.deepEqual(result.output, [big, 'tail']);
      assert.ok(server.actions.filter((a) => a === 'Receive').length >= 5, 'several Receives for the pipeline');
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('CommandState Done without a PIPELINE_STATE ends the pipeline as Completed, and an operation timeout is retried', async () => {
    const server = await startScriptedPsrp({ pipelines: [['timeout', [OUTPUT('<S>late</S>')], { done: true }]] });
    const pool = await open(server);
    try {
      const result = await pool.invoke('x').result();
      assert.equal(result.state, 'Completed');
      assert.deepEqual(result.output, ['late']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('Done without a PIPELINE_STATE after a stop is Stopped: the state went out on the Receive the stop cut', async () => {
    const server = await startScriptedPsrp({ pipelines: [[[OUTPUT('<S>1</S>')], { doneAfterSignal: true }]] });
    const pool = await open(server);
    try {
      const pipeline = pool.invoke('Start-Sleep 60');
      const deadline = Date.now() + 3000;
      while (server.actions.filter((a) => a === 'Receive').length < 4) {
        if (Date.now() > deadline) throw new Error('the pipeline Receives did not start');
        await new Promise((r) => setTimeout(r, 10));
      }
      await pipeline.stop();
      assert.equal(pipeline.state, 'Stopped');
      assert.equal((await pipeline.result()).state, 'Stopped');
      assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('a host call on a pipeline (no host offered) stops it with a PSRemotingError reason', async () => {
    const server = await startScriptedPsrp({
      pipelines: [[[{ type: MessageType.PIPELINE_HOST_CALL, data: '<Obj RefId="0"><MS><I64 N="ci">1</I64><Obj N="mi" RefId="1"><TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>ReadLine</ToString><I32>11</I32></Obj></MS></Obj>' }], { afterSignal: [{ type: MessageType.PIPELINE_STATE, data: pipelineState(3) }] }]],
    });
    const pool = await open(server);
    try {
      const result = await pool.invoke('Read-Host').result();
      assert.equal(result.state, 'Failed');
      assert.ok(result.reason instanceof PSRemotingError && /host call/.test(result.reason.message));
      assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
    } finally {
      await pool.close();
      await server.close();
    }
  });

  it('invoke on a closed pool is refused; close stops a running pipeline first', async () => {
    const server = await startScriptedPsrp({ pipelines: [[{ afterSignal: [{ type: MessageType.PIPELINE_STATE, data: pipelineState(3) }] }]] });
    const pool = await open(server);
    const pipeline = pool.invoke('Start-Sleep 60');
    await new Promise((r) => setTimeout(r, 100));
    await pool.close();
    assert.equal(pipeline.state, 'Stopped');
    assert.deepEqual(server.signals, ['powershell/signal/ctrl_c']);
    assert.equal(server.actions.at(-1), 'Delete');
    assert.throws(() => pool.invoke('x'), PSRemotingError);
    await server.close();
  });
});
