// CLIXML (MS-PSRP 2.2.5): the reader, the writer, the escaping rule,
// references and the JSON view. The golden inputs follow the shapes of
// the examples in MS-PSRP 2.2.2.1, 2.2.2.2, 2.2.2.9, 2.2.2.21, 2.2.2.29,
// 2.2.2.30, 2.2.5.2.8 and 2.2.5.2.9.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deserializeClixml,
  escapeClixmlString,
  isPSObject,
  psEnum,
  psGuid,
  psObject,
  psVersion,
  serializeClixml,
  toErrorRecord,
  toInformationRecord,
  toInformationalMessage,
  toJson,
  toProgressRecord,
  unescapeClixmlString,
  type PSDateTime,
  type PSObject,
  type PSValue,
} from '../../src/winrm/psrp/clixml.js';
import { PSRemotingError } from '../../src/winrm/errors.js';

const one = (xml: string): PSValue => {
  const values = deserializeClixml(xml);
  assert.equal(values.length, 1, `one value from ${xml}`);
  return values[0] as PSValue;
};
const obj = (value: PSValue): PSObject => {
  assert.ok(isPSObject(value), `a PSObject, got ${String(value)}`);
  return value;
};

describe('primitive elements (2.2.5.1)', () => {
  it('reads every primitive of the design table into the right JavaScript value', () => {
    assert.equal(one('<S>hello</S>'), 'hello');
    assert.equal(one('<S></S>'), '');
    assert.equal(one('<S/>'), '');
    assert.equal(one('<C>97</C>'), 'a');
    assert.equal(one('<C>128512</C>'), '😀');
    assert.equal(one('<B>true</B>'), true);
    assert.equal(one('<B>false</B>'), false);
    const dt = one('<DT>2026-10-12T01:02:03.1234567+02:00</DT>') as PSDateTime;
    assert.equal(dt.kind, 'datetime');
    assert.equal(dt.iso, '2026-10-12T01:02:03.1234567+02:00');
    assert.equal(dt.date.toISOString(), '2026-10-11T23:02:03.123Z');
    assert.deepEqual(one('<TS>PT1.5S</TS>'), { kind: 'duration', iso: 'PT1.5S' });
    assert.equal(one('<By>255</By>'), 255);
    assert.equal(one('<SB>-128</SB>'), -128);
    assert.equal(one('<U16>65535</U16>'), 65535);
    assert.equal(one('<I16>-32768</I16>'), -32768);
    assert.equal(one('<U32>4294967295</U32>'), 4294967295);
    assert.equal(one('<I32>-2147483648</I32>'), -2147483648);
    assert.equal(one('<U64>18446744073709551615</U64>'), 18446744073709551615n);
    assert.equal(one('<I64>-9223372036854775808</I64>'), -9223372036854775808n);
    assert.equal(one('<D>12345.678901234567890</D>'), '12345.678901234567890');
    assert.equal(one('<Sg>1.5</Sg>'), 1.5);
    assert.equal(one('<Db>-0.25</Db>'), -0.25);
    assert.equal(one('<Db>INF</Db>'), Infinity);
    assert.equal(one('<Db>-INF</Db>'), -Infinity);
    assert.ok(Number.isNaN(one('<Sg>NaN</Sg>')));
    assert.ok((one('<BA>AQID</BA>') as Buffer).equals(Buffer.from([1, 2, 3])));
    assert.deepEqual(obj(one('<G>792e5b37-4505-47ef-b7d2-8711bb7affa8</G>')).kind, 'guid');
    assert.equal(obj(one('<G>792e5b37-4505-47ef-b7d2-8711bb7affa8</G>')).value, '792e5b37-4505-47ef-b7d2-8711bb7affa8');
    assert.equal(obj(one('<URI>http://example.test/</URI>')).kind, 'uri');
    assert.equal(obj(one('<Version>2.3</Version>')).kind, 'version');
    assert.equal(obj(one('<Version>2.3</Version>')).value, '2.3');
    assert.equal(obj(one('<XD>&lt;a/&gt;</XD>')).value, '<a/>');
    assert.equal(obj(one('<SBK>Get-Date</SBK>')).kind, 'scriptblock');
    assert.equal(one('<Nil/>'), null);
    assert.deepEqual(one('<SS>AAEAAAD=</SS>'), { kind: 'securestring', encrypted: 'AAEAAAD=' });
  });

  it('reads a progress record (2.2.5.1.25) with a Nil or a text current operation', () => {
    const record = toProgressRecord(obj(one('<PR><AV>Copying</AV><AI>1</AI><Nil/><PI>-1</PI><PC>50</PC><T>Processing</T><SR>-1</SR><SD>half</SD></PR>')));
    assert.deepEqual(record, { activity: 'Copying', activityId: 1, currentOperation: null, parentActivityId: -1, percentComplete: 50, type: 'Processing', secondsRemaining: -1, statusDescription: 'half' });
    const withOperation = toProgressRecord(obj(one('<PR><AV>A</AV><AI>2</AI><S>step 3</S><PI>1</PI><PC>100</PC><T>Completed</T><SR>0</SR><SD>done</SD></PR>')));
    assert.equal(withOperation.currentOperation, 'step 3');
    assert.equal(withOperation.type, 'Completed');
  });
});

describe('string escaping (2.2.5.3.2)', () => {
  it('escapes controls, lone surrogates and a lookalike underscore, and decodes them back', () => {
    assert.equal(escapeClixmlString('a\nb\tc\u0000d'), 'a_x000A_b_x0009_c_x0000_d');
    assert.equal(escapeClixmlString('\ud83d'), '_xD83D_', 'a lone high surrogate');
    assert.equal(escapeClixmlString('ok _x0041_ literal'), 'ok _x005F_x0041_ literal', 'the underscore of a lookalike is escaped');
    assert.equal(escapeClixmlString('plain_under_score'), 'plain_under_score');
    assert.equal(escapeClixmlString('é 日本 😀'), 'é 日本 😀', 'non-ASCII text is not escaped');
    assert.equal(unescapeClixmlString('a_x000A_b_x0009_c'), 'a\nb\tc');
    assert.equal(unescapeClixmlString('_xD83D__xDE00_'), '😀', 'a surrogate pair from two escapes');
    for (const text of ['a\r\nb', 'x_x0041_y', '_', '__x', 'tab\there', '\u0085', 'end_']) {
      assert.equal(unescapeClixmlString(escapeClixmlString(text)), text, JSON.stringify(text));
      assert.equal(one(serializeClixml(text)), text, `through XML: ${JSON.stringify(text)}`);
    }
  });

  it('reads escapes inside S, property names, type names and ToString', () => {
    const value = obj(one('<Obj RefId="0"><TN RefId="0"><T>My_x002E_Type</T></TN><ToString>line_x000A_two</ToString><MS><S N="a_x0020_b">v_x000D_</S></MS></Obj>'));
    assert.deepEqual(value.typeNames, ['My.Type']);
    assert.equal(value.toStringValue, 'line\ntwo');
    assert.equal(value.extended.get('a b'), 'v\r');
  });
});

describe('complex objects (2.2.5.2)', () => {
  it('reads an object with TN, ToString, Props and MS (the shape of 2.2.5.2.8 and 2.2.5.2.9)', () => {
    const value = obj(
      one(
        '<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T><T>System.ComponentModel.Component</T><T>System.Object</T></TN>' +
          '<ToString>System.Diagnostics.Process (pwsh)</ToString>' +
          '<Props><I32 N="Id">4242</I32><S N="ProcessName">pwsh</S><Nil N="MainWindowTitle"/></Props>' +
          '<MS><I64 N="WorkingSet">123456789</I64><S N="PSComputerName">example.test</S></MS></Obj>',
      ),
    );
    assert.equal(value.kind, 'object');
    assert.deepEqual(value.typeNames, ['System.Diagnostics.Process', 'System.ComponentModel.Component', 'System.Object']);
    assert.equal(value.toStringValue, 'System.Diagnostics.Process (pwsh)');
    assert.deepEqual([...value.adapted.entries()], [['Id', 4242], ['ProcessName', 'pwsh'], ['MainWindowTitle', null]]);
    assert.deepEqual([...value.extended.entries()], [['WorkingSet', 123456789n], ['PSComputerName', 'example.test']]);
    assert.equal(value.value, undefined);
  });

  it('reads an extended primitive and an enum (2.2.5.2.5, 2.2.5.2.7)', () => {
    const state = obj(one('<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.Runspaces.RunspacePoolState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Opened</ToString><I32>2</I32></Obj>'));
    assert.equal(state.value, 2);
    assert.equal(state.toStringValue, 'Opened');
    const str = obj(one('<Obj RefId="0"><S>text</S><MS><B N="flag">true</B></MS></Obj>'));
    assert.equal(str.value, 'text');
    assert.equal(str.extended.get('flag'), true);
  });

  it('reads containers (2.2.5.2.6): a plain list is an array, a dictionary a Map with any key, a list with properties keeps them', () => {
    const list = one('<Obj RefId="0"><TN RefId="0"><T>System.Object[]</T><T>System.Array</T><T>System.Object</T></TN><LST><S>a</S><I32>1</I32><Nil/></LST></Obj>');
    assert.deepEqual(list, ['a', 1, null]);
    for (const tag of ['IE', 'STK', 'QUE']) assert.deepEqual(one(`<Obj RefId="0"><${tag}><S>x</S></${tag}></Obj>`), ['x'], tag);
    const dict = one('<Obj RefId="0"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">name</S><S N="Value">v</S></En><En><I32 N="Key">0</I32><B N="Value">true</B></En></DCT></Obj>') as Map<PSValue, PSValue>;
    assert.ok(dict instanceof Map);
    assert.equal(dict.get('name'), 'v');
    assert.equal(dict.get(0), true);
    const withProps = obj(one('<Obj RefId="0"><LST><S>a</S></LST><MS><I32 N="Count">1</I32></MS></Obj>'));
    assert.deepEqual(withProps.value, ['a']);
    assert.equal(withProps.extended.get('Count'), 1);
  });

  it('resolves Ref and TNRef, including a cycle (2.2.5.2.1, 2.2.5.2.3)', () => {
    const root = obj(
      one(
        '<Obj RefId="0"><TN RefId="0"><T>Node</T><T>System.Object</T></TN><MS>' +
          '<Obj N="Child" RefId="1"><TNRef RefId="0"/><MS><Ref N="Parent" RefId="0"/><S N="Name">child</S></MS></Obj>' +
          '<Ref N="Self" RefId="0"/>' +
          '</MS></Obj>',
      ),
    );
    const child = obj(root.extended.get('Child') as PSValue);
    assert.deepEqual(child.typeNames, ['Node', 'System.Object'], 'TNRef reuses the type names');
    assert.equal(child.extended.get('Parent'), root, 'the same object');
    assert.equal(root.extended.get('Self'), root);
    assert.throws(() => one('<Ref RefId="9"/>'), PSRemotingError);
  });

  it('turns an unknown element into kind unknown with its XML, and the siblings still decode', () => {
    const values = deserializeClixml('<S>before</S><Mystery a="1"><Inner>x</Inner></Mystery><S>after</S>');
    assert.equal(values.length, 3);
    const unknown = obj(values[1] as PSValue);
    assert.equal(unknown.kind, 'unknown');
    assert.equal(unknown.xml, '<Mystery a="1"><Inner>x</Inner></Mystery>');
    assert.deepEqual([values[0], values[2]], ['before', 'after']);
    const inside = obj(one('<Obj RefId="0"><MS><Weird N="w">?</Weird><S N="s">ok</S></MS></Obj>'));
    assert.equal(obj(inside.extended.get('w') as PSValue).kind, 'unknown');
    assert.equal(inside.extended.get('s'), 'ok');
  });

  it('reads an Objs document with the CLIXML namespace and an XML declaration, and refuses malformed XML', () => {
    const values = deserializeClixml('<?xml version="1.0"?><Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S>a</S><I32>1</I32></Objs>');
    assert.deepEqual(values, ['a', 1]);
    assert.throws(() => deserializeClixml('<S>unclosed'), PSRemotingError);
  });
});

describe('message bodies in the shapes of the specification examples', () => {
  it('SESSION_CAPABILITY (2.2.2.1): versions as MS properties', () => {
    const cap = obj(one('<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>'));
    assert.equal(obj(cap.extended.get('protocolversion') as PSValue).value, '2.3');
    assert.equal(obj(cap.extended.get('SerializationVersion') as PSValue).value, '1.1.0.1');
  });

  it('INIT_RUNSPACEPOOL (2.2.2.2): runspace counts, enums, HostInfo with a dictionary of I32 keys', () => {
    const init = obj(
      one(
        '<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32>' +
          '<Obj N="PSThreadOptions" RefId="1"><TN RefId="0"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj>' +
          '<Obj N="ApartmentState" RefId="2"><TN RefId="1"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj>' +
          '<Obj N="HostInfo" RefId="3"><MS><Obj N="_hostDefaultData" RefId="4"><MS><Obj N="data" RefId="5"><TN RefId="2"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT>' +
          '<En><I32 N="Key">9</I32><Obj N="Value" RefId="6"><MS><S N="T">System.String</S><S N="V">winlinux</S></MS></Obj></En>' +
          '</DCT></Obj></MS></Obj><B N="_isHostNull">false</B><B N="_isHostUINull">false</B><B N="_isHostRawUINull">false</B><B N="_useRunspaceHost">false</B></MS></Obj>' +
          '<Nil N="ApplicationArguments"/></MS></Obj>',
      ),
    );
    assert.equal(init.extended.get('MinRunspaces'), 1);
    assert.equal(obj(init.extended.get('PSThreadOptions') as PSValue).toStringValue, 'Default');
    const host = obj(init.extended.get('HostInfo') as PSValue);
    assert.equal(host.extended.get('_isHostNull'), false);
    const data = obj(host.extended.get('_hostDefaultData') as PSValue).extended.get('data') as Map<PSValue, PSValue>;
    assert.equal(obj(data.get(9) as PSValue).extended.get('V'), 'winlinux');
    assert.equal(init.extended.get('ApplicationArguments'), null);
  });

  it('RUNSPACEPOOL_STATE (2.2.2.9) and PIPELINE_STATE (2.2.2.21) with an error record', () => {
    const state = obj(one('<Obj RefId="0"><MS><I32 N="RunspaceState">2</I32></MS></Obj>'));
    assert.equal(state.extended.get('RunspaceState'), 2);
    const failed = obj(
      one(
        '<Obj RefId="0"><MS><I32 N="PipelineState">5</I32>' +
          '<Obj N="ExceptionAsErrorRecord" RefId="1"><TN RefId="0"><T>System.Management.Automation.ErrorRecord</T><T>System.Object</T></TN><ToString>boom</ToString><MS>' +
          '<Obj N="Exception" RefId="2"><TN RefId="1"><T>System.Management.Automation.RuntimeException</T><T>System.SystemException</T><T>System.Exception</T><T>System.Object</T></TN><ToString>boom</ToString><Props><S N="Message">boom</S></Props></Obj>' +
          '<Nil N="TargetObject"/><S N="FullyQualifiedErrorId">boom</S><Nil N="InvocationInfo"/><I32 N="ErrorCategory_Category">0</I32><S N="ErrorCategory_Activity"></S><S N="ErrorCategory_Reason">RuntimeException</S><S N="ErrorCategory_TargetName"></S><S N="ErrorCategory_TargetType"></S><S N="ErrorCategory_Message">NotSpecified: (:) [], RuntimeException</S><B N="SerializeExtendedInfo">false</B>' +
          '</MS></Obj></MS></Obj>',
      ),
    );
    assert.equal(failed.extended.get('PipelineState'), 5);
    const record = toErrorRecord(obj(failed.extended.get('ExceptionAsErrorRecord') as PSValue));
    assert.equal(record.message, 'boom');
    assert.equal(record.fullyQualifiedErrorId, 'boom');
    assert.equal(record.category, 0);
    assert.equal(record.categoryInfo, 'NotSpecified: (:) [], RuntimeException');
    assert.equal(record.exceptionType, 'System.Management.Automation.RuntimeException');
    assert.equal(record.scriptStackTrace, undefined);
    assert.equal(record.invocationInfo, undefined);
  });

  it('an ERROR_RECORD with ErrorDetails, InvocationInfo and a script stack trace (2.2.3.15)', () => {
    const record = toErrorRecord(
      obj(
        one(
          '<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.ErrorRecord</T><T>System.Object</T></TN><ToString>raw</ToString><MS>' +
            '<Obj N="Exception" RefId="1"><TN RefId="1"><T>System.IO.FileNotFoundException</T><T>System.Exception</T><T>System.Object</T></TN><Props><S N="Message">Cannot find file</S></Props></Obj>' +
            '<S N="FullyQualifiedErrorId">PathNotFound,Get-Item</S><I32 N="ErrorCategory_Category">13</I32><S N="ErrorCategory_TargetName">C:\\nope</S>' +
            '<S N="ErrorCategory_Message">ObjectNotFound: (C:\\nope:String) [Get-Item], FileNotFoundException</S>' +
            '<S N="ErrorDetails_Message">Friendly text</S><S N="ScriptStackTrace">at &lt;ScriptBlock&gt;, &lt;No file&gt;: line 1</S>' +
            '<Obj N="InvocationInfo" RefId="2"><MS><S N="MyCommand">Get-Item</S><I32 N="ScriptLineNumber">1</I32></MS></Obj>' +
            '</MS></Obj>',
        ),
      ),
    );
    assert.equal(record.message, 'Friendly text', 'ErrorDetails wins over the exception message');
    assert.equal(record.category, 13);
    assert.equal(record.targetName, 'C:\\nope');
    assert.equal(record.exceptionType, 'System.IO.FileNotFoundException');
    assert.equal(record.scriptStackTrace, 'at <ScriptBlock>, <No file>: line 1');
    assert.equal(record.invocationInfo?.extended.get('MyCommand'), 'Get-Item');
  });

  it('warning, verbose and debug records (2.2.3.16) and an information record (2.2.2.26)', () => {
    const warning = obj(one('<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.WarningRecord</T><T>System.Management.Automation.InformationalRecord</T><T>System.Object</T></TN><ToString>careful</ToString><MS><S N="InformationalRecord_Message">careful</S><B N="InformationalRecord_SerializeInvocationInfo">false</B></MS></Obj>'));
    assert.equal(toInformationalMessage(warning), 'careful');
    assert.equal(toInformationalMessage(obj(one('<Obj RefId="0"><ToString>fallback</ToString></Obj>'))), 'fallback');
    const info = toInformationRecord(
      obj(
        one(
          '<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.InformationRecord</T><T>System.Object</T></TN><MS>' +
            '<Obj N="MessageData" RefId="1"><TN RefId="1"><T>System.Management.Automation.HostInformationMessage</T><T>System.Object</T></TN><ToString>hi</ToString><Props><S N="Message">hi</S><B N="NoNewLine">false</B></Props></Obj>' +
            '<S N="Source">Write-Host</S><DT N="TimeGenerated">2026-10-12T01:02:03.0000000Z</DT><Obj N="Tags" RefId="2"><TN RefId="2"><T>System.Collections.Generic.List`1[[System.String]]</T><T>System.Object</T></TN><LST><S>PSHOST</S></LST></Obj>' +
            '<S N="User">example\\user</S><S N="Computer">example.test</S><U32 N="ProcessId">1</U32><U32 N="NativeThreadId">2</U32><U32 N="ManagedThreadId">3</U32></MS></Obj>',
        ),
      ),
    );
    assert.equal(obj(info.messageData).adapted.get('Message'), 'hi');
    assert.equal(info.source, 'Write-Host');
    assert.equal(info.timeGenerated?.iso, '2026-10-12T01:02:03.0000000Z');
    assert.deepEqual(info.tags, ['PSHOST']);
    assert.equal(info.user, 'example\\user');
    assert.equal(info.computer, 'example.test');
  });

  it('CONNECT_RUNSPACEPOOL (2.2.2.29) and RUNSPACEPOOL_INIT_DATA (2.2.2.30) shapes', () => {
    const connect = obj(one('<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32></MS></Obj>'));
    assert.deepEqual([...connect.extended.entries()], [['MinRunspaces', 1], ['MaxRunspaces', 1]]);
    const initData = obj(one('<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32></MS></Obj>'));
    assert.equal(initData.extended.get('MaxRunspaces'), 1);
  });
});

describe('writer (2.2.5 subset)', () => {
  it('writes each primitive the design lists, and reads it back', () => {
    const cases: Array<[PSValue, string]> = [
      ['text', '<S>text</S>'],
      [true, '<B>true</B>'],
      [5, '<I32>5</I32>'],
      [-2147483648, '<I32>-2147483648</I32>'],
      [2147483648, '<I64>2147483648</I64>'],
      [7n, '<I64>7</I64>'],
      [1.5, '<Db>1.5</Db>'],
      [Infinity, '<Db>INF</Db>'],
      [null, '<Nil/>'],
      [Buffer.from([1, 2, 3]), '<BA>AQID</BA>'],
      [{ kind: 'datetime', iso: '2026-10-12T01:02:03.0000000Z', date: new Date('2026-10-12T01:02:03Z') }, '<DT>2026-10-12T01:02:03.0000000Z</DT>'],
      [{ kind: 'duration', iso: 'PT2S' }, '<TS>PT2S</TS>'],
      [{ kind: 'securestring', encrypted: 'AAEC' }, '<SS>AAEC</SS>'],
      [psVersion('2.3'), '<Version>2.3</Version>'],
      [psGuid('792e5b37-4505-47ef-b7d2-8711bb7affa8'), '<G>792e5b37-4505-47ef-b7d2-8711bb7affa8</G>'],
    ];
    for (const [value, xml] of cases) {
      assert.equal(serializeClixml(value), xml);
      const back = one(xml);
      // An I64 reads back as a bigint by design, whatever wrote it.
      const expected = typeof value === 'number' && Number.isInteger(value) && xml.startsWith('<I64>') ? BigInt(value) : value;
      assert.deepEqual(back, expected, xml);
    }
    assert.equal(serializeClixml(NaN), '<Db>NaN</Db>');
  });

  it('writes an enum as Obj with TN, ToString and I32, and nested objects with MS and I32 dictionary keys (INIT_RUNSPACEPOOL shape)', () => {
    const data = new Map<PSValue, PSValue>([[9, psObject({ T: 'System.String', V: 'winlinux' })]]);
    const init = psObject({
      MinRunspaces: 1,
      MaxRunspaces: 1,
      PSThreadOptions: psEnum(['System.Management.Automation.Runspaces.PSThreadOptions', 'System.Enum', 'System.ValueType', 'System.Object'], 'Default', 0),
      HostInfo: psObject({ _hostDefaultData: psObject({ data }), _isHostNull: true }),
      ApplicationArguments: null,
    });
    const xml = serializeClixml(init);
    assert.equal(
      xml,
      '<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32>' +
        '<Obj N="PSThreadOptions" RefId="1"><TN RefId="0"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj>' +
        '<Obj N="HostInfo" RefId="2"><MS><Obj N="_hostDefaultData" RefId="3"><MS><Obj N="data" RefId="4"><TN RefId="1"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><I32 N="Key">9</I32><Obj N="Value" RefId="5"><MS><S N="T">System.String</S><S N="V">winlinux</S></MS></Obj></En></DCT></Obj></MS></Obj><B N="_isHostNull">true</B></MS></Obj>' +
        '<Nil N="ApplicationArguments"/></MS></Obj>',
    );
    const back = obj(one(xml));
    assert.equal(obj(back.extended.get('PSThreadOptions') as PSValue).value, 0);
    const hostData = obj(obj(back.extended.get('HostInfo') as PSValue).extended.get('_hostDefaultData') as PSValue).extended.get('data') as Map<PSValue, PSValue>;
    assert.equal(obj(hostData.get(9) as PSValue).extended.get('V'), 'winlinux');
  });

  it('writes arrays as System.Object[] lists and Maps as Hashtables, reusing TNRef and RefId within one message', () => {
    const shared = psObject({ n: 1 }, ['My.Type', 'System.Object']);
    const other = psObject({ n: 2 }, ['My.Type', 'System.Object']);
    const xml = serializeClixml([shared, other, shared, new Map<PSValue, PSValue>([['k', 'v']])]);
    assert.equal(
      xml,
      '<Obj RefId="0"><TN RefId="0"><T>System.Object[]</T><T>System.Array</T><T>System.Object</T></TN><LST>' +
        '<Obj RefId="1"><TN RefId="1"><T>My.Type</T><T>System.Object</T></TN><MS><I32 N="n">1</I32></MS></Obj>' +
        '<Obj RefId="2"><TNRef RefId="1"/><MS><I32 N="n">2</I32></MS></Obj>' +
        '<Ref RefId="1"/>' +
        '<Obj RefId="3"><TN RefId="2"><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">k</S><S N="Value">v</S></En></DCT></Obj>' +
        '</LST></Obj>',
    );
    const back = one(xml) as PSValue[];
    assert.equal(back[0], back[2], 'the Ref resolves to the same object');
    assert.equal(serializeClixml(shared), serializeClixml(shared), 'a new RefId space per call');
  });

  it('escapes XML and CLIXML in text, names, type names and ToString; refuses an unknown element', () => {
    const value = psObject({ 'a<b': 'x&y\n' }, ['T<1>'], 'to"string\t');
    const xml = serializeClixml(value);
    assert.equal(xml, '<Obj RefId="0"><TN RefId="0"><T>T&lt;1&gt;</T></TN><ToString>to"string_x0009_</ToString><MS><S N="a&lt;b">x&amp;y_x000A_</S></MS></Obj>');
    const back = obj(one(xml));
    assert.equal(back.extended.get('a<b'), 'x&y\n');
    assert.deepEqual(back.typeNames, ['T<1>']);
    assert.equal(back.toStringValue, 'to"string\t');
    assert.throws(() => serializeClixml({ kind: 'unknown', typeNames: [], adapted: new Map(), extended: new Map(), xml: '<x/>' }), PSRemotingError);
  });
});

describe('toJson', () => {
  it('shows an object as its properties with @type, @toString and @value, and cuts a cycle to @ref', () => {
    const root = obj(
      one(
        '<Obj RefId="0"><TN RefId="0"><T>Node</T><T>System.Object</T></TN><ToString>root</ToString><Props><S N="Name">r</S></Props><MS>' +
          '<Obj N="Child" RefId="1"><TNRef RefId="0"/><MS><Ref N="Parent" RefId="0"/></MS></Obj>' +
          '<I64 N="Big">9007199254740993</I64><D N="Dec">1.5</D><BA N="Bytes">AQID</BA><DT N="When">2026-01-01T00:00:00Z</DT><Nil N="Nothing"/>' +
          '<Obj N="State" RefId="2"><TN RefId="1"><T>E</T></TN><ToString>Opened</ToString><I32>2</I32></Obj>' +
          '<Obj N="List" RefId="3"><LST><S>a</S><Ref RefId="0"/></LST></Obj>' +
          '</MS></Obj>',
      ),
    );
    assert.deepEqual(toJson(root), {
      '@type': 'Node',
      '@toString': 'root',
      Name: 'r',
      Child: { '@type': 'Node', Parent: { '@ref': true } },
      Big: '9007199254740993',
      Dec: '1.5',
      Bytes: 'AQID',
      When: '2026-01-01T00:00:00Z',
      Nothing: null,
      State: { '@type': 'E', '@toString': 'Opened', '@value': 2 },
      List: ['a', { '@ref': true }],
    });
    assert.deepEqual(toJson(new Map<PSValue, PSValue>([['k', 1], [2, 'two']])), { k: 1, '2': 'two' });
    assert.deepEqual(toJson({ kind: 'securestring', encrypted: 'x' }), { '@type': 'System.Security.SecureString' });
    assert.deepEqual(toJson(obj(one('<Zed/>'))), { '@type': 'unknown', '@xml': '<Zed/>' });
    assert.equal(toJson(Infinity), 'Infinity');
    assert.equal(JSON.stringify(toJson(root)).includes('"@ref"'), true, 'JSON.stringify never sees the cycle');
  });
});
