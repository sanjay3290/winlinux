import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mapEventRecords, mapProcesses, mapServices } from '../src/winrm/mapping.js';
import { WinRMProtocolError } from '../src/winrm/errors.js';

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
}

describe('JSON mapping', () => {
  it('maps event records with ISO timestamps', () => {
    assert.deepEqual(mapEventRecords(fixture('events.json')), [
      {
        timeCreated: '2026-09-11T14:24:35.123Z',
        id: 7036,
        level: 'Information',
        provider: 'Service Control Manager',
        message: 'The Windows Update service entered the running state.',
      },
      {
        timeCreated: '2026-09-11T14:20:01.000Z',
        id: 10016,
        level: 'Error',
        provider: 'Microsoft-Windows-DistributedCOM',
        message: 'Access denied.',
      },
    ]);
  });

  it('parses the Windows PowerShell 5.1 ConvertTo-Json date form', () => {
    // ConvertTo-Json on 5.1 writes DateTime as \/Date(<ms>)\/, with a zone
    // offset for a Local kind. JSON.parse turns \/ into /.
    const events = mapEventRecords(
      '[{"TimeCreated":"\\/Date(1791551154213)\\/","Id":7036,"LevelDisplayName":"Information","ProviderName":"Service Control Manager","Message":"m"},' +
        '{"TimeCreated":"\\/Date(1791551154213+0200)\\/","Id":1,"LevelDisplayName":"Error","ProviderName":"p","Message":"n"},' +
        '{"TimeCreated":"\\/Date(-1000)\\/","Id":2,"LevelDisplayName":"Error","ProviderName":"p","Message":"o"}]',
    );
    assert.equal(events[0]?.timeCreated, new Date(1791551154213).toISOString());
    assert.equal(events[0]?.timeCreated, '2026-10-09T13:05:54.213Z');
    assert.equal(events[1]?.timeCreated, '2026-10-09T13:05:54.213Z', 'the offset does not move the instant');
    assert.equal(events[2]?.timeCreated, '1969-12-31T23:59:59.000Z');
    const processes = mapProcesses('[{"Id":4,"ProcessName":"System","CPU":1,"WS":1,"StartTime":"\\/Date(1791551154213)\\/"}]');
    assert.equal(processes[0]?.startTime, '2026-10-09T13:05:54.213Z');
    // Not the form: left alone, as before.
    assert.equal(mapEventRecords('[{"TimeCreated":"/Date(x)/","Id":1}]')[0]?.timeCreated, '/Date(x)/');
  });

  it('wraps a single event object into an array', () => {
    const records = mapEventRecords(fixture('events-single.json'));
    assert.equal(records.length, 1);
    assert.equal(records[0]?.id, 7036);
  });

  it('maps empty stdout to []', () => {
    assert.deepEqual(mapEventRecords(fixture('events-empty.txt')), []);
    assert.deepEqual(mapEventRecords('   \n  '), []);
    assert.deepEqual(mapServices(''), []);
    assert.deepEqual(mapProcesses(''), []);
  });

  it('maps services with numeric and string enums', () => {
    assert.deepEqual(mapServices(fixture('services.json')), [
      { name: 'wuauserv', displayName: 'Windows Update', status: 'Running', startType: 'Manual' },
      { name: 'Spooler', displayName: 'Print Spooler', status: 'Stopped', startType: 'Automatic' },
    ]);
  });

  it('maps processes with null CPU/StartTime', () => {
    assert.deepEqual(mapProcesses(fixture('processes.json')), [
      { id: 4, name: 'System', cpuSeconds: 123.45, workingSetBytes: 8192, startTime: '2026-09-11T10:24:35' },
      { id: 9999, name: 'exited', cpuSeconds: null, workingSetBytes: 0, startTime: null },
    ]);
  });

  it('wraps a single process object and parses PM times', () => {
    assert.deepEqual(mapProcesses(fixture('process-single.json')), [
      { id: 4, name: 'System', cpuSeconds: 1.5, workingSetBytes: 4096, startTime: '2026-09-11T13:02:03' },
    ]);
  });

  it('keeps unparseable timestamps as raw strings', () => {
    const out = mapProcesses('[{"Id":1,"ProcessName":"x","CPU":0,"WS":0,"StartTime":"11.09.2026 10:24:35"}]');
    assert.equal(out[0]?.startTime, '11.09.2026 10:24:35');
  });

  it('throws WinRMProtocolError on malformed JSON', () => {
    assert.throws(() => mapEventRecords('not json'), WinRMProtocolError);
    assert.throws(() => mapServices('{oops'), WinRMProtocolError);
    assert.throws(() => mapProcesses('42'), WinRMProtocolError);
  });
});
