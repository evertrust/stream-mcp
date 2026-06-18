import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  configureLogging,
  getLogger,
  setMcpLoggingSink,
} from '../../src/logging.js';

afterEach(() => {
  configureLogging('INFO'); // reset the module-global level
  setMcpLoggingSink(undefined);
  vi.restoreAllMocks();
});

describe('logging', () => {
  it('emits structured JSON to stderr with ts/level/logger/msg', () => {
    const writes: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: any) => {
      writes.push(String(chunk));
      return true;
    });
    getLogger('test.logger').info('hello', { request_id: 'r1' });
    expect(writes).toHaveLength(1);
    const entry = JSON.parse(writes[0]!);
    expect(entry).toMatchObject({
      level: 'INFO',
      logger: 'test.logger',
      msg: 'hello',
      request_id: 'r1',
    });
    expect(typeof entry.ts).toBe('string');
  });

  it('drops messages below the configured level', () => {
    const writes: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: any) => {
      writes.push(String(chunk));
      return true;
    });
    configureLogging('WARNING');
    const log = getLogger('test');
    log.info('suppressed');
    log.debug('suppressed');
    expect(writes).toHaveLength(0);
    log.warning('shown');
    expect(writes).toHaveLength(1);
    expect(JSON.parse(writes[0]!).level).toBe('WARNING');
  });

  it('forwards to the MCP sink and survives a throwing sink', () => {
    vi.spyOn(process.stderr, 'write').mockReturnValue(true as any);
    const received: Array<{ level: string; msg: string }> = [];
    setMcpLoggingSink((level, payload) => {
      received.push({ level, msg: payload.msg });
    });
    getLogger('test').error('boom');
    expect(received).toEqual([{ level: 'error', msg: 'boom' }]);

    // A sink that throws must not crash the logging call.
    setMcpLoggingSink(() => {
      throw new Error('sink failure');
    });
    expect(() => getLogger('test').info('still ok')).not.toThrow();
  });
});
