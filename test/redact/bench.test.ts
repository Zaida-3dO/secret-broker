import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../../src/redact/index.js';
import { rng, dummyHex, randomBytes, countOf } from './helpers.js';

// Design §6: "fast enough for 50 MB of output". Budget from the brief: 50 MB with 20 secrets < 3 s.
// Skipped under CI (shared runners make wall-clock assertions flaky); set REDACT_BENCH=1 to force.
const skip = !!process.env.CI && !process.env.REDACT_BENCH;

for (const kind of ['text', 'binary'] as const) {
  test(`benchmark: 50 MB of ${kind} output, 20 secrets, 64 KiB chunks, < 3 s`, { skip }, (t) => {
    const r = rng(2026);
    const secrets = Array.from({ length: 20 }, (_, i) => ({
      name: `S${i}`,
      value: `DUMMY-SECRET-${dummyHex(r, 32)}/+ "é${i}"`,
    }));
    const line = Buffer.from('2026-10-10T22:00:00Z INFO request ok {"key":"value","n":123} aGVsbG8gd29ybGQ= ✓\n');
    const chunk =
      kind === 'text' ? Buffer.alloc(64 * 1024, line) : randomBytes(r, 64 * 1024);
    // one secret, in a different encoding each time, inside every chunk
    const encs = (v: string) => [v, Buffer.from(v).toString('base64'), Buffer.from(v).toString('hex'), encodeURIComponent(v)];
    const total = 50 * 1024 * 1024;
    const chunks: Buffer[] = [];
    for (let n = 0, i = 0; n < total; i++) {
      const c = Buffer.from(chunk);
      const enc = Buffer.from(encs(secrets[i % 20]!.value)[i % 4]!);
      enc.copy(c, 1000);
      chunks.push(c);
      n += c.length;
    }

    const t0 = performance.now();
    const red = createRedactor(secrets);
    const built = performance.now();
    const outs: Buffer[] = [];
    for (const c of chunks) outs.push(red.push(c));
    outs.push(red.flush());
    const ms = performance.now() - t0;
    let labels = 0;
    for (const o of outs) labels += countOf(o, '[secret:');
    t.diagnostic(`build ${(built - t0).toFixed(0)} ms, total ${ms.toFixed(0)} ms for ${chunks.length * 64} KiB`);
    assert.equal(labels, chunks.length, 'every planted secret was redacted');
    assert.ok(ms < 3000, `took ${ms.toFixed(0)} ms`);
  });
}
