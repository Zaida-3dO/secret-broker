import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../../src/redact/index.js';
import { Automaton } from '../../src/redact/automaton.js';
import { buildPatterns } from '../../src/redact/patterns.js';
import { redactOnce, redactChunked, rng, randInt, randomBytes, ENCODERS, pick, dummyHex } from './helpers.js';

test('a secret shorter than minLength throws, naming the secret and never echoing the value', () => {
  assert.throws(
    () => createRedactor([{ name: 'OK_ONE', value: 'DUMMY-SECRET-long-enough' }, { name: 'TOO_SHORT', value: 'Dum-7ch' }]),
    (e: Error) => {
      assert.match(e.message, /TOO_SHORT/);
      assert.ok(!e.message.includes('Dum-7ch'), 'message must not contain the value');
      return true;
    },
  );
  assert.throws(() => createRedactor([{ name: 'EMPTY', value: '' }]), /EMPTY/);
  // exactly minLength is accepted
  assert.doesNotThrow(() => createRedactor([{ name: 'EIGHT', value: 'DUMMY-08' }]));
  // custom minLength
  assert.throws(() => createRedactor([{ name: 'X', value: 'DUMMY-SECRET-0a' }], { minLength: 16 }), /X/);
  assert.doesNotThrow(() => createRedactor([{ name: 'X', value: 'DUMMY-SECRET-0a' }], { minLength: 15 }));
});

test('minLength counts characters (code points), not UTF-16 units or bytes', () => {
  // 7 code points, 8 UTF-16 units (the emoji is a surrogate pair), 13 UTF-8 bytes
  assert.throws(() => createRedactor([{ name: 'EMOJI', value: 'DUMMY-🔑' }]), /EMOJI/);
  assert.doesNotThrow(() => createRedactor([{ name: 'EMOJI', value: 'DUMMY-🔑!' }]));
});

test('empty input and no secrets', () => {
  const r = createRedactor([{ name: 'S', value: 'DUMMY-SECRET-0000' }]);
  assert.equal(r.push(Buffer.alloc(0)).length, 0);
  assert.equal(r.flush().length, 0);
  assert.equal(r.flush().length, 0);
  const none = createRedactor([]);
  const bin = Buffer.from([0, 0xff, 0xc3, 0x28, 0x80]);
  assert.deepEqual(Buffer.concat([none.push(bin), none.flush()]), bin);
});

test('multiple secrets in one stream each get their own label', () => {
  const secrets = [
    { name: 'A', value: 'DUMMY-SECRET-aaaa1111' },
    { name: 'B', value: 'DUMMY-SECRET-bbbb2222' },
    { name: 'C', value: 'DUMMY-SECRET-cccc3333' },
  ];
  const input = `a=DUMMY-SECRET-aaaa1111 b=${Buffer.from('DUMMY-SECRET-bbbb2222').toString('base64')} c=${Buffer.from('DUMMY-SECRET-cccc3333').toString('hex')}`;
  assert.equal(redactOnce(secrets, input).toString(), 'a=[secret:A] b=[secret:B] c=[secret:C]');
});

test('a value that is a substring of another: the longer secret wins where it occurs', () => {
  const secrets = [
    { name: 'SHORT', value: 'DUMMY-SECRET-abcdef01' },
    { name: 'LONG', value: 'DUMMY-SECRET-abcdef01-EXTENDED' },
  ];
  assert.equal(redactOnce(secrets, 'x DUMMY-SECRET-abcdef01-EXTENDED y').toString(), 'x [secret:LONG] y');
  assert.equal(redactOnce(secrets, 'x DUMMY-SECRET-abcdef01-EXTENDE y').toString(), 'x [secret:SHORT]-EXTENDE y');
  // order of the secrets array does not matter
  assert.equal(
    redactOnce([secrets[1]!, secrets[0]!], 'x DUMMY-SECRET-abcdef01-EXTENDED y').toString(),
    'x [secret:LONG] y',
  );
});

test('overlapping matches merge into one region labelled by the longest; no byte of either leaks', () => {
  const secrets = [
    { name: 'A', value: 'DUMMY-SECRET-1111-OVERLAP' },
    { name: 'B', value: 'OVERLAP-DUMMY-SECRET-3333-longer' },
  ];
  const out = redactOnce(secrets, '<DUMMY-SECRET-1111-OVERLAP-DUMMY-SECRET-3333-longer>').toString();
  assert.equal(out, '<[secret:B]>');
  // longer one first in the stream this time
  const s2 = [
    { name: 'A', value: 'DUMMY-SECRET-1111-longer-OVERLAP' },
    { name: 'B', value: 'OVERLAP-DUMMY-SECRET-3333' },
  ];
  assert.equal(redactOnce(s2, '<DUMMY-SECRET-1111-longer-OVERLAP-DUMMY-SECRET-3333>').toString(), '<[secret:A]>');
});

test('a chain of overlaps where a later, longer match starts before an earlier region', () => {
  // C starts before A's region and overlaps both A and B; all three must collapse into one region.
  const secrets = [
    { name: 'A', value: 'DUMMY-AAAA' },
    { name: 'B', value: 'BBBB-DUMMY' },
    { name: 'C', value: 'zz-DUMMY-AAAABBBB-DUMMY-cc' },
  ];
  assert.equal(redactOnce(secrets, '[zz-DUMMY-AAAABBBB-DUMMY-cc]').toString(), '[[secret:C]]');
  assert.equal(redactOnce(secrets, '[zz-DUMMY-AAAABBBB-DUMMY-c]').toString(), '[zz-[secret:A][secret:B]-c]');
});

test('adjacent (touching, non-overlapping) matches are labelled separately', () => {
  const secrets = [
    { name: 'A', value: 'DUMMY-SECRET-aaaa' },
    { name: 'B', value: 'DUMMY-SECRET-bbbb' },
  ];
  assert.equal(redactOnce(secrets, 'DUMMY-SECRET-aaaaDUMMY-SECRET-bbbb').toString(), '[secret:A][secret:B]');
});

test('repeated occurrences are all replaced', () => {
  const v = 'DUMMY-SECRET-rep-9999';
  const input = Array.from({ length: 50 }, () => v).join(',');
  const out = redactOnce([{ name: 'R', value: v }], input).toString();
  assert.equal(out, Array.from({ length: 50 }, () => '[secret:R]').join(','));
});

test('non-UTF-8 binary bytes around a secret are preserved byte-for-byte', () => {
  const r = rng(7);
  const v = 'DUMMY-SECRET-bin-cafe';
  for (let i = 0; i < 50; i++) {
    const a = randomBytes(r, randInt(r, 0, 300));
    const b = randomBytes(r, randInt(r, 0, 300));
    const input = Buffer.concat([a, Buffer.from(v), b]);
    const out = redactChunked([{ name: 'S', value: v }], input, (k) => randInt(r, 1, 64 + k));
    assert.deepEqual(out, Buffer.concat([a, Buffer.from('[secret:S]'), b]));
  }
});

test('unicode labels and values', () => {
  const v = 'DUMMY-секрет-秘密-ab';
  assert.equal(redactOnce([{ name: 'ключ', value: v }], `«${v}»`).toString(), '«[secret:ключ]»');
  // non-ASCII case variants
  assert.equal(redactOnce([{ name: 'K', value: v }], v.toUpperCase()).toString(), '[secret:K]');
});

test('the sparse (over-budget) automaton path produces identical output to the dense one', () => {
  const r = rng(99);
  const secrets = Array.from({ length: 5 }, (_, i) => ({ name: `S${i}`, value: `DUMMY-SECRET-${dummyHex(r, 12)}/é "${i}"` }));
  const ac = new Automaton(buildPatterns(secrets.map((s) => s.value), 8), 64);
  assert.ok(ac.denseStates < ac.states / 10, 'the tiny budget really does force sparse states');
  for (let iter = 0; iter < 40; iter++) {
    const parts: Buffer[] = [];
    for (let k = 0; k < 30; k++) {
      if (r() < 0.4) parts.push(pick(r, ENCODERS).enc(pick(r, secrets).value));
      else parts.push(randomBytes(r, randInt(r, 0, 40)));
    }
    const input = Buffer.concat(parts);
    const dense = redactOnce(secrets, input);
    const sparse = redactChunked(secrets, input, (k) => randInt(r, 1, 50 + k), { denseBudget: 64 });
    assert.deepEqual(sparse, dense);
    for (const s of secrets) assert.ok(!sparse.includes(Buffer.from(s.value)));
  }
});

test('flush() mid-stream emits held-back bytes; the rest of a straddling secret is still redacted', () => {
  const v = 'DUMMY-SECRET-idle-4242';
  const red = createRedactor([{ name: 'S', value: v }]);
  const a = red.push(Buffer.from('log: DUMMY-SECRET-'));
  const f = red.flush();
  assert.equal(Buffer.concat([a, f]).toString(), 'log: DUMMY-SECRET-', 'flush emits everything held back');
  const b = red.push(Buffer.from('idle-4242 done\n'));
  const end = red.flush();
  assert.equal(Buffer.concat([b, end]).toString(), '[secret:S] done\n');
  // and a fresh secret after the flush is redacted normally
  const c = Buffer.concat([red.push(Buffer.from(`again ${v}!`)), red.flush()]);
  assert.equal(c.toString(), 'again [secret:S]!');
});

test('push output never retains a view of the caller buffer that a later mutation could change', () => {
  const red = createRedactor([{ name: 'S', value: 'DUMMY-SECRET-mut-0001' }]);
  // the held-back tail turns out NOT to be a secret, so it is emitted raw on the next push
  const chunk = Buffer.from('hello DUMMY-SECRET-mu');
  const out1 = red.push(chunk);
  assert.ok(out1.length < chunk.length, 'a tail was held back');
  chunk.fill(0x41); // caller reuses its buffer
  const out2 = Buffer.concat([red.push(Buffer.from('X bye')), red.flush()]);
  assert.equal(Buffer.concat([out1, out2]).toString(), 'hello DUMMY-SECRET-muX bye');
  // and when it IS a secret
  const red2 = createRedactor([{ name: 'S', value: 'DUMMY-SECRET-mut-0001' }]);
  const c2 = Buffer.from('hello DUMMY-SECRET-mu');
  const o1 = red2.push(c2);
  c2.fill(0x41);
  const o2 = Buffer.concat([red2.push(Buffer.from('t-0001 bye')), red2.flush()]);
  assert.equal(Buffer.concat([o1, o2]).toString(), 'hello [secret:S] bye');
});

test('a mismatch deep inside a pattern falls back to the right shorter prefix (dense and sparse)', () => {
  // After "DUMMY-DUMMY-" a "D" does not continue the pattern; the failure link must land on
  // "DUMMY-" (not the root) or the real occurrence that started six bytes earlier is missed.
  const secrets = [{ name: 'S', value: 'DUMMY-DUMMY-SECRET-99' }];
  for (const denseBudget of [undefined, 1]) {
    for (const sizes of [[1000], [1], [5, 3]]) {
      const out = redactChunked(secrets, Buffer.from('<DUMMY-DUMMY-DUMMY-SECRET-99>'), sizes, { denseBudget });
      assert.equal(out.toString(), '<DUMMY-[secret:S]>', `budget=${denseBudget} sizes=${sizes}`);
    }
  }
  // output link through a failure link: B is a suffix of a longer partial match of A
  const s2 = [
    { name: 'A', value: 'xxDUMMY-SECRET-1234567-tail' },
    { name: 'B', value: 'DUMMY-SECRET-1234567' },
  ];
  for (const denseBudget of [undefined, 1]) {
    const out = redactChunked(s2, Buffer.from('xxDUMMY-SECRET-1234567-tai!'), [1], { denseBudget });
    assert.equal(out.toString(), 'xx[secret:B]-tai!', `budget=${denseBudget}`);
  }
});

test('equal-length overlapping matches: the earlier one labels the merged region', () => {
  const secrets = [
    { name: 'FIRST', value: 'DUMMY-SECRET-AAAA-OV' },
    { name: 'SECOND', value: 'OV-DUMMY-SECRET-BBBB' },
  ];
  assert.equal(secrets[0]!.value.length, secrets[1]!.value.length);
  assert.equal(redactOnce(secrets, '<DUMMY-SECRET-AAAA-OV-DUMMY-SECRET-BBBB>').toString(), '<[secret:FIRST]>');
  assert.equal(redactOnce([secrets[1]!, secrets[0]!], '<DUMMY-SECRET-AAAA-OV-DUMMY-SECRET-BBBB>').toString(), '<[secret:FIRST]>');
});

test('a self-overlapping secret repeated for megabytes does not stall output or go quadratic', () => {
  for (const [value, unit] of [
    ['abababababab', 'ab'],
    ['0000000000000000', '0'],
  ] as const) {
    const red = createRedactor([{ name: 'R', value }]);
    const chunk = Buffer.from(unit.repeat((64 * 1024) / unit.length));
    const total = 8 * 1024 * 1024;
    const t0 = performance.now();
    let beforeFlush = 0;
    const outs: Buffer[] = [];
    for (let n = 0; n < total; n += chunk.length) {
      const o = red.push(chunk);
      beforeFlush += o.length;
      outs.push(o);
    }
    outs.push(red.flush());
    const ms = performance.now() - t0;
    assert.ok(beforeFlush > 0, `${value}: nothing emitted before flush`);
    const out = Buffer.concat(outs).toString();
    assert.match(out, /^(\[secret:R\])+$/, `${value}: only labels, no raw bytes`);
    assert.ok(out.length < 1000, `${value}: one label per ~1 MiB, got ${out.length} chars`);
    assert.ok(ms < 2000, `${value}: ${ms.toFixed(0)} ms for 8 MiB`);
  }
});

test('equal-length tie when a later match absorbs an earlier region: the earlier label wins', () => {
  // A [0,19) and B [19,29) are separate regions until C [13,32) overlaps both; |A| = |C| > |B|.
  const secrets = [
    { name: 'C', value: 'AAAA-1BBBB-DUMMY-zz' },
    { name: 'B', value: 'BBBB-DUMMY' },
    { name: 'A', value: 'DUMMY-SECRET-AAAA-1' },
  ];
  assert.equal(secrets[0]!.value.length, secrets[2]!.value.length);
  assert.equal(redactOnce(secrets, '<DUMMY-SECRET-AAAA-1BBBB-DUMMY-zz>').toString(), '<[secret:A]>');
  assert.equal(redactOnce(secrets, '<DUMMY-SECRET-AAAA-1BBBB-DUMMY-z>').toString(), '<[secret:A][secret:B]-z>');
});
