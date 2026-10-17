import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../../src/redact/index.js';
import { Automaton } from '../../src/redact/automaton.js';
import { buildPatterns } from '../../src/redact/patterns.js';
import { ENCODERS, embeddedBase64, redactOnce, redactChunked, rng, randInt, randomBytes, countOf } from './helpers.js';

const SECRETS = [
  { name: 'API', value: 'DUMMY-SECRET-7e3a/91+fc "x" é' },
  { name: 'UNI', value: 'DUMMY-秘密-ключ-🔑-c0de' },
  { name: 'URL', value: 'https://bot:DUMMY-PW-%2B5a5a@host.invalid/' },
];

/** A corpus containing every encoder's output of every secret, among multi-byte UTF-8 text. */
function corpus(): Buffer {
  const r = rng(1234);
  const parts: Buffer[] = [Buffer.from('start ✓ ')];
  for (const s of SECRETS) {
    for (const e of ENCODERS) {
      parts.push(e.enc(s.value), Buffer.from(` — ${e.name} ✓ `));
    }
    const { b64 } = embeddedBase64(s.value, randomBytes(r, 1), randomBytes(r, 2), false);
    parts.push(Buffer.from(b64 + ' 🔑 '));
  }
  parts.push(Buffer.from('DUMMY-PW-+5a5a end'));
  return Buffer.concat(parts);
}

const INPUT = corpus();
const REFERENCE = redactOnce(SECRETS, INPUT);

test('reference output really redacted the corpus (guards the fuzz oracle)', () => {
  const text = REFERENCE.toString('utf8');
  for (const s of SECRETS) assert.equal(countOf(text, s.value), 0);
  assert.ok(countOf(text, '[secret:API]') >= ENCODERS.length);
  assert.ok(countOf(text, '[secret:UNI]') >= ENCODERS.length);
  assert.match(text, /end$/);
});

test(`every single split point (${INPUT.length + 1} of them) gives the reference output`, () => {
  for (let i = 0; i <= INPUT.length; i++) {
    const red = createRedactor(SECRETS);
    const out = Buffer.concat([red.push(INPUT.subarray(0, i)), red.push(INPUT.subarray(i)), red.flush()]);
    if (!out.equals(REFERENCE)) assert.fail(`split at ${i} differs`);
  }
});

test('one byte at a time gives the reference output', () => {
  assert.deepEqual(redactChunked(SECRETS, INPUT, [1]), REFERENCE);
});

test('300 seeded random chunkings give the reference output', () => {
  for (let seed = 1; seed <= 300; seed++) {
    const r = rng(seed);
    const max = pickMax(r);
    const out = redactChunked(SECRETS, INPUT, () => randInt(r, 1, max));
    if (!out.equals(REFERENCE)) assert.fail(`seed ${seed} differs`);
  }
});

function pickMax(r: () => number): number {
  return [2, 3, 7, 16, 61, 200, 4096][Math.floor(r() * 7)]!;
}

test('every emitted chunk of valid UTF-8 input is itself valid UTF-8 (no split sequences)', () => {
  for (let seed = 1; seed <= 100; seed++) {
    const r = rng(seed);
    redactChunked(SECRETS, INPUT, () => randInt(r, 1, 9), undefined, (out) => {
      const roundTrip = Buffer.from(out.toString('utf8'), 'utf8');
      if (!roundTrip.equals(out)) assert.fail(`seed ${seed}: a chunk split a UTF-8 sequence`);
    });
  }
});

test('output is not held back indefinitely: lag stays within maxPatternLen-1 (+3 for a UTF-8 tail)', () => {
  const ac = new Automaton(buildPatterns(SECRETS.map((s) => s.value), 8));
  const red = createRedactor(SECRETS);
  const r = rng(5);
  const text = Buffer.from('plain log line with ünïcödé and no secrets at all ✓ 0123456789\n'.repeat(2000));
  let inLen = 0;
  let outLen = 0;
  for (let pos = 0; pos < text.length; ) {
    const n = randInt(r, 1, 300);
    const chunk = text.subarray(pos, pos + n);
    pos += chunk.length;
    inLen += chunk.length;
    outLen += red.push(chunk).length;
    assert.ok(inLen - outLen <= ac.maxLen - 1 + 3, `lag ${inLen - outLen} > ${ac.maxLen - 1 + 3}`);
  }
  outLen += red.flush().length;
  assert.equal(outLen, inLen);
});

test('random binary noise without secrets passes through byte-identical under any chunking', () => {
  for (let seed = 1; seed <= 50; seed++) {
    const r = rng(seed);
    const noise = randomBytes(r, 20_000);
    const out = redactChunked(SECRETS, noise, () => randInt(r, 1, 1000));
    if (!out.equals(noise)) assert.fail(`seed ${seed}: noise was altered`);
  }
});

test('huge input: 16 MiB with a secret in 3 encodings every ~64 KiB, in random chunks', () => {
  const r = rng(77);
  const v = SECRETS[0]!.value;
  const filler = Buffer.from('lorem ipsum dolor sit amet ✓ '.repeat(2300)); // ~64 KiB
  const parts: Buffer[] = [];
  const expected: Buffer[] = [];
  const label = Buffer.from('[secret:API]');
  let inserted = 0;
  while (parts.reduce((a, b) => a + b.length, 0) < 16 * 1024 * 1024) {
    const enc = [ENCODERS[0]!, ENCODERS[3]!, ENCODERS[5]!][inserted % 3]!.enc(v);
    parts.push(filler, enc);
    expected.push(filler, label);
    inserted++;
  }
  const input = Buffer.concat(parts);
  const out = redactChunked(SECRETS, input, () => randInt(r, 1, 128 * 1024));
  assert.deepEqual(out, Buffer.concat(expected));
  assert.equal(countOf(out, '[secret:API]'), inserted);
});
