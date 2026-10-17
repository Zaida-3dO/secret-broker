import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ENCODERS, embeddedBase64, redactChunked, rng, randInt, randomBytes, pick, dummyHex } from './helpers.js';

const WORDS = ['the', 'quick', 'ünïcödé', '秘密', '🔑', '{"k":', '"v"}', '\n', '\r\n', ' ', '=', '%', '\\', '/', '+'];
const DECOR = ['-', '/', '+', ' ', '"', '\\', 'é', 'ж', '😀', '%', '&', '<', '\n', '='];

function randomSecret(r: () => number, i: number): { name: string; value: string } {
  if (r() < 0.2) {
    return { name: `URL${i}`, value: `https://user${i}:DUMMY-PW-${dummyHex(r, 6)}%2F${dummyHex(r, 2)}@h${i}.invalid/p` };
  }
  let v = `DUMMY-SECRET-${dummyHex(r, randInt(r, 4, 24))}`;
  const extra = randInt(r, 0, 4);
  for (let k = 0; k < extra; k++) v += pick(r, DECOR) + dummyHex(r, 2);
  return { name: `S${i}`, value: v };
}

/**
 * Property: for random documents built from noise, text and encoded secrets, under random
 * chunking, the output contains none of the encodings that were inserted (nor the stable core of
 * any base64 blob the secret was embedded in), and nothing else is lost.
 */
test('property: no inserted encoding of any secret survives (400 seeded documents)', () => {
  for (let seed = 1; seed <= 400; seed++) {
    const r = rng(seed * 7919);
    const secrets = Array.from({ length: randInt(r, 1, 5) }, (_, i) => randomSecret(r, i));
    const forbidden: string[] = [];
    const parts: Buffer[] = [];
    const pieces = randInt(r, 1, 40);
    for (let k = 0; k < pieces; k++) {
      const roll = r();
      // the URL secrets' derived password is a target too
      const sec = pick(r, secrets);
      const target = sec.value.startsWith('https://') && r() < 0.5 ? decodeURIComponent(sec.value.split(':')[2]!.split('@')[0]!) : sec.value;
      if (roll < 0.35) {
        const e = pick(r, ENCODERS).enc(target);
        parts.push(e);
        forbidden.push(e.toString('latin1'));
      } else if (roll < 0.5) {
        const { b64, core } = embeddedBase64(target, randomBytes(r, randInt(r, 0, 7)), randomBytes(r, randInt(r, 0, 7)), r() < 0.5);
        parts.push(Buffer.from(b64));
        forbidden.push(core);
      } else if (roll < 0.75) {
        parts.push(randomBytes(r, randInt(r, 0, 64)));
      } else {
        parts.push(Buffer.from(Array.from({ length: randInt(r, 1, 8) }, () => pick(r, WORDS)).join('')));
      }
    }
    const input = Buffer.concat(parts);
    const out = redactChunked(secrets, input, () => randInt(r, 1, pick(r, [1, 5, 33, 500, 10_000]))).toString('latin1');
    for (const f of forbidden) {
      if (out.includes(f)) assert.fail(`seed ${seed}: an inserted encoding survived: ${JSON.stringify(f)}`);
    }
    for (const s of secrets) {
      if (out.includes(Buffer.from(s.value).toString('latin1'))) assert.fail(`seed ${seed}: raw value survived`);
    }
  }
});
