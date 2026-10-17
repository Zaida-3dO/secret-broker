// Shared test helpers. The encoders here are written independently of src/redact/patterns.ts on
// purpose: a test that asked the implementation what to look for could not catch it missing one.
import type { Redactor, SecretValue } from '../../src/types.js';
import { createRedactor, type RedactorOptions } from '../../src/redact/index.js';

/** mulberry32: small seeded PRNG so every fuzz failure is reproducible from its seed */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const randInt = (r: () => number, lo: number, hiIncl: number) => lo + Math.floor(r() * (hiIncl - lo + 1));
export const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;

export function randomBytes(r: () => number, n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(r() * 256);
  return b;
}

export function dummyHex(r: () => number, n = 8): string {
  let s = '';
  for (let i = 0; i < n; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

/** Push `input` through a fresh redactor in the given chunk sizes (cycled), then flush. */
export function redactChunked(
  secrets: SecretValue[],
  input: Buffer,
  sizes: number[] | ((i: number) => number),
  opts?: RedactorOptions,
  onChunk?: (out: Buffer) => void,
): Buffer {
  const red = createRedactor(secrets, opts);
  return drive(red, input, sizes, onChunk);
}

export function drive(
  red: Redactor,
  input: Buffer,
  sizes: number[] | ((i: number) => number),
  onChunk?: (out: Buffer) => void,
): Buffer {
  const outs: Buffer[] = [];
  let pos = 0;
  let i = 0;
  while (pos < input.length) {
    const n = Math.max(1, typeof sizes === 'function' ? sizes(i) : sizes[i % sizes.length]!);
    const o = red.push(input.subarray(pos, pos + n));
    onChunk?.(o);
    outs.push(o);
    pos += n;
    i++;
  }
  const f = red.flush();
  onChunk?.(f);
  outs.push(f);
  return Buffer.concat(outs);
}

export function redactOnce(secrets: SecretValue[], input: Buffer | string, opts?: RedactorOptions): Buffer {
  const red = createRedactor(secrets, opts);
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return Buffer.concat([red.push(buf), red.flush()]);
}

// ---------- independent encoders ----------

export type Encoder = { name: string; enc: (v: string) => Buffer };

const s = (str: string) => Buffer.from(str, 'utf8');

/** percent-encode every UTF-8 byte except ASCII characters matching `keep` */
export function pctWith(v: string, keep: RegExp, plus: boolean): string {
  return [...Buffer.from(v, 'utf8')]
    .map((b) => {
      const c = String.fromCharCode(b);
      if (b < 128 && keep.test(c)) return c;
      if (plus && b === 0x20) return '+';
      return '%' + b.toString(16).padStart(2, '0').toUpperCase();
    })
    .join('');
}
/** RFC 3986 strict: everything but unreserved escaped */
const strictPct = (v: string, plus: boolean) => pctWith(v, /[A-Za-z0-9\-._~]/, plus);

export const ENCODERS: Encoder[] = [
  { name: 'exact', enc: (v) => s(v) },
  { name: 'upper', enc: (v) => s(v.toUpperCase()) },
  { name: 'lower', enc: (v) => s(v.toLowerCase()) },
  { name: 'hex-lower', enc: (v) => s(Buffer.from(v).toString('hex')) },
  { name: 'hex-upper', enc: (v) => s(Buffer.from(v).toString('hex').toUpperCase()) },
  { name: 'base64', enc: (v) => s(Buffer.from(v).toString('base64')) },
  { name: 'base64-nopad', enc: (v) => s(Buffer.from(v).toString('base64').replace(/=/g, '')) },
  { name: 'base64url', enc: (v) => s(Buffer.from(v).toString('base64url')) },
  {
    name: 'base64url-pad',
    enc: (v) => s(Buffer.from(v).toString('base64').replace(/\+/g, '-').replace(/\//g, '_')),
  },
  { name: 'encodeURIComponent', enc: (v) => s(encodeURIComponent(v)) },
  {
    name: 'encodeURIComponent-lowerhex',
    enc: (v) => s(encodeURIComponent(v).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())),
  },
  { name: 'urlsearchparams', enc: (v) => s(new URLSearchParams({ k: v }).toString().slice(2)) },
  { name: 'encodeURI', enc: (v) => s(encodeURI(v)) },
  { name: 'rfc3986', enc: (v) => s(strictPct(v, false)) },
  { name: 'rfc3986-plus', enc: (v) => s(strictPct(v, true)) },
  { name: 'json', enc: (v) => s(JSON.stringify(v).slice(1, -1)) },
  { name: 'json-slash', enc: (v) => s(JSON.stringify(v).slice(1, -1).split('/').join('\\/')) },
  {
    name: 'json-ascii',
    enc: (v) =>
      s(
        JSON.stringify(v)
          .slice(1, -1)
          .split('')
          .map((c) => (c.charCodeAt(0) > 0x7e ? '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0') : c))
          .join(''),
      ),
  },
  { name: 'utf16le', enc: (v) => Buffer.from(v, 'utf16le') },
  // PHP urlencode / Java URLEncoder
  { name: 'php-urlencode', enc: (v) => s(pctWith(v, /[A-Za-z0-9\-_.]/, true)) },
  // .NET WebUtility.UrlEncode
  { name: 'dotnet-urlencode', enc: (v) => s(pctWith(v, /[A-Za-z0-9\-_.!*()]/, true)) },
  { name: 'pct-every-byte', enc: (v) => s(pctWith(v, /(?!)/, false)) },
  {
    // .NET System.Text.Json default encoder: " ' + < > & ` and everything non-ASCII as \uXXXX
    name: 'json-dotnet',
    enc: (v) =>
      s(
        v
          .split('') // UTF-16 code units
          .map((c) => {
            const code = c.charCodeAt(0);
            if (code > 0x7e || `"'+<>&\``.includes(c)) return '\\u' + code.toString(16).toUpperCase().padStart(4, '0');
            return JSON.stringify(c).slice(1, -1);
          })
          .join(''),
      ),
  },
];

/**
 * base64 of `pre ++ value ++ post`, with the span of characters every one of whose six bits come
 * from `value` (found by walking the bits, not by formula).
 */
export function embeddedBase64(value: string, pre: Buffer, post: Buffer, urlSafe: boolean) {
  const v = Buffer.from(value, 'utf8');
  let b64 = Buffer.concat([pre, v, post]).toString('base64');
  if (urlSafe) b64 = b64.replace(/\+/g, '-').replace(/\//g, '_');
  const lo = pre.length * 8;
  const hi = (pre.length + v.length) * 8;
  let first = -1;
  let last = -1;
  for (let i = 0; i * 6 < hi; i++) {
    if (i * 6 >= lo && i * 6 + 6 <= hi) {
      if (first < 0) first = i;
      last = i;
    }
  }
  return { b64, core: b64.slice(first, last + 1) };
}

export function countOf(hay: Buffer | string, needle: string): number {
  const h = typeof hay === 'string' ? hay : hay.toString('latin1');
  const n = Buffer.from(needle, 'utf8').toString('latin1');
  let k = 0;
  for (let i = h.indexOf(n); i >= 0; i = h.indexOf(n, i + n.length)) k++;
  return k;
}
