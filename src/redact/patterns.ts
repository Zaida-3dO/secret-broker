// Pattern generation for the redactor (design §6).
//
// For each secret value we generate the byte strings that its common encodings produce. Matching is
// ASCII-case-insensitive (see automaton.ts), so hex upper/lower, `%2F`/`%2f` and all-upper/all-lower
// ASCII variants of the value collapse into one pattern each; only non-ASCII case variants need an
// explicit pattern.

export interface Pattern {
  /** the bytes to find (before ASCII case-folding) */
  bytes: Buffer;
  /** index into the secrets array: whose name labels a match */
  secret: number;
}

/** length in code points — what a human means by "characters" for a unicode value */
export function charLength(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

/** Raw, `+`-as-space-decoded and plain-decoded forms of a URL component, at least `minLength` long. */
function withDecodings(raw: string, minLength: number, out: string[]): void {
  const forms = new Set<string>([raw]);
  for (const f of [(x: string) => decodeURIComponent(x.replace(/\+/g, ' ')), decodeURIComponent]) {
    try {
      forms.add(f(raw));
    } catch {
      /* malformed escape: the raw form still counts */
    }
  }
  for (const f of forms) if (charLength(f) >= minLength) out.push(f);
}

/** at most this many `@`-terminated password candidates per URL (see deriveSubSecrets) */
const MAX_PW_CANDIDATES = 4;

/**
 * Sub-secrets derived from a value: for every `scheme://user:pw@host` URL in it, the password —
 * raw and URL-decoded — when at least `minLength` characters; for `scheme://token@host` (no colon),
 * the token. A component shorter than that is skipped silently: it is not the caller's secret, so
 * refusing the whole value would be wrong.
 *
 * Passwords are not always escaped, so one may contain raw `/ ? # @` or spaces, which makes the
 * userinfo/host boundary ambiguous. Rather than guess, every `@` after the user's colon (up to
 * MAX_PW_CANDIDATES, and not past the start of another URL) ends a candidate. A wrong candidate only
 * costs a pattern that never occurs in output.
 */
export function deriveSubSecrets(value: string, minLength: number): string[] {
  const out: string[] = [];
  for (const m of value.matchAll(/[A-Za-z][A-Za-z0-9+.-]*:\/\//g)) {
    const restStart = m.index! + m[0].length;
    const tail = value.slice(restStart);
    const nextUrl = tail.search(/\s[A-Za-z][A-Za-z0-9+.-]*:\/\//);
    const rest = nextUrl < 0 ? tail : tail.slice(0, nextUrl);
    const user = /^[^\s:@/?#]*/.exec(rest)![0];
    if (rest[user.length] === ':') {
      const pwStart = user.length + 1;
      let found = 0;
      for (let at = rest.indexOf('@', pwStart); at >= 0 && found < MAX_PW_CANDIDATES; at = rest.indexOf('@', at + 1)) {
        withDecodings(rest.slice(pwStart, at), minLength, out);
        found++;
      }
    } else if (rest[user.length] === '@') {
      withDecodings(user, minLength, out); // token as the username: `https://TOKEN@host`
    }
  }
  return out;
}

const latin1 = (s: string) => Buffer.from(s, 'latin1');
const utf8 = (s: string) => Buffer.from(s, 'utf8');

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
/** Sets of ASCII characters different percent-encoders leave literal. */
const PCT_KEEP_SETS: string[] = [
  ALNUM + "-_.!~*'()", // encodeURIComponent
  ALNUM + '-_.~', // RFC 3986 unreserved (Python quote(safe=''), Go url.PathEscape-ish)
  ALNUM + '-_.~/', // Python urllib.parse.quote default (safe='/')
  ALNUM + '*-._', // WHATWG application/x-www-form-urlencoded (URLSearchParams)
  ALNUM + "-_.!~*'();/?:@&=+$,#", // encodeURI
  ALNUM + '-_.', // PHP urlencode, Java URLEncoder (each with + for space)
  ALNUM + '-_.!*()', // .NET WebUtility.UrlEncode / HttpUtility.UrlEncode
  '', // every byte escaped
];
const PCT_KEEP: Uint8Array[] = PCT_KEEP_SETS.map((set) => {
  const t = new Uint8Array(128);
  for (const ch of set) t[ch.charCodeAt(0)] = 1;
  return t;
});

function percentEncode(bytes: Buffer, keep: Uint8Array, spaceAsPlus: boolean): string {
  let out = '';
  for (const b of bytes) {
    if (b < 128 && keep[b]) out += String.fromCharCode(b);
    else if (b === 0x20 && spaceAsPlus) out += '+';
    else out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

function jsonEscape(value: string, escapeSlash: boolean, asciiOnly: boolean, html: boolean): string {
  let s = JSON.stringify(value).slice(1, -1);
  if (escapeSlash) s = s.replace(/\//g, '\\/');
  // Go encoding/json: HTML-safe escapes, and U+2028/U+2029
  if (html) s = s.replace(/[<>&\u2028\u2029]/g, uEscape);
  // per UTF-16 code unit, as Python's ensure_ascii (which also escapes DEL) and Java/Go escapers do
  if (asciiOnly) s = s.replace(/[^\x00-\x7e]/g, uEscape);
  return s;
}

function uEscape(c: string): string {
  return '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0');
}

/**
 * .NET System.Text.Json's default encoder: `"` and the HTML-sensitive / other ASCII characters
 * ``' + < > & ` `` as `\uXXXX`, and everything outside printable ASCII escaped.
 */
function jsonEscapeDotnet(value: string): string {
  return JSON.stringify(value)
    .slice(1, -1)
    .replace(/\\"/g, '\\u0022')
    .replace(/[^\x00-\x7e]|['+<>&`]/g, uEscape);
}

/** at most this many distinct ASCII punctuation characters get the exhaustive treatment */
const PCT_EXHAUSTIVE_MAX = 4;

/**
 * Every literal/escaped choice for each distinct ASCII non-alphanumeric character of the value
 * (space: literal, `%20` or `+`), so any percent-encoder with a consistent policy is covered whatever
 * its keep-set — when the value has few enough distinct punctuation characters for that to be cheap.
 */
function percentExhaustive(bytes: Buffer): string[] {
  const isAlnum = (b: number) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
  const punct = [...new Set([...bytes].filter((b) => b < 128 && !isAlnum(b)))];
  if (punct.length === 0 || punct.length > PCT_EXHAUSTIVE_MAX) return [];
  const results: string[] = [];
  const choice = new Map<number, number>(); // 0 literal, 1 %XX, 2 '+'
  const rec = (i: number): void => {
    if (i === punct.length) {
      let out = '';
      for (const b of bytes) {
        const c = b < 128 ? (isAlnum(b) ? 0 : choice.get(b)!) : 1;
        out += c === 0 ? String.fromCharCode(b) : c === 2 ? '+' : '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
      results.push(out);
      return;
    }
    const options = punct[i] === 0x20 ? 3 : 2;
    for (let c = 0; c < options; c++) {
      choice.set(punct[i]!, c);
      rec(i + 1);
    }
  };
  rec(0);
  return results;
}

/**
 * Stable core of base64(prefix(k) ++ bytes ++ suffix): the characters whose six bits fall entirely
 * inside `bytes`, so they are identical whatever bytes surround the value. `k` is the value's byte
 * offset modulo 3 inside the encoded blob.
 */
export function base64Core(bytes: Buffer, k: number): string {
  const blob = Buffer.concat([Buffer.alloc(k), bytes, Buffer.alloc(3)]);
  const s = blob.toString('base64');
  const first = Math.ceil((8 * k) / 6);
  const endExcl = Math.floor((8 * (k + bytes.length)) / 6);
  return s.slice(first, endExcl);
}

const toUrlSafe = (s: string) => s.replace(/\+/g, '-').replace(/\//g, '_');

/** Every encoded form of one value that the redactor looks for. May contain duplicates. */
export function encodingsOf(value: string): Buffer[] {
  const raw = utf8(value);
  const out: Buffer[] = [raw];

  // case variants (ASCII case is folded by the matcher; these matter for non-ASCII letters)
  out.push(utf8(value.toUpperCase()), utf8(value.toLowerCase()));

  // line-ending variants of multi-line values (PEM keys printed on Windows)
  if (value.includes('\n')) {
    out.push(utf8(value.replace(/\r?\n/g, '\r\n')), utf8(value.replace(/\r\n/g, '\n')));
  }

  // hex (case folded by the matcher, so lower covers upper)
  out.push(latin1(raw.toString('hex')));

  // percent-encoding (hex digits case folded, so %2F covers %2f)
  for (const keep of PCT_KEEP) {
    out.push(latin1(percentEncode(raw, keep, false)), latin1(percentEncode(raw, keep, true)));
  }
  for (const p of percentExhaustive(raw)) out.push(latin1(p));

  // JSON string escaping
  for (const slash of [false, true])
    for (const ascii of [false, true])
      for (const html of [false, true]) out.push(utf8(jsonEscape(value, slash, ascii, html)));
  out.push(utf8(jsonEscapeDotnet(value)));

  // UTF-16 (LE as Windows writes it; BE for completeness)
  const le = Buffer.from(value, 'utf16le');
  out.push(le, Buffer.from(le).swap16());

  // base64: the whole value encoded alone (padded / unpadded, standard / URL-safe) ...
  const std = raw.toString('base64');
  const stdBare = std.replace(/=+$/, '');
  out.push(latin1(std), latin1(stdBare), latin1(toUrlSafe(std)), latin1(toUrlSafe(stdBare)));
  // ... and the stable core at each of the three byte alignments inside a larger blob
  for (let k = 0; k < 3; k++) {
    const core = base64Core(raw, k);
    out.push(latin1(core), latin1(toUrlSafe(core)));
  }

  return out.filter((b) => b.length > 0);
}

/** All patterns for a secret list: each value, its derived sub-secrets, and all their encodings. */
export function buildPatterns(values: string[], minLength: number): Pattern[] {
  const patterns: Pattern[] = [];
  values.forEach((value, secret) => {
    for (const v of [value, ...deriveSubSecrets(value, minLength)]) {
      for (const bytes of encodingsOf(v)) patterns.push({ bytes, secret });
    }
  });
  return patterns;
}
