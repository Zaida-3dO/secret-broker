import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ENCODERS, embeddedBase64, redactOnce, rng, randomBytes, countOf } from './helpers.js';

const VALUES: Record<string, string> = {
  ASCII_SPECIALS: 'DUMMY-SECRET-3f9a/b+c=d "q" \\ <x>&é~*\'(!)',
  UNICODE: 'DUMMY-SECRET-ключ-秘密-🔑-0b1c',
  MULTILINE: 'DUMMY-SECRET-line1\nline2\tTAB-0a0b',
  SPACES: 'DUMMY SECRET 9c8d e7f6?a=1&b=2#frag',
};

for (const [name, value] of Object.entries(VALUES)) {
  for (const e of ENCODERS) {
    test(`${e.name} of ${name} is replaced with [secret:${name}]`, () => {
      const enc = e.enc(value);
      const input = Buffer.concat([Buffer.from('pre<'), enc, Buffer.from('>post\n')]);
      const out = redactOnce([{ name, value }], input).toString('utf8');
      assert.equal(out, `pre<[secret:${name}]>post\n`);
    });
  }

  test(`base64 of ${name} embedded at every byte alignment, standard and URL-safe`, () => {
    const r = rng(0xb64);
    for (let pre = 0; pre <= 5; pre++) {
      for (let post = 0; post <= 4; post++) {
        for (const urlSafe of [false, true]) {
          const { b64, core } = embeddedBase64(value, randomBytes(r, pre), randomBytes(r, post), urlSafe);
          assert.ok(core.length >= 8, 'core is long enough to mean something');
          const out = redactOnce([{ name, value }], `Authorization: Basic ${b64}\n`).toString('utf8');
          assert.equal(countOf(out, core), 0, `core leaked (pre=${pre} post=${post} url=${urlSafe}): ${out}`);
          assert.equal(countOf(out, `[secret:${name}]`), 1, out);
        }
      }
    }
  });
}

test('mixed ASCII case of the value is caught (matching folds ASCII case)', () => {
  const value = 'DUMMY-SECRET-abcdef0123';
  const out = redactOnce([{ name: 'S', value }], 'x dUmMy-SeCrEt-AbCdEf0123 y').toString();
  assert.equal(out, 'x [secret:S] y');
});

test('mixed-case hex digits inside one percent-encoded value are caught', () => {
  const value = 'DUMMY/SECRET/0a1b';
  const out = redactOnce([{ name: 'S', value }], 'q=DUMMY%2fSECRET%2F0a1b&').toString();
  assert.equal(out, 'q=[secret:S]&');
});

test('CRLF form of a multi-line value is caught', () => {
  const value = 'DUMMY-SECRET-l1\nl2\nl3-ffee';
  const out = redactOnce([{ name: 'K', value }], 'a\r\nDUMMY-SECRET-l1\r\nl2\r\nl3-ffee\r\nb').toString();
  assert.equal(out, 'a\r\n[secret:K]\r\nb');
});

test('UTF-16BE of the value is caught', () => {
  const value = 'DUMMY-SECRET-be16-7788';
  const be = Buffer.from(value, 'utf16le').swap16();
  const out = redactOnce([{ name: 'S', value }], Buffer.concat([Buffer.from([0xfe, 0xff]), be]));
  assert.deepEqual(out, Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from('[secret:S]')]));
});

test('JSON with HTML-safe escapes (Go encoding/json) is caught', () => {
  const value = 'DUMMY-SECRET-<a>&b-1234';
  const go = 'DUMMY-SECRET-\\u003ca\\u003e\\u0026b-1234';
  assert.equal(redactOnce([{ name: 'S', value }], `{"t":"${go}"}`).toString(), '{"t":"[secret:S]"}');
});

test('derived sub-secret: the password of a URL with userinfo, raw and URL-decoded', () => {
  const value = 'postgres://dummy-user:DUMMY-PW-%2Fx9y8z7@db.example.invalid:5432/app';
  const secrets = [{ name: 'DB_URL', value }];
  const cases: Array<[string, string]> = [
    [value, '[secret:DB_URL]'],
    ['pw=DUMMY-PW-%2Fx9y8z7;', 'pw=[secret:DB_URL];'],
    ['pw=DUMMY-PW-/x9y8z7;', 'pw=[secret:DB_URL];'],
    // the decoded password, base64-encoded (it is a secret in its own right)
    [`p=${Buffer.from('DUMMY-PW-/x9y8z7').toString('base64')}`, 'p=[secret:DB_URL]'],
    // hex of the decoded password
    [`p=${Buffer.from('DUMMY-PW-/x9y8z7').toString('hex')}`, 'p=[secret:DB_URL]'],
  ];
  for (const [input, expected] of cases) assert.equal(redactOnce(secrets, input).toString(), expected, input);

  // HTTP Basic auth built from the URL's userinfo: base64("dummy-user:<decoded pw>")
  const basic = Buffer.from('dummy-user:DUMMY-PW-/x9y8z7').toString('base64');
  const out = redactOnce(secrets, `Authorization: Basic ${basic}`).toString();
  const { core } = embeddedBase64('DUMMY-PW-/x9y8z7', Buffer.from('dummy-user:'), Buffer.alloc(0), false);
  assert.equal(countOf(out, core), 0, out);
  assert.match(out, /\[secret:DB_URL\]/);
});

test('derived password with an unencoded @ keeps everything up to the last @', () => {
  const value = 'https://u:DUMMY@PW-55aa66@host.invalid/';
  assert.equal(redactOnce([{ name: 'U', value }], 'pw DUMMY@PW-55aa66 end').toString(), 'pw [secret:U] end');
});

test('derived password shorter than minLength is not redacted on its own', () => {
  const value = 'https://user:short@host.invalid/DUMMY-SECRET-path';
  const out = redactOnce([{ name: 'U', value }], 'the word short stays').toString();
  assert.equal(out, 'the word short stays');
});

test('a URL without userinfo derives nothing', () => {
  const value = 'https://host.invalid/DUMMY-SECRET-token-0011';
  assert.equal(redactOnce([{ name: 'U', value }], 'host.invalid stays').toString(), 'host.invalid stays');
});

test('percent-encoding with ANY consistent keep-set, for values with few distinct punctuation chars', () => {
  // 3 distinct punctuation characters, one of them space: 2 * 2 * 3 = 12 encoder policies
  const value = 'DUMMY/SECRET~a1 b2/c3~d4';
  const secrets = [{ name: 'P', value }];
  let n = 0;
  for (const slash of [false, true])
    for (const tilde of [false, true])
      for (const space of ['lit', 'pct', 'plus'] as const) {
        const enc = [...value]
          .map((c) =>
            c === '/' ? (slash ? '/' : '%2F') : c === '~' ? (tilde ? '~' : '%7E') : c === ' ' ? (space === 'lit' ? ' ' : space === 'pct' ? '%20' : '+') : c,
          )
          .join('');
        assert.equal(redactOnce(secrets, `[${enc}]`).toString(), '[[secret:P]]', enc);
        n++;
      }
  assert.equal(n, 12);
});

test('reviewer repro: .NET and PHP URL-encoding of a value with ~ and ! * ( ) \'', () => {
  const v1 = 'DUMMY-SECRET-!~ab12cd';
  assert.equal(redactOnce([{ name: 'S', value: v1 }], 'DUMMY-SECRET-!%7Eab12cd').toString(), '[secret:S]');
  const v2 = 'DUMMY-SECRET-*~ab12cd';
  assert.equal(redactOnce([{ name: 'S', value: v2 }], 'DUMMY-SECRET-%2A%7Eab12cd').toString(), '[secret:S]');
});

test('JSON: Go escapes U+2028/U+2029 but leaves other non-ASCII raw; Python ensure_ascii escapes DEL', () => {
  const go = 'DUMMY-SECRET-é\u2028-\u2029-ab';
  assert.equal(redactOnce([{ name: 'S', value: go }], '"DUMMY-SECRET-é\\u2028-\\u2029-ab"').toString(), '"[secret:S]"');
  // '+' stays raw in Python's output (unlike .NET's), so only the ensure_ascii variant can match
  const del = 'DUMMY-SECRET-\x7f-é+ab';
  assert.equal(redactOnce([{ name: 'S', value: del }], '"DUMMY-SECRET-\\u007f-\\u00e9+ab"').toString(), '"[secret:S]"');
});

test('derived password containing raw / ? # or space (unescaped in the URL)', () => {
  for (const pw of ['DUMMY-PW/abc123', 'DUMMY-PW?abc123', 'DUMMY-PW#abc123', 'DUMMY PW abc123']) {
    const value = `postgres://user:${pw}@db.invalid/app`;
    const out = redactOnce([{ name: 'DB', value }], `pw=<${pw}>`).toString();
    assert.equal(out, 'pw=<[secret:DB]>', pw);
  }
  // a path containing @ after a real password does not stop the real password being derived
  const value = 'https://u:DUMMY-PW-77aa88@host.invalid/a@b';
  assert.equal(redactOnce([{ name: 'U', value }], '<DUMMY-PW-77aa88>').toString(), '<[secret:U]>');
});

test('derived token from token-only userinfo (https://TOKEN@host)', () => {
  const value = 'https://DUMMY-TOKEN-0123456789abcdef@git.example.invalid/org/repo.git';
  const out = redactOnce([{ name: 'GIT', value }], 'Authorization: token DUMMY-TOKEN-0123456789abcdef').toString();
  assert.equal(out, 'Authorization: token [secret:GIT]');
  // a short username is not treated as a secret
  const v2 = 'ssh://git@github.example.invalid/DUMMY-SECRET-repo-path';
  assert.equal(redactOnce([{ name: 'X', value: v2 }], 'user git logged in').toString(), 'user git logged in');
});
