# `src/redact` — streaming redactor

Implements design §6. `createRedactor(secrets, opts?)` returns `{ push(chunk): Buffer, flush(): Buffer }`;
every occurrence of a secret, in any of the encodings below, comes out as `[secret:NAME]`.

**Redaction is a backstop, not the control** (design §1, §3 rule 7). It catches a value that ends up
in output *by accident*. It does not, and cannot, stop a process that wants the value out.

## What is matched

For each secret value, and for each sub-secret derived from it:

| Form | Notes |
|---|---|
| exact UTF-8 bytes | |
| case variants | ASCII matching is **case-insensitive** throughout (so mixed case is caught too); `toUpperCase()`/`toLowerCase()` patterns cover non-ASCII letters |
| CRLF / LF | for multi-line values (PEM blocks printed on Windows) |
| hex | lower, upper, mixed (case-folded) |
| percent-encoding | seven encoder conventions — `encodeURIComponent`, RFC 3986 strict, Python `quote` (`/` safe), WHATWG form (`URLSearchParams`), `encodeURI`, PHP `urlencode` / Java `URLEncoder`, .NET `UrlEncode` — plus every byte escaped; each with `%20` and with `+` for space. When a value has at most 4 distinct ASCII punctuation characters, **every** consistent literal-or-escaped policy is generated too, so any encoder is covered. Hex digits case-folded (`%2F` = `%2f`) |
| JSON string escaping | `JSON.stringify` body, plus `\/`, `\uXXXX` for non-ASCII and DEL (Python `ensure_ascii`), and Go's `< > &` and U+2028/U+2029 — all 8 combinations; plus .NET `System.Text.Json`'s default encoder (`"` `'` `+` `<` `>` `&` and backtick, and all non-ASCII, as `\uXXXX`) |
| UTF-16 | LE (Windows) and BE |
| base64 | standard and URL-safe; the value encoded alone, padded and unpadded; **and** the stable core at all three byte alignments, so the value is caught inside a larger encoded blob (`Basic base64(user:pw)`, a base64'd JSON document). The 1–2 characters at each edge of the core also carry bits of the neighbouring bytes and are left in place |
| derived sub-secrets | for every `scheme://user:pw@host` URL inside a value: `pw` raw, and URL-decoded (with and without `+`→space), when at least `minLength` characters; each gets every encoding above. An unescaped password may contain `/ ? # @` or spaces, so every `@` after the user's colon ends a candidate (up to 4). For `scheme://token@host` (no colon) the token is derived |

## Semantics

- **Length check.** A secret shorter than `minLength` (default 8, counted in code points) throws, naming
  the secret and never its value.
- **Overlaps.** Overlapping matches (of one secret or several) are merged into one region, so no byte
  of either leaks; the region is labelled with the **longest** match in it (ties: the earliest).
  Touching but non-overlapping matches get one label each. A chain of overlapping matches spanning
  more than 1 MiB (only a self-repeating secret such as `abab…` inside `ababab…` produces one) is
  closed early so output keeps flowing; the rest of the chain gets its own label and no byte leaks.
- **Streaming.** The automaton state persists across `push` calls, so a value split at any chunk
  boundary is caught. Hold-back is exact rather than a fixed window: only the bytes that are still a
  prefix of some pattern (the Aho–Corasick state depth, at most `maxPatternLen - 1`) plus any
  not-yet-final match are held. Output is never cut inside a multi-byte UTF-8 sequence (up to 3
  extra bytes are held); non-UTF-8 bytes pass through unchanged.
- **`flush()`** emits everything held back — call it on idle (~100 ms) and at exit. The automaton
  state is kept: if output resumes and a secret was straddling the flush, the part *after* the flush
  is still redacted (the part before it has already gone out — see non-goals). Because `flush()`
  emits *everything*, its output can end inside a UTF-8 sequence if the producer paused mid-character;
  `push()` output never does.
- **Performance.** Aho–Corasick over byte classes, with fully-resolved dense rows for as many states
  as fit `denseBudget` (default 4 Mi entries, 16 MiB) and a sparse fallback beyond that. ~0.5–0.8 s for
  50 MB with 20 secrets on the dev PC (see `test/redact/bench.test.ts`).
- No dependencies.

## Known non-goals

These pass through unredacted. They are the "deliberate act" class from design §1 — or rare enough
that the cost of covering them is not worth it for a backstop:

- **Arbitrary transforms**: `tr`, `rev`, `sed s/./&-/g`, ROT13, character-by-character interleaving,
  printing the value one character per line, reversing, XOR.
- **Compression / encryption**: gzip, zip, `openssl enc`, anything whose bytes do not contain an
  encoding listed above.
- **Partial disclosure**: `head -c 10`, `cut`, a substring of a value, a long value (PEM key) printed
  only in part. Only whole-value matches are redacted (plus derived sub-secrets).
- **Nested / mixed encodings**: base64 of the hex, percent-encoding of the base64, a JSON-escaped
  percent-encoding, double percent-encoding, a percent-encoding that mixes conventions within one
  value (escaping `/` in one place but not another), and an encoder convention not listed above
  applied to a value with more than 4 distinct punctuation characters.
- **Wrapped encodings**: base64 with line breaks inside the value's span (MIME 76-column, PEM
  bodies), hex with separators (`xxd`, `od`, `aa:bb:cc`), JSON `\u`-escaping of ASCII characters
  beyond the Go and .NET sets above.
- **Derived sub-secrets beyond URL userinfo**: query-string tokens (`?token=…`), `key=value`
  connection strings, JWT segments. Name each as its own secret if it matters.
- **Other character sets**: UTF-32, Latin-1/CP-1252 transcoding of non-ASCII values, Unicode
  normalisation (NFC vs NFD), and mixed case of *non-ASCII* letters (all-upper and all-lower are covered).
- **Secrets split by an idle `flush()`**: bytes emitted by a flush before the rest of the value arrived
  are already out. The caller schedules flush on idle, so this needs a process that pauses mid-value.
- **Base64 edge characters**: the 1–2 characters at each end of an embedded value's base64 span, which
  mix in bits of neighbouring bytes, are not removed.
