// Streaming multi-encoding redactor (design §6). See README.md in this directory for what is and is
// not covered. The exported signature is the contract other modules build against.
import type { Redactor, SecretValue } from '../types.js';
import { Automaton, DEFAULT_DENSE_BUDGET } from './automaton.js';
import { buildPatterns, charLength } from './patterns.js';

export interface RedactorOptions {
  /** minimum secret length in characters (code points); shorter secrets throw. Default 8. */
  minLength?: number;
  /**
   * Cap on the dense transition table, in entries (4 bytes each). States beyond it use a slower
   * sparse lookup. Default 4Mi entries (16 MiB). Exposed mainly so tests can exercise both paths.
   */
  denseBudget?: number;
}

interface Region {
  start: number; // absolute stream offsets, [start, end)
  end: number;
  len: number; // length of the longest match merged into this region
  secret: number;
}

const EMPTY = Buffer.alloc(0);
/** span beyond which an open match region is closed early (see emit) */
const REGION_CAP = 1024 * 1024;

/** Index at which to cut `buf` at or before `idx` so no UTF-8 sequence is split. Never below `floor`. */
function utf8SafeCut(buf: Buffer, idx: number, floor: number): number {
  for (let j = 1; j <= 3 && idx - j >= floor; j++) {
    const b = buf[idx - j]!;
    if ((b & 0xc0) === 0x80) continue; // continuation byte: keep looking for the lead
    if ((b & 0xc0) === 0xc0) {
      const seqLen = b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : 2;
      if (j < seqLen) return idx - j; // the sequence starting there is not complete before idx
    }
    break; // ASCII, or a lead whose sequence is complete
  }
  return idx;
}

export function createRedactor(secrets: SecretValue[], opts: RedactorOptions = {}): Redactor {
  const min = opts.minLength ?? 8;
  for (const s of secrets) {
    if (typeof s.value !== 'string' || charLength(s.value) < min) {
      throw new Error(`secret ${s.name} is shorter than ${min} characters; refusing`);
    }
  }
  const labels = secrets.map((s) => Buffer.from(`[secret:${s.name}]`, 'utf8'));
  const patterns = buildPatterns(
    secrets.map((s) => s.value),
    min,
  );
  if (patterns.length === 0) {
    return { push: (chunk) => Buffer.from(chunk), flush: () => EMPTY };
  }
  const ac = new Automaton(patterns, opts.denseBudget ?? DEFAULT_DENSE_BUDGET);
  const { cls, rowOf, dense, matchLen, matchSecret, depth } = ac;

  let state = 0;
  let scanned = 0; // bytes scanned so far (absolute)
  let emitted = 0; // bytes consumed into output so far (absolute) == offset of pending[0]
  let pending: Buffer = EMPTY;
  // disjoint, ordered, not yet emitted match regions; overlapping matches are merged
  const regions: Region[] = [];

  function onMatch(end: number, len: number, secret: number): void {
    // a match that began in bytes already emitted (after an idle flush() or an early close of a long
    // region) is clipped to what remains
    const start = Math.max(end - len, emitted);
    // matches arrive in order of end offset, so a new one can only overlap trailing regions
    const last = regions.length > 0 ? regions[regions.length - 1]! : undefined;
    if (last === undefined || last.end <= start) {
      regions.push({ start, end, len, secret });
      return;
    }
    // merge into the last region in place (hot path for self-overlapping secrets: no allocation)
    last.end = end;
    if (len > last.len) {
      // ties keep the earlier match's label
      last.len = len;
      last.secret = secret;
    }
    if (start < last.start) {
      last.start = start;
      // the new match may also reach back over earlier regions: absorb them
      while (regions.length > 1 && regions[regions.length - 2]!.end > last.start) {
        const r = regions.splice(regions.length - 2, 1)[0]!;
        if (r.start < last.start) last.start = r.start;
        if (r.len >= last.len) {
          last.len = r.len;
          last.secret = r.secret;
        }
      }
    }
  }

  function scan(chunk: Buffer): void {
    const base = scanned;
    let s = state;
    for (let i = 0; i < chunk.length; i++) {
      const c = cls[chunk[i]!]!;
      const off = rowOf[s]!;
      s = off >= 0 ? dense[off + c]! : ac.step(s, c);
      const ml = matchLen[s]!;
      if (ml !== 0) onMatch(base + i + 1, ml, matchSecret[s]!);
    }
    state = s;
    scanned = base + chunk.length;
  }

  /**
   * Emit everything that can no longer be touched by a future match. `final` emits all of it
   * (flush); otherwise output stops at the hold-back boundary, moved back to a UTF-8 boundary.
   */
  function emit(final: boolean): Buffer {
    // No future match can start before `safe`: the bytes after it are the longest suffix of the
    // stream that is still a prefix of some pattern (the automaton state's depth, <= maxLen - 1
    // once a match is complete and the next byte is seen).
    const safe = final ? scanned : Math.max(emitted, scanned - depth[state]!);
    // A chain of overlapping matches (a secret that repeats itself, e.g. `abab…` in `abababab…`) keeps
    // its region open indefinitely. Once a region spans more than REGION_CAP bytes it is closed
    // early: its label goes out now, and a later match overlapping it is clipped to the bytes not yet
    // emitted and gets a label of its own (onMatch), so nothing leaks and the hold-back stays bounded.
    const parts: Buffer[] = [];
    let pos = emitted;
    let i = 0;
    for (; i < regions.length; i++) {
      const r = regions[i]!;
      if (r.end > safe && scanned - r.start <= REGION_CAP) break; // a later match could still overlap it and extend it
      if (r.start > pos) parts.push(pending.subarray(pos - emitted, r.start - emitted));
      parts.push(labels[r.secret]!);
      pos = r.end;
    }
    regions.splice(0, i);
    let limit = safe;
    if (regions.length > 0 && regions[0]!.start < limit) limit = regions[0]!.start;
    if (!final) limit = emitted + utf8SafeCut(pending, limit - emitted, pos - emitted);
    if (limit > pos) parts.push(pending.subarray(pos - emitted, limit - emitted));
    else limit = pos;
    const out = parts.length === 0 ? EMPTY : Buffer.concat(parts);
    // keep a private copy of the held-back bytes: the caller may reuse its chunk buffer
    pending = limit - emitted < pending.length ? Buffer.from(pending.subarray(limit - emitted)) : EMPTY;
    emitted = limit;
    return out;
  }

  return {
    push(chunk: Buffer): Buffer {
      if (chunk.length === 0) return EMPTY;
      scan(chunk);
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
      return emit(false);
    },
    flush(): Buffer {
      // The automaton state is deliberately kept: if more output follows an idle flush, a secret
      // that straddles it still has its unflushed remainder redacted.
      return emit(true);
    },
  };
}
