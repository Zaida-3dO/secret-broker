// Aho–Corasick over bytes, ASCII-case-insensitive.
//
// Bytes are mapped to equivalence classes first (every byte that appears in no pattern is class 0,
// and `A-Z` share a class with `a-z`), which keeps a dense transition row small. States get a dense,
// fully-resolved row (one array read per input byte) while the table fits `denseBudget` entries,
// in BFS order so the shallow states that ordinary text lives in are always dense. States past the
// budget — only reached by very long or very many secrets — fall back to a sparse child list plus
// the failure link, which is the textbook algorithm and amortised O(1) per byte.

import type { Pattern } from './patterns.js';

export const DEFAULT_DENSE_BUDGET = 4 * 1024 * 1024; // transition entries (Int32) => 16 MiB

const fold = (b: number) => (b >= 0x41 && b <= 0x5a ? b + 32 : b);

export class Automaton {
  /** byte -> class (0 = in no pattern) */
  readonly cls: Uint8Array;
  readonly classes: number;
  /** state -> offset of its dense row in `dense`, or -1 for a sparse state */
  readonly rowOf: Int32Array;
  readonly dense: Int32Array;
  readonly fail: Int32Array;
  readonly depth: Int32Array;
  /** state -> length of the longest pattern that is a suffix of the state's string (0 = none) */
  readonly matchLen: Int32Array;
  /** state -> secret index of that longest pattern */
  readonly matchSecret: Int32Array;
  readonly maxLen: number;
  // sparse children: linked list per state
  private readonly firstChild: Int32Array;
  private readonly nextSibling: Int32Array;
  private readonly edgeCls: Uint8Array;

  constructor(patterns: Pattern[], denseBudget = DEFAULT_DENSE_BUDGET) {
    // 1. byte classes
    const cls = new Uint8Array(256);
    let classes = 1;
    for (const p of patterns) for (const b of p.bytes) {
      const f = fold(b);
      if (cls[f] === 0) cls[f] = classes++;
    }
    for (let b = 0x41; b <= 0x5a; b++) cls[b] = cls[b + 32]!;
    this.cls = cls;
    this.classes = classes;

    // 2. trie (plain arrays while growing)
    const first: number[] = [-1];
    const next: number[] = [-1];
    const ecls: number[] = [0];
    const dep: number[] = [0];
    const term: number[] = [-1]; // secret index if a pattern ends here
    let maxLen = 0;
    for (const p of patterns) {
      let s = 0;
      for (const b of p.bytes) {
        const c = cls[b]!;
        let ch = first[s]!;
        while (ch !== -1 && ecls[ch] !== c) ch = next[ch]!;
        if (ch === -1) {
          ch = first.length;
          first.push(-1);
          next.push(first[s]!);
          ecls.push(c);
          dep.push(dep[s]! + 1);
          term.push(-1);
          first[s] = ch;
        }
        s = ch;
      }
      if (p.bytes.length > 0 && term[s] === -1) term[s] = p.secret;
      if (p.bytes.length > maxLen) maxLen = p.bytes.length;
    }
    const n = first.length;
    this.maxLen = maxLen;
    this.firstChild = Int32Array.from(first);
    this.nextSibling = Int32Array.from(next);
    this.edgeCls = Uint8Array.from(ecls);
    this.depth = Int32Array.from(dep);

    // 3. BFS: failure links, outputs, dense rows
    const fail = (this.fail = new Int32Array(n));
    const matchLen = (this.matchLen = new Int32Array(n));
    const matchSecret = (this.matchSecret = new Int32Array(n).fill(-1));
    const rowOf = (this.rowOf = new Int32Array(n).fill(-1));
    const maxRows = Math.max(1, Math.min(n, Math.floor(denseBudget / classes)));
    this.dense = new Int32Array(maxRows * classes);
    let rows = 0;

    const queue = new Int32Array(n);
    let head = 0;
    let tail = 0;
    queue[tail++] = 0;
    while (head < tail) {
      const s = queue[head++]!;
      // s's failure link and outputs were set when its parent was dequeued
      if (rows < maxRows) {
        const off = rows++ * classes;
        rowOf[s] = off;
        for (let c = 0; c < classes; c++) this.dense[off + c] = s === 0 ? 0 : this.step(fail[s]!, c);
        for (let ch = this.firstChild[s]!; ch !== -1; ch = this.nextSibling[ch]!) {
          this.dense[off + this.edgeCls[ch]!] = ch;
        }
      }
      for (let ch = this.firstChild[s]!; ch !== -1; ch = this.nextSibling[ch]!) {
        const f = s === 0 ? 0 : this.step(fail[s]!, this.edgeCls[ch]!);
        fail[ch] = f;
        if (term[ch]! >= 0) {
          matchLen[ch] = dep[ch]!;
          matchSecret[ch] = term[ch]!;
        } else {
          matchLen[ch] = matchLen[f]!;
          matchSecret[ch] = matchSecret[f]!;
        }
        queue[tail++] = ch;
      }
    }
  }

  /** transition from state `s` on class `c` */
  step(s: number, c: number): number {
    for (;;) {
      const off = this.rowOf[s]!;
      if (off >= 0) return this.dense[off + c]!;
      for (let ch = this.firstChild[s]!; ch !== -1; ch = this.nextSibling[ch]!) {
        if (this.edgeCls[ch] === c) return ch;
      }
      s = this.fail[s]!;
    }
  }

  /** number of states with a dense row (exposed for tests) */
  get denseStates(): number {
    let k = 0;
    for (const r of this.rowOf) if (r >= 0) k++;
    return k;
  }

  get states(): number {
    return this.depth.length;
  }
}
