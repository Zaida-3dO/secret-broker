// Bash-subset lexer for secret commands (design §3 "Sentinel substitution", §5 policy).
//
// Two jobs:
//   1. find every `{{secret:NAME}}` sentinel and the quote context it sits in, so `substitute()`
//      can rewrite it to an environment reference that bash expands to the value at run time;
//   2. extract every simple command (program + words + redirections) in the pipeline/list,
//      including those inside `$(...)`, backticks, `<(...)`, subshells and unquoted heredoc bodies,
//      so the policy can check each one.
//
// It is deliberately conservative: anything it cannot model with confidence (case, functions,
// `[[ ]]`, arrays, command substitution inside `${...}` or arithmetic …) is reported as a
// `problem`, and the policy denies a secret command that has any problem. A false deny is the
// safe direction; a missed command is not.

/** Sentinel grammar (design §3). */
export const SENTINEL_PREFIX = '{{secret:';
const SENTINEL_AT = /\{\{secret:([A-Za-z0-9_./-]{1,128})\}\}/y;

export type SentinelCtx =
  | 'unquoted'
  | 'double'
  | 'single'
  | 'ansi'
  | 'heredoc'
  | 'heredoc-quoted'
  | 'comment'
  | 'backtick'
  | 'arith'
  | 'param';

export interface Sentinel {
  name: string;
  start: number;
  end: number;
  ctx: SentinelCtx;
}

export interface Word {
  /** Source text of the word, quotes included. */
  raw: string;
  /** Quote-removed text. Sentinels are kept verbatim. Meaningful only when `static`. */
  text: string;
  /** False when the word contains a `$`-expansion, command substitution or backtick. */
  static: boolean;
  hasSentinel: boolean;
  quoted: boolean;
  start: number;
  end: number;
}

export interface Redirect {
  op: string;
  fd: string | null;
  target: Word | null;
}

export interface SimpleCommand {
  assigns: Word[];
  words: Word[];
  redirects: Redirect[];
  /** Set for pseudo-commands: `for` headers, `((…))`, closers like `done`/`fi`/`}`/`)`. */
  keyword: string | null;
}

export interface ParseResult {
  sentinels: Sentinel[];
  commands: SimpleCommand[];
  /** Constructs the lexer could not model. A secret command with any problem is denied. */
  problems: string[];
}

const META = new Set([' ', '\t', '\n', ';', '&', '|', '(', ')', '<', '>']);
const LIST_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '{', '!', 'time']);
const END_KEYWORDS = new Set(['fi', 'done', '}', 'esac']);
const UNSUPPORTED_KEYWORDS = new Set(['case', 'function', 'select', 'coproc', '[[', ']]', 'in']);
const REDIRECT_AT = /(\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(<<<|<<-|<<|<>|<&|>&|>>|>\||&>>|&>|<|>)/y;
const SEPARATORS = [';;&', ';;', ';&', '&&', '||', '|&', ';', '|', '&'];
const ARITH_PROBLEM = 'arithmetic ($((...)), ((...)), $[...]) is not supported in a secret command';
const ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/;

interface WordAcc {
  text: string;
  static: boolean;
  hasSentinel: boolean;
  quoted: boolean;
}

interface PendingHeredoc {
  delim: string;
  quoted: boolean;
  stripTabs: boolean;
}

function emptyCmd(): SimpleCommand {
  return { assigns: [], words: [], redirects: [], keyword: null };
}

function isEmpty(c: SimpleCommand): boolean {
  return c.assigns.length === 0 && c.words.length === 0 && c.redirects.length === 0 && c.keyword === null;
}

class Parser {
  readonly sentinels: Sentinel[] = [];
  readonly commands: SimpleCommand[] = [];
  readonly problems: string[] = [];
  private pending: PendingHeredoc[] = [];
  private readonly n: number;

  constructor(
    private readonly src: string,
    /** False for backtick sub-parsers: their sentinels are recorded (and refused) by the parent. */
    private readonly recordSentinels = true,
  ) {
    this.n = src.length;
  }

  problem(msg: string): void {
    if (!this.problems.includes(msg)) this.problems.push(msg);
  }

  /** Returns the sentinel at i, 'malformed' for a `{{secret:` that does not parse, or null. */
  sentinelAt(i: number): { name: string; end: number } | 'malformed' | null {
    if (!this.src.startsWith(SENTINEL_PREFIX, i)) return null;
    SENTINEL_AT.lastIndex = i;
    const m = SENTINEL_AT.exec(this.src);
    if (!m) return 'malformed';
    return { name: m[1], end: i + m[0].length };
  }

  /** If a sentinel (or malformed sentinel) starts at i, record it and return its end; else -1. */
  takeSentinel(i: number, ctx: SentinelCtx, acc?: WordAcc): number {
    const s = this.sentinelAt(i);
    if (s === null) return -1;
    if (s === 'malformed') {
      this.problem(
        'malformed {{secret:...}} sentinel — the form is {{secret:NAME}} with NAME made of letters, digits, _ . / - (max 128)',
      );
      if (acc) acc.text += SENTINEL_PREFIX;
      return i + SENTINEL_PREFIX.length;
    }
    if (this.recordSentinels) this.sentinels.push({ name: s.name, start: i, end: s.end, ctx });
    if (acc) {
      acc.text += this.src.slice(i, s.end);
      acc.hasSentinel = true;
    }
    return s.end;
  }

  /** Record every sentinel in [from, to) with a fixed context (single quotes, comments, …). */
  scanFlat(from: number, to: number, ctx: SentinelCtx): void {
    let i = this.src.indexOf(SENTINEL_PREFIX, from);
    while (i !== -1 && i < to) {
      const end = this.takeSentinel(i, ctx);
      i = this.src.indexOf(SENTINEL_PREFIX, end);
    }
  }

  parse(): ParseResult {
    const end = this.parseSeq(0, false);
    if (end < this.n) this.problem('unexpected trailing input');
    if (this.pending.length) this.pending = []; // heredoc with no body before EOF: bash warns, body empty
    return { sentinels: this.sentinels, commands: this.commands, problems: this.problems };
  }

  /**
   * Parse a command list. With `inParen`, stops after the matching `)` and returns the index
   * after it; otherwise runs to the end of input.
   */
  parseSeq(start: number, inParen: boolean): number {
    const src = this.src;
    let i = start;
    let cur = emptyCmd();
    const finish = () => {
      if (!isEmpty(cur)) this.commands.push(cur);
      cur = emptyCmd();
    };
    while (i < this.n) {
      const c = src[i];
      if (c === ' ' || c === '\t') {
        i++;
        continue;
      }
      if (c === '\\' && src[i + 1] === '\n') {
        i += 2;
        continue;
      }
      if (c === '\n') {
        finish();
        i = this.readHeredocs(i + 1);
        continue;
      }
      if (c === '#') {
        const nl = src.indexOf('\n', i);
        const end = nl === -1 ? this.n : nl;
        this.scanFlat(i, end, 'comment');
        i = end;
        continue;
      }
      if (c === ')') {
        if (inParen) {
          finish();
          return i + 1;
        }
        this.problem('unbalanced )');
        i++;
        continue;
      }
      if (c === '(') {
        if (isEmpty(cur)) {
          if (src[i + 1] === '(') {
            cur.keyword = '((';
            i = this.arith(i + 2);
            finish();
            continue;
          }
          finish();
          i = this.parseSeq(i + 1, true);
          cur.keyword = ')'; // redirects after a subshell attach here
          continue;
        }
        this.problem('( in the middle of a command (function definitions and arrays are not supported)');
        i++;
        continue;
      }
      // Redirection (checked before separators so `&>` is not read as `&`).
      const procSubst = (c === '<' || c === '>') && src[i + 1] === '(';
      if (!procSubst) {
        REDIRECT_AT.lastIndex = i;
        const rm = REDIRECT_AT.exec(src);
        if (rm) {
          const op = rm[2];
          const fd = rm[1] ?? null;
          let j = i + rm[0].length;
          while (src[j] === ' ' || src[j] === '\t') j++;
          const targetIsProcSubst = (src[j] === '<' || src[j] === '>') && src[j + 1] === '(';
          if (j >= this.n || (META.has(src[j]) && !targetIsProcSubst)) {
            this.problem(`redirection ${op} without a target`);
            cur.redirects.push({ op, fd, target: null });
            i = j;
            continue;
          }
          const w = this.readWord(j);
          if (op === '<<' || op === '<<-') {
            if (!w.static || w.hasSentinel) this.problem('heredoc delimiter must be a literal word');
            this.pending.push({ delim: w.text, quoted: w.quoted, stripTabs: op === '<<-' });
          }
          cur.redirects.push({ op, fd, target: w });
          i = w.end;
          continue;
        }
      }
      if (!procSubst) {
        const sep = SEPARATORS.find((s) => src.startsWith(s, i));
        if (sep) {
          if (sep.startsWith(';;') || sep === ';&') this.problem('case statements are not supported');
          finish();
          i += sep.length;
          continue;
        }
      }
      // A word.
      const w = this.readWord(i);
      i = w.end;
      if (cur.words.length === 0 && cur.assigns.length === 0 && !w.quoted && w.static) {
        if (cur.keyword === null || cur.keyword === ')') {
          if (LIST_KEYWORDS.has(w.text)) continue;
          if (END_KEYWORDS.has(w.text)) {
            finish();
            cur.keyword = w.text;
            continue;
          }
          if (w.text === 'for') {
            finish();
            cur.keyword = 'for';
            continue;
          }
          if (UNSUPPORTED_KEYWORDS.has(w.text)) {
            this.problem(`'${w.text}' is not supported in a secret command`);
            continue;
          }
        }
      }
      if (cur.keyword !== null && cur.keyword !== 'for' && cur.keyword !== '((') {
        // Words after `done`, `fi`, `}` or `)` — bash calls this a syntax error.
        this.problem(`unexpected word after '${cur.keyword}'`);
      }
      if (cur.words.length === 0 && cur.keyword === null && ASSIGN_RE.test(w.raw)) {
        cur.assigns.push(w);
      } else {
        cur.words.push(w);
      }
    }
    if (inParen) this.problem('unterminated ( or $(');
    finish();
    return this.n;
  }

  /** Read one shell word starting at i (i must not be a metacharacter, except `<(`/`>(`). */
  readWord(start: number): Word {
    const src = this.src;
    const acc: WordAcc = { text: '', static: true, hasSentinel: false, quoted: false };
    let unquoted = '';
    let i = start;
    while (i < this.n) {
      const c = src[i];
      if ((c === '<' || c === '>') && src[i + 1] === '(') {
        acc.static = false;
        i = this.parseSeq(i + 2, true);
        continue;
      }
      if (META.has(c)) break;
      if (c === '\\') {
        if (src[i + 1] === '\n') {
          i += 2;
          continue;
        }
        if (i + 1 < this.n) {
          acc.text += src[i + 1];
          acc.quoted = true;
          i += 2;
          continue;
        }
        acc.text += c;
        i++;
        continue;
      }
      if (c === "'") {
        const end = src.indexOf("'", i + 1);
        acc.quoted = true;
        if (end === -1) {
          this.problem('unterminated single quote');
          this.scanFlat(i + 1, this.n, 'single');
          acc.text += src.slice(i + 1);
          i = this.n;
          break;
        }
        this.scanFlat(i + 1, end, 'single');
        acc.text += src.slice(i + 1, end);
        if (src.slice(i + 1, end).includes(SENTINEL_PREFIX)) acc.hasSentinel = true;
        i = end + 1;
        continue;
      }
      if (c === '"') {
        acc.quoted = true;
        i = this.dquote(i + 1, acc);
        continue;
      }
      if (c === '$') {
        const nx = src[i + 1];
        if (nx === "'") {
          acc.quoted = true;
          i = this.ansi(i + 2, acc);
          continue;
        }
        if (nx === '"') {
          acc.quoted = true;
          i = this.dquote(i + 2, acc);
          continue;
        }
        const j = this.dollar(i, acc);
        if (j !== -1) {
          i = j;
          continue;
        }
        acc.text += '$';
        i++;
        continue;
      }
      if (c === '`') {
        acc.static = false;
        i = this.backtick(i + 1, false);
        continue;
      }
      const s = this.takeSentinel(i, 'unquoted', acc);
      if (s !== -1) {
        i = s;
        continue;
      }
      acc.text += c;
      unquoted += c;
      i++;
    }
    if (/\{[^{}]*(,|\.\.)[^{}]*\}/.test(unquoted)) {
      this.problem('brace expansion ({a,b} / {1..3}) is not supported');
    }
    return {
      raw: src.slice(start, i),
      text: acc.text,
      static: acc.static,
      hasSentinel: acc.hasSentinel,
      quoted: acc.quoted,
      start,
      end: i,
    };
  }

  /**
   * Handle a `$` expansion at i (`$(`, `$((`, `${`, `$name`, `$1`, `$@` …). Returns the index
   * after it, or -1 when the `$` is literal.
   */
  dollar(i: number, acc: WordAcc): number {
    const src = this.src;
    const nx = src[i + 1];
    if (nx === '(') {
      acc.static = false;
      if (src[i + 2] === '(') return this.arith(i + 3);
      return this.parseSeq(i + 2, true);
    }
    if (nx === '[') {
      acc.static = false;
      this.problem(ARITH_PROBLEM);
      const close = src.indexOf(']', i + 2);
      const end = close === -1 ? this.n : close;
      this.scanFlat(i + 2, end, 'arith');
      return close === -1 ? this.n : close + 1;
    }
    if (nx === '{') {
      acc.static = false;
      return this.param(i + 2);
    }
    if (nx !== undefined && /[A-Za-z_]/.test(nx)) {
      acc.static = false;
      let j = i + 2;
      while (j < this.n && /[A-Za-z0-9_]/.test(src[j])) j++;
      return j;
    }
    if (nx !== undefined && /[0-9@*#?$!-]/.test(nx)) {
      acc.static = false;
      return i + 2;
    }
    return -1;
  }

  /** Inside "…" starting after the opening quote. Returns index after the closing quote. */
  dquote(start: number, acc: WordAcc): number {
    const src = this.src;
    let i = start;
    while (i < this.n) {
      const c = src[i];
      if (c === '"') return i + 1;
      if (c === '\\') {
        const nx = src[i + 1];
        if (nx === '\n') {
          i += 2;
          continue;
        }
        if (nx === '$' || nx === '`' || nx === '"' || nx === '\\') {
          acc.text += nx;
          i += 2;
          continue;
        }
        if (src.startsWith(SENTINEL_PREFIX, i + 1)) {
          this.problem('a backslash directly before {{secret:...}} is ambiguous; remove it');
        }
        acc.text += c;
        i++;
        continue;
      }
      if (c === '$') {
        const j = this.dollar(i, acc);
        if (j !== -1) {
          i = j;
          continue;
        }
        acc.text += '$';
        i++;
        continue;
      }
      if (c === '`') {
        acc.static = false;
        i = this.backtick(i + 1, true);
        continue;
      }
      const s = this.takeSentinel(i, 'double', acc);
      if (s !== -1) {
        i = s;
        continue;
      }
      acc.text += c;
      i++;
    }
    this.problem('unterminated double quote');
    return this.n;
  }

  /** Inside $'…' (ANSI-C quoting) after the opening quote. */
  ansi(start: number, acc: WordAcc): number {
    const src = this.src;
    let i = start;
    while (i < this.n) {
      const c = src[i];
      if (c === "'") return i + 1;
      if (c === '\\') {
        // Escapes are decoded by bash; a decoded word is not a reliable literal.
        acc.static = false;
        acc.text += src.slice(i, i + 2);
        i += 2;
        continue;
      }
      const s = this.takeSentinel(i, 'ansi', acc);
      if (s !== -1) {
        i = s;
        continue;
      }
      acc.text += c;
      i++;
    }
    this.problem("unterminated $'...'");
    return this.n;
  }

  /** `${…}` after the `${`. Command substitution inside is refused; sentinels are refused. */
  param(start: number): number {
    const src = this.src;
    // `${a[i]}` and `${s:off}` evaluate arithmetic (see arith()).
    const head = /^[#!]?(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])(.)?(.)?/.exec(src.slice(start, start + 140));
    if (head && (head[1] === '[' || (head[1] === ':' && head[2] !== undefined && !'-=?+'.includes(head[2])))) {
      this.problem('array subscripts and substring offsets in ${...} are not supported in a secret command');
    }
    if (head && head[1] === '@') {
      // ${x@P}, ${x@E}, … re-expand or transform the variable's contents.
      this.problem('${...@op} transformations are not supported in a secret command');
    }
    let i = start;
    let depth = 1;
    let q: string | null = null;
    while (i < this.n) {
      const c = src[i];
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (src.startsWith(SENTINEL_PREFIX, i)) {
        const e = this.takeSentinel(i, 'param');
        i = e;
        continue;
      }
      if ((c === '$' && src[i + 1] === '(') || c === '`') {
        this.problem('command substitution inside ${...} is not supported');
      }
      if (q) {
        if (c === q) q = null;
        i++;
        continue;
      }
      if (c === "'" || c === '"') {
        q = c;
        i++;
        continue;
      }
      if (c === '{') depth++;
      if (c === '}') {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    this.problem('unterminated ${');
    return this.n;
  }

  /** Arithmetic `$((…))` / `((…))` after the opening `((`. */
  arith(start: number): number {
    const src = this.src;
    // Bash evaluates variable contents recursively in arithmetic, and an array subscript there can
    // run a command substitution hidden in a quoted string, so arithmetic is refused outright.
    this.problem(ARITH_PROBLEM);
    let i = start;
    let depth = 0;
    while (i < this.n) {
      const c = src[i];
      if (src.startsWith(SENTINEL_PREFIX, i)) {
        i = this.takeSentinel(i, 'arith');
        continue;
      }
      if ((c === '$' && src[i + 1] === '(') || c === '`') {
        this.problem('command substitution inside arithmetic is not supported');
      }
      if (c === '(') depth++;
      if (c === ')') {
        if (depth === 0) {
          if (src[i + 1] === ')') return i + 2;
          this.problem('unbalanced arithmetic expression');
          return i + 1;
        }
        depth--;
      }
      i++;
    }
    this.problem('unterminated arithmetic expression');
    return this.n;
  }

  /** Backtick substitution after the opening backtick. Sentinels inside are refused. */
  backtick(start: number, inDouble: boolean): number {
    const src = this.src;
    let i = start;
    while (i < this.n && src[i] !== '`') i += src[i] === '\\' ? 2 : 1;
    const end = Math.min(i, this.n);
    if (i >= this.n) this.problem('unterminated backtick');
    this.scanFlat(start, end, 'backtick');
    let body = src.slice(start, end).replace(/\\([\\`$])/g, '$1');
    if (inDouble) body = body.replace(/\\"/g, '"');
    const sub = new Parser(body, false).parse();
    this.commands.push(...sub.commands);
    for (const p of sub.problems) this.problem(p);
    return Math.min(end + 1, this.n);
  }

  /** At the start of the line after a newline token: read any pending heredoc bodies. */
  readHeredocs(start: number): number {
    if (!this.pending.length) return start;
    const docs = this.pending;
    this.pending = [];
    let i = start;
    for (const d of docs) {
      const bodyStart = i;
      let bodyEnd = this.n;
      let after = this.n;
      while (i < this.n) {
        const nl = this.src.indexOf('\n', i);
        const lineEnd = nl === -1 ? this.n : nl;
        let line = this.src.slice(i, lineEnd);
        if (d.stripTabs) line = line.replace(/^\t+/, '');
        if (line === d.delim) {
          bodyEnd = i;
          after = nl === -1 ? this.n : nl + 1;
          break;
        }
        i = nl === -1 ? this.n : nl + 1;
      }
      if (d.quoted) this.scanFlat(bodyStart, bodyEnd, 'heredoc-quoted');
      else this.heredocBody(bodyStart, bodyEnd);
      i = after;
    }
    return i;
  }

  /** Unquoted heredoc body: expansions and command substitutions are live. */
  heredocBody(start: number, end: number): void {
    const src = this.src;
    let i = start;
    const acc: WordAcc = { text: '', static: true, hasSentinel: false, quoted: false };
    while (i < end) {
      const c = src[i];
      if (c === '\\') {
        const nx = src[i + 1];
        if (nx === '$' || nx === '`' || nx === '\\' || nx === '\n') {
          i += 2;
          continue;
        }
        if (src.startsWith(SENTINEL_PREFIX, i + 1)) {
          this.problem('a backslash directly before {{secret:...}} is ambiguous; remove it');
        }
        i++;
        continue;
      }
      if (c === '$') {
        const j = this.dollar(i, acc);
        if (j !== -1) {
          if (j > end) this.problem('expansion runs past the end of a heredoc body');
          i = j;
          continue;
        }
        i++;
        continue;
      }
      if (c === '`') {
        i = this.backtick(i + 1, false);
        continue;
      }
      const s = this.takeSentinel(i, 'heredoc');
      if (s !== -1) {
        i = s;
        continue;
      }
      i++;
    }
  }
}

export function lex(command: string): ParseResult {
  return new Parser(command).parse();
}

/** Sentinel contexts that cannot be substituted safely; the command is refused. */
const REFUSED: Partial<Record<SentinelCtx, string>> = {
  'heredoc-quoted':
    "inside a quoted heredoc (<<'EOF' or <<\"EOF\") the shell would not expand it — use an unquoted <<EOF heredoc",
  backtick: 'inside `backticks` — use $(...) instead',
  arith: 'inside arithmetic $((...)) — not supported',
  param: 'inside ${...} — not supported',
};

export class SubstitutionError extends Error {}

export interface Substitution {
  /** The command with each sentinel replaced by a reference to `__SR_<i>`. */
  script: string;
  /** Distinct secret names in order of first appearance; `__SR_<i>` holds `names[i]`. */
  names: string[];
}

/** Distinct secret names a command uses (comments excluded). */
export function sentinelNames(parse: ParseResult): string[] {
  const names: string[] = [];
  for (const s of parse.sentinels) if (s.ctx !== 'comment' && !names.includes(s.name)) names.push(s.name);
  return names;
}

/**
 * Rewrite each sentinel by quote context (design §3):
 *   unquoted → "${__SR_i}"    double/unquoted heredoc → ${__SR_i}
 *   single   → '"${__SR_i}"'  $'…' → '"${__SR_i}"$'
 * Sentinels in comments are left untouched. Throws SubstitutionError (naming the secret, never
 * a value) for contexts that cannot be substituted.
 */
export function substitute(command: string, parse: ParseResult = lex(command)): Substitution {
  const names = sentinelNames(parse);
  const sorted = [...parse.sentinels].sort((a, b) => a.start - b.start);
  let out = '';
  let pos = 0;
  for (const s of sorted) {
    if (s.ctx === 'comment') continue;
    const why = REFUSED[s.ctx];
    if (why) throw new SubstitutionError(`{{secret:${s.name}}} is ${why}.`);
    const ref = `__SR_${names.indexOf(s.name)}`;
    let rep: string;
    switch (s.ctx) {
      case 'unquoted':
        rep = `"\${${ref}}"`;
        break;
      case 'double':
      case 'heredoc':
        rep = `\${${ref}}`;
        break;
      case 'single':
        rep = `'"\${${ref}}"'`;
        break;
      case 'ansi':
        rep = `'"\${${ref}}"$'`;
        break;
      default:
        throw new SubstitutionError(`{{secret:${s.name}}} is in an unsupported position.`);
    }
    out += command.slice(pos, s.start) + rep;
    pos = s.end;
  }
  out += command.slice(pos);
  return { script: out, names };
}

/** Last path component, lower-cased, `.exe` stripped — for matching program names. */
export function programBase(word: string): string {
  const b = word.split(/[\\/]/).pop() ?? word;
  return b.toLowerCase().replace(/\.exe$/, '');
}
