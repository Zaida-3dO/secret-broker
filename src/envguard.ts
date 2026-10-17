// `.env` guard: deny tool calls that would read a dotenv file into the transcript. A speed bump —
// `grep -r . .` or a script that opens the file itself is not caught (design §1).
import { lex, programBase, type ParseResult } from './lex.js';

const BOUNDARY = `\\s"'\`=:,;(|&<>@`;
const ENV_RE = new RegExp(
  `(?:^|[${BOUNDARY}])((?:[^${BOUNDARY}]*[\\\\/])?(\\.env[\\w.-]*|[\\w.-]+\\.env\\.bak[\\w.-]*))(?=$|[^\\w.-])`,
  'gi',
);
const TEMPLATE_RE = /\.(example|sample|template)$/i;

/** Dotenv-looking paths mentioned in `text` (templates such as `.env.example` excluded). */
export function findEnvRefs(text: string): string[] {
  const out: string[] = [];
  ENV_RE.lastIndex = 0;
  for (let m = ENV_RE.exec(text); m; m = ENV_RE.exec(text)) {
    const base = m[2];
    if (!TEMPLATE_RE.test(base)) out.push(m[1]);
    if (m[0].length === 0) ENV_RE.lastIndex++;
  }
  return out;
}

/** Programs that may name a dotenv file without reading it. */
const NON_READING = new Set(['ls', 'rm', 'mv', 'touch', 'chmod', 'stat', 'test', '[', 'echo', 'printf', 'mkdir']);
const GIT_NON_READING = new Set(['check-ignore', 'status', 'ls-files', 'rm', 'mv']);

/** The first dotenv path a Bash command would read, or null. */
export function bashEnvRead(command: string, parse: ParseResult = lex(command)): string | null {
  if (parse.problems.length) return findEnvRefs(command)[0] ?? null;
  for (const cmd of parse.commands) {
    for (const r of cmd.redirects) {
      if ((r.op === '<' || r.op === '<>') && r.target) {
        const hit = findEnvRefs(r.target.text)[0];
        if (hit) return hit;
      }
    }
    if (cmd.words.length === 0) continue;
    const prog = cmd.words[0];
    if (prog.static) {
      const base = programBase(prog.text);
      if (NON_READING.has(base)) continue;
      if (base === 'git') {
        const sub = cmd.words.slice(1).find((w) => !w.text.startsWith('-'));
        if (sub && GIT_NON_READING.has(sub.text)) continue;
      }
    }
    for (const w of [...cmd.assigns, ...cmd.words]) {
      const hit = findEnvRefs(w.text)[0];
      if (hit) return hit;
    }
  }
  return null;
}

/** For tools that take a path (Read, Grep): the dotenv path they target, or null. */
export function pathEnvRead(toolInput: Record<string, unknown>): string | null {
  for (const key of ['file_path', 'path', 'glob', 'notebook_path']) {
    const v = toolInput[key];
    if (typeof v !== 'string') continue;
    const hit = findEnvRefs(v)[0];
    if (hit) return hit;
  }
  return null;
}
