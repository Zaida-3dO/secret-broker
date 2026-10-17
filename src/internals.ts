// Broker internals an agent must never read: the bootstrap machine credentials written by
// the identity bootstrap script, the ticket store, and the dev FileBackend's JSON. Like the
// `.env` guard this is a speed bump (design §1): it catches a path the agent names, not a script
// that finds the file by itself.
import * as os from 'node:os';
import * as path from 'node:path';
import { loadConfig } from './backend/index.js';
import { stateDir } from './paths.js';

export interface InternalPaths {
  /** Normalised directories whose contents are off limits. */
  dirs: string[];
  /** Normalised individual files. */
  files: string[];
}

/** Lower-case, forward slashes, `/c/…` → `c:/…`, no duplicate or trailing slashes. */
export function normPath(p: string): string {
  let s = p.replace(/\\/g, '/').toLowerCase();
  s = s.replace(/(^|[\s'"=:(<>|;&`])\/([a-z])\//g, (_m, pre: string, d: string) => `${pre}${d}:/`);
  return s.replace(/\/{2,}/g, '/').replace(/\/$/, '');
}

export function internalPaths(): InternalPaths {
  const bases = new Set([stateDir()]);
  const local = process.env.LOCALAPPDATA ?? path.join(os.homedir(), '.local', 'state');
  bases.add(path.join(local, 'secret-broker'));
  const dirs: string[] = [];
  for (const b of bases) dirs.push(normPath(path.join(b, 'bootstrap')), normPath(path.join(b, 'tickets')));
  const files: string[] = [];
  try {
    const cfg = loadConfig();
    if (cfg.backend === 'file' && typeof cfg.file === 'string') files.push(normPath(path.resolve(cfg.file)));
  } catch {
    /* not configured: nothing more to protect */
  }
  return { dirs, files };
}

const GENERIC = /secret-broker\/(bootstrap|tickets)(\/|$|[^a-z0-9_.-])/;

/**
 * The internal path `text` refers to, or null. `cwd` lets a bare file name in the store's own
 * directory count too.
 */
export function internalRef(text: string, paths: InternalPaths, cwd?: string): string | null {
  const t = normPath(text);
  for (const d of paths.dirs) if (t.includes(d)) return d;
  const g = GENERIC.exec(t);
  if (g) return `secret-broker/${g[1]}`;
  for (const f of paths.files) {
    if (t.includes(f)) return f;
    const base = f.split('/').pop()!;
    const parent = f.split('/').slice(-2).join('/');
    if (t.includes(parent)) return f;
    if (cwd && normPath(cwd) === f.slice(0, f.length - base.length - 1) && new RegExp(`(^|[^a-z0-9_.-])${escapeRe(base)}($|[^a-z0-9_.-])`).test(t)) {
      return f;
    }
  }
  return null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function internalDeny(ref: string, display: string): string {
  return (
    `${ref} is a secret-broker internal (machine credentials, single-use tickets or the dev secret store); ` +
    'agents must not read or list it. Use secrets by name instead — write {{secret:NAME}} in a Bash command — ' +
    `and run \`${display} list\` to see the names available.`
  );
}
