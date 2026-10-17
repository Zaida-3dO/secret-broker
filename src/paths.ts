// Locations and small path helpers. No heavy imports: the hook loads this on its slow path.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Forward-slash Windows form (`C:/…`) — the one spelling the hook emits (design §3 rule 1). */
export function fwd(p: string): string {
  return p.replace(/\\/g, '/');
}

/** `%APPDATA%\secret-broker\config.json`, or `SECRETRUN_CONFIG`. */
export function configPath(): string {
  if (process.env.SECRETRUN_CONFIG) return process.env.SECRETRUN_CONFIG;
  const base = process.env.APPDATA ?? path.join(os.homedir(), '.config');
  return path.join(base, 'secret-broker', 'config.json');
}

/** `%LOCALAPPDATA%\secret-broker` (tickets + audit), or `SECRETRUN_STATE_DIR`. */
export function stateDir(): string {
  if (process.env.SECRETRUN_STATE_DIR) return process.env.SECRETRUN_STATE_DIR;
  const base = process.env.LOCALAPPDATA ?? path.join(os.homedir(), '.local', 'state');
  return path.join(base, 'secret-broker');
}

/** dist/ directory of this install (where cli.js and hook.js live). */
export function distDir(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

export function cliPath(): string {
  return path.join(distDir(), 'cli.js');
}

export function hookPath(): string {
  return path.join(distDir(), 'hook.js');
}

/**
 * The exact command prefix the hook emits to run secretrun: absolute node + absolute cli.js,
 * with MSYS path conversion off so Git Bash hands the original command to node byte-for-byte
 * (without it, an argument such as `/usr/bin/true` is rewritten to `C:/Program Files/Git/...`
 * and the ticket's command hash no longer matches).
 */
export function secretrunInvocation(): string {
  return `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "${fwd(process.execPath)}" "${fwd(cliPath())}"`;
}

/** Same, for a human or an agent to run a read-only subcommand (no env prefix needed). */
export function secretrunDisplay(): string {
  return `"${fwd(process.execPath)}" "${fwd(cliPath())}"`;
}

/** Git Bash — `CLAUDE_CODE_GIT_BASH_PATH` or the default install. Never `System32\bash.exe` (WSL). */
export function gitBashPath(): string | null {
  const candidates = [
    process.env.CLAUDE_CODE_GIT_BASH_PATH,
    'C:\\Program Files\\Git\\bin\\bash.exe',
    'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
  ];
  if (process.platform !== 'win32') candidates.push('/bin/bash', '/usr/bin/bash');
  for (const c of candidates) {
    if (!c) continue;
    if (/system32[\\/]+bash\.exe$/i.test(c)) continue;
    try {
      if (fs.statSync(c).isFile()) return c;
    } catch {
      /* next */
    }
  }
  return null;
}

/**
 * Create a directory readable only by the current user. On Windows `mode` is ignored, so the
 * inherited ACL is replaced with one granting only this user (best effort — a same-user process
 * can always read it; design §1).
 */
export function ensurePrivateDir(dir: string): void {
  if (fs.existsSync(dir)) return;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32' && process.env.USERNAME) {
    const user = process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}` : process.env.USERNAME;
    try {
      // Synchronous so the directory is locked down before the first ticket is written.
      spawnSync('icacls', [dir, '/inheritance:r', '/grant:r', `${user}:(OI)(CI)F`], {
        windowsHide: true,
        stdio: 'ignore',
      });
    } catch {
      /* best effort */
    }
  }
}
