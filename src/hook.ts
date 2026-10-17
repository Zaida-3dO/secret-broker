#!/usr/bin/env node
// secretrun-hook — Claude Code PreToolUse hook (design §3).
//
// Fast path: this file has NO static imports. It reads stdin and, unless the raw input mentions a
// sentinel, a dotenv file or secretrun itself, exits 0 having printed nothing — before any module
// is loaded. Everything else lives in hook-core.js, imported only on the slow path.
//
// Fail-safe: any internal error on a command containing `{{secret:` prints a generic deny; with no
// sentinel it exits 0 silently (a crash would let the command run unchanged, which leaks nothing).
const t0 = performance.now();
const TRIGGER = /\{\{secret:|\.env|secretrun|secret-broker/i;

/**
 * The dev FileBackend's file name, so a command naming it reaches the internals guard even when
 * it does not live under a `secret-broker` folder. One small synchronous read; no module loading.
 */
function storeName(): string | null {
  try {
    const fs = process.getBuiltinModule('node:fs') as typeof import('node:fs');
    const cfgPath =
      process.env.SECRETRUN_CONFIG ?? `${process.env.APPDATA ?? `${process.env.HOME ?? ''}/.config`}/secret-broker/config.json`;
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { backend?: string; file?: string };
    if (cfg.backend !== 'file' || typeof cfg.file !== 'string') return null;
    return cfg.file.split(/[\\/]/).pop()?.toLowerCase() || null;
  } catch {
    return null;
  }
}

const chunks: Buffer[] = [];
process.stdin.on('data', (c: Buffer) => chunks.push(c));
let tEnd = 0;
process.stdin.on('end', () => {
  tEnd = performance.now();
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!TRIGGER.test(raw) && !mentionsStore(raw)) {
    timing('fast');
    return;
  }
  slow(raw).catch(() => fail(raw));
});

function mentionsStore(raw: string): boolean {
  const name = storeName();
  return !!name && raw.toLowerCase().includes(name);
}

/** `total` = script start → decision (includes waiting on stdin); `work` = stdin end → decision. */
function timing(path: string): void {
  if (!process.env.SECRETRUN_HOOK_TIMING) return;
  const now = performance.now();
  process.stderr.write(`secretrun-hook ${path} total=${(now - t0).toFixed(2)}ms work=${(now - tEnd).toFixed(2)}ms\n`);
}

function fail(raw: string): void {
  if (raw.includes('{{secret:')) {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason:
            'secret-broker could not check this command, so it was blocked (no secret was used). Run `secretrun doctor`, or ask the operator.',
        },
      }),
    );
  }
  process.exitCode = 0;
}

async function slow(raw: string): Promise<void> {
  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    return fail(raw);
  }
  const core = await import('./hook-core.js');
  const out = await core.decide(input as Parameters<typeof core.decide>[0], core.defaultDeps());
  if (out) process.stdout.write(JSON.stringify(out));
  timing('slow');
}
