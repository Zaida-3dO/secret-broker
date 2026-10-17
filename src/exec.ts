// `secretrun exec --ticket <nonce> -- '<command>'` (design §3).
//
// redeem ticket → re-check policy → fetch values → substitute sentinels by quote context →
// spawn Git Bash with the values in the child's environment only → stream stdout/stderr through
// the redactor (100 ms idle flush, flush on exit) → pass the exit code through → audit.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { audit } from './audit.js';
import { getBackend } from './backend/index.js';
import { lex, substitute, SubstitutionError } from './lex.js';
import { gitBashPath } from './paths.js';
import { checkPolicy } from './policy.js';
import { createRedactor } from './redact/index.js';
import { redeemTicket, TicketError } from './ticket.js';
import type { Redactor, SecretBackend, SecretValue, Ticket } from './types.js';

/** Exit code when secretrun refuses to run the command (bash's "cannot execute"). */
export const REFUSED_EXIT = 126;
export const IDLE_FLUSH_MS = 100;

/**
 * Variables that could make the child shell trace or source code, or that we set ourselves —
 * including the MSYS path-conversion switches the hook's rewrite sets for node, which must not
 * change how the agent's own command is run.
 */
export const STRIP_ENV = /^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PS4|BASH_XTRACEFD|PROMPT_COMMAND|MSYS_NO_PATHCONV|MSYS2_ARG_CONV_EXCL|__SR_.*|BASH_FUNC_.*)$/i;

export interface ExecOptions {
  ticket: string;
  command: string;
  backend?: SecretBackend;
  ticketDir?: string;
  bash?: string;
  stdout?: Writable;
  stderr?: Writable;
  idleMs?: number;
}

class Refusal extends Error {}

/** Never let an error message carry a value out. */
function safeMessage(err: unknown, values: SecretValue[]): string {
  const msg = err instanceof Error ? err.message : String(err);
  return values.some((v) => v.value && msg.includes(v.value)) ? 'internal error' : msg;
}

export async function runExec(opts: ExecOptions): Promise<number> {
  const stderr = opts.stderr ?? process.stderr;
  const stdout = opts.stdout ?? process.stdout;
  const started = Date.now();
  let ticket: Ticket | null = null;
  let names: string[] = [];
  let values: SecretValue[] = [];
  const auditBase = () => ({
    kind: 'exec' as const,
    session_id: ticket?.sessionId ?? null,
    agent_id: ticket?.agentId ?? null,
    tool_use_id: ticket?.toolUseId ?? null,
    names,
    command: opts.command,
  });

  let script: string;
  let bash: string;
  try {
    try {
      ticket = redeemTicket(opts.ticket, opts.command, { dir: opts.ticketDir });
    } catch (e) {
      if (e instanceof TicketError) {
        ticket = e.ticket;
        throw new Refusal(e.message);
      }
      throw new Refusal('invalid ticket');
    }
    const parse = lex(opts.command);
    let sub;
    try {
      sub = substitute(opts.command, parse);
    } catch (e) {
      if (e instanceof SubstitutionError) throw new Refusal(e.message);
      throw e;
    }
    names = sub.names;
    script = sub.script;
    if ([...names].sort().join('\n') !== [...ticket.names].sort().join('\n')) {
      throw new Refusal('ticket was issued for different secrets');
    }
    const backend = opts.backend ?? getBackend();
    const metas = await backend.listMeta();
    const grantTier = names.some((n) => metas.find((m) => m.name === n)?.policy?.tier === 'grant');
    const grants = grantTier ? await backend.getGrants(ticket.sessionId) : [];
    const verdict = checkPolicy({ parse, names, metas, grants, sessionId: ticket.sessionId });
    if (!verdict.ok) throw new Refusal(verdict.reason);
    const found = opts.bash ?? gitBashPath();
    if (!found) throw new Refusal('Git Bash not found (set CLAUDE_CODE_GIT_BASH_PATH)');
    bash = found;
    values = names.length ? await backend.getValues(names) : [];
    if (values.length !== names.length) throw new Refusal('backend returned the wrong number of values');
  } catch (e) {
    const reason = e instanceof Refusal ? e.message : safeMessage(e, values);
    stderr.write(`secretrun: refused: ${reason}\n`);
    audit({ ...auditBase(), decision: 'refuse', reason, exit_code: REFUSED_EXIT, duration_ms: Date.now() - started });
    return REFUSED_EXIT;
  }

  let outRed: Redactor;
  let errRed: Redactor;
  try {
    outRed = createRedactor(values);
    errRed = createRedactor(values);
  } catch (e) {
    const reason = `cannot redact: ${safeMessage(e, values)}`;
    stderr.write(`secretrun: refused: ${reason}\n`);
    audit({ ...auditBase(), decision: 'refuse', reason, exit_code: REFUSED_EXIT, duration_ms: Date.now() - started });
    return REFUSED_EXIT;
  }

  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!STRIP_ENV.test(k)) env[k] = v;
  for (const v of values) env[`__SR_${names.indexOf(v.name)}`] = v.value;
  // The script travels in an env var and is eval'd, so it never passes through Windows argv
  // quoting (or MSYS globbing/path conversion) on its way into bash.
  env.__SR_CMD = script;
  const child = spawn(bash, ['-c', '__sr_c=$__SR_CMD; unset __SR_CMD; eval "$__sr_c"'], {
    env,
    stdio: ['inherit', 'pipe', 'pipe'],
    windowsHide: true,
  });
  values = []; // drop our references; the redactors hold what they need

  const cleanup = installKillers(child);
  const idle = opts.idleMs ?? IDLE_FLUSH_MS;
  const exited = new Promise<number>((resolve) => {
    child.on('error', () => resolve(REFUSED_EXIT));
    child.on('exit', (c, sig) => resolve(c ?? (sig ? 128 + (signalNumber(sig) ?? 1) : 1)));
  });
  const [code] = await Promise.all([
    exited,
    pump(child.stdout!, stdout, outRed, idle),
    pump(child.stderr!, stderr, errRed, idle),
  ]);
  cleanup();
  audit({ ...auditBase(), decision: 'run', exit_code: code, duration_ms: Date.now() - started });
  return code;
}

function signalNumber(sig: NodeJS.Signals): number | undefined {
  return ({ SIGHUP: 1, SIGINT: 2, SIGKILL: 9, SIGTERM: 15 } as Record<string, number>)[sig];
}

/** Stream src → dst through a redactor; flush on 100 ms idle and at end. */
export function pump(src: Readable, dst: Writable, red: Redactor, idleMs: number): Promise<void> {
  return new Promise((resolve) => {
    let timer: NodeJS.Timeout | null = null;
    const flush = () => {
      timer = null;
      const out = red.flush();
      if (out.length) dst.write(out);
    };
    src.on('data', (chunk: Buffer) => {
      const out = red.push(chunk);
      if (out.length) dst.write(out);
      if (timer) clearTimeout(timer);
      timer = setTimeout(flush, idleMs);
    });
    let finished = false;
    const end = () => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      flush();
      resolve();
    };
    src.on('end', end);
    src.on('close', end);
    src.on('error', end);
  });
}

function killTree(child: ChildProcess): void {
  if (child.exitCode !== null || child.signalCode !== null || !child.pid) return;
  try {
    if (process.platform === 'win32') {
      spawnSync('taskkill', ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true });
    } else {
      child.kill('SIGKILL');
    }
  } catch {
    /* already gone */
  }
}

/** Kill the child tree on SIGINT/SIGTERM/SIGHUP/SIGBREAK, on our own exit, and if our parent dies. */
function installKillers(child: ChildProcess): () => void {
  const onSignal = (sig: NodeJS.Signals) => {
    killTree(child);
    process.exit(128 + (signalNumber(sig) ?? 2));
  };
  const sigs: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  if (process.platform === 'win32') sigs.push('SIGBREAK');
  for (const s of sigs) process.on(s, onSignal);
  const onExit = () => killTree(child);
  process.on('exit', onExit);
  const ppid = process.ppid;
  const watch = setInterval(() => {
    try {
      process.kill(ppid, 0);
    } catch {
      killTree(child);
      process.exit(129);
    }
  }, 1000);
  watch.unref();
  return () => {
    clearInterval(watch);
    for (const s of sigs) process.off(s, onSignal);
    process.off('exit', onExit);
  };
}
