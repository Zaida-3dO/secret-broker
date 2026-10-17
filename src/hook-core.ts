// PreToolUse decision logic (design §3). Loaded by hook.ts only on its slow path.
//
// Rules that must hold for every code path here:
//   - never call getValues(); never hold, print or log a value;
//   - every sentinel command gets an explicit permissionDecision (allow or deny);
//   - deny reasons are shown to the model, so they carry names, never values.
import { audit as writeAudit, type AuditEntry } from './audit.js';
import { getBackend as defaultBackend } from './backend/index.js';
import { bashEnvRead, findEnvRefs, pathEnvRead } from './envguard.js';
import { internalDeny, internalPaths, internalRef, type InternalPaths } from './internals.js';
import { lex, programBase, sentinelNames, substitute, SubstitutionError, SENTINEL_PREFIX, type ParseResult } from './lex.js';
import { cliPath, fwd, secretrunDisplay, secretrunInvocation } from './paths.js';
import { checkPolicy } from './policy.js';
import { VaultUnhealthyError } from './backend/infisical-http.js';
import { loadConfig } from './backend/index.js';
import { mintTicket, TICKET_TTL_MS, type MintInput } from './ticket.js';
import type { Grant, SecretBackend, SecretMeta, Ticket } from './types.js';

export interface HookInput {
  session_id?: string;
  cwd?: string;
  agent_id?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  hook_event_name?: string;
}

export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny';
    permissionDecisionReason?: string;
    updatedInput?: Record<string, unknown>;
  };
}

export interface HookDeps {
  getBackend: () => SecretBackend;
  mint: (input: MintInput) => Ticket;
  audit: (entry: AuditEntry) => void;
  /** Command prefix that runs secretrun (absolute paths). */
  invocation: string;
  /** How to tell an agent to run a read-only subcommand. */
  display: string;
  /** Broker-internal paths an agent may not touch. */
  internals: () => InternalPaths;
}

export function defaultDeps(): HookDeps {
  return {
    getBackend: () => defaultBackend(),
    mint: (i) => mintTicket(i, { ttlMs: configuredTtl() }),
    audit: (e) => writeAudit(e),
    invocation: secretrunInvocation(),
    display: secretrunDisplay(),
    internals: () => internalPaths(),
  };
}

function configuredTtl(): number {
  try {
    const s = Number(loadConfig().ticketTtlSeconds);
    return Number.isFinite(s) && s >= 5 && s <= 600 ? s * 1000 : TICKET_TTL_MS;
  } catch {
    return TICKET_TTL_MS;
  }
}

export const GENERIC_DENY =
  'secret-broker could not check this command, so it was blocked (no secret was used). ' +
  'Run `secretrun doctor`, or ask the operator.';

function allow(updatedInput: Record<string, unknown>, reason: string): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
      permissionDecisionReason: reason,
      updatedInput,
    },
  };
}

export function deny(reason: string): HookOutput {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}

/** Single-quote a string for bash. */
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function envDeny(path: string, display: string): string {
  return (
    `Reading ${path} is blocked by secret-broker: its values would land in the transcript. ` +
    'Use secrets by name instead — write {{secret:NAME}} in a Bash command and the value is injected at ' +
    `run time and redacted from output. Run \`${display} list\` to see the names available. ` +
    'If the secret you need is missing, ask the operator to add it to the broker.'
  );
}

const READ_ONLY_SUBCOMMANDS = new Set(['list', 'doctor', 'hook-snippet', 'help', '--help', '-h', 'version', '--version']);

/** Does the command invoke secretrun / its hook directly for anything but a read-only subcommand? */
export function directInvocation(command: string, parse: ParseResult, ownCli: string = cliPath()): boolean {
  const own = fwd(ownCli).toLowerCase();
  const ownHook = own.replace(/cli\.js$/, 'hook.js');
  if (/\bexec\s+--ticket\b/.test(command)) return true;
  // broker-resolve prints a value: whatever runs it (even `node "$f" broker-resolve …`), deny.
  if (parse.commands.some((c) => c.words.some((w) => w.text === 'broker-resolve'))) return true;
  if (parse.problems.length) {
    return /(secretrun|secret-broker)[^\n|;&]*\b(exec|grant|scrub|broker-resolve)\b/i.test(command) || /secretrun-hook|secret-broker[\\/][^\s'"]*hook\.js/i.test(command);
  }
  for (const cmd of parse.commands) {
    const ws = cmd.words;
    for (let k = 0; k < ws.length; k++) {
      const t = ws[k].text;
      const base = programBase(t);
      const lower = fwd(t).toLowerCase();
      const isHook =
        base === 'secretrun-hook' || base === 'secretrun-hook.cmd' || lower === ownHook || /secret-broker[\\/].*hook\.js$/i.test(t);
      if (isHook) return true;
      const isCli = base === 'secretrun' || base === 'secretrun.cmd' || lower === own || /secret-broker[\\/].*cli\.js$/i.test(t);
      if (!isCli) continue;
      const sub = ws.slice(k + 1).find((w) => !(w.static && w.text.startsWith('-') && !READ_ONLY_SUBCOMMANDS.has(w.text)));
      if (!sub || !READ_ONLY_SUBCOMMANDS.has(sub.text)) return true;
    }
  }
  return false;
}

export async function decide(input: HookInput, deps: HookDeps): Promise<HookOutput | null> {
  const tool = input.tool_name ?? '';
  const ti = input.tool_input ?? {};
  const base: Omit<AuditEntry, 'decision' | 'names' | 'command'> = {
    kind: 'hook',
    session_id: input.session_id ?? null,
    agent_id: input.agent_id ?? null,
    tool_use_id: input.tool_use_id ?? null,
    tool,
  };
  const denyAudited = (reason: string, names: string[], command: string): HookOutput => {
    deps.audit({ ...base, names, command, decision: 'deny', reason });
    return deny(reason);
  };

  const internals = deps.internals();
  const cwd = typeof input.cwd === 'string' ? input.cwd : undefined;

  if (tool === 'Read' || tool === 'Grep' || tool === 'NotebookRead') {
    for (const key of ['file_path', 'path', 'glob', 'notebook_path']) {
      const v = ti[key];
      const ref = typeof v === 'string' ? internalRef(v, internals, cwd) : null;
      if (ref) return denyAudited(internalDeny(ref, deps.display), [], `${tool} ${v as string}`);
    }
    const hit = pathEnvRead(ti);
    return hit ? denyAudited(envDeny(hit, deps.display), [], `${tool} ${hit}`) : null;
  }

  const command = typeof ti.command === 'string' ? ti.command : null;
  if (command === null) return null;

  if (tool === 'PowerShell' || tool === 'Bash') {
    const ref = internalRef(command, internals, cwd);
    if (ref) return denyAudited(internalDeny(ref, deps.display), [], command);
  }

  if (tool === 'PowerShell') {
    if (command.includes(SENTINEL_PREFIX)) {
      return denyAudited(
        'Secrets ({{secret:NAME}}) work only in the Bash tool. Run this command with the Bash tool instead.',
        [],
        command,
      );
    }
    if (/secretrun|secret-broker/i.test(command) && /\b(exec|grant|broker-resolve)\b/i.test(command)) {
      return denyAudited(directDenyText(deps.display), [], command);
    }
    const hit = findEnvRefs(command)[0];
    return hit ? denyAudited(envDeny(hit, deps.display), [], command) : null;
  }

  if (tool !== 'Bash') return null;

  const hasSentinel = command.includes(SENTINEL_PREFIX);
  let parse: ParseResult;
  try {
    parse = lex(command);
  } catch {
    return hasSentinel ? denyAudited(GENERIC_DENY, [], command) : null;
  }

  if (directInvocation(command, parse)) return denyAudited(directDenyText(deps.display), [], command);

  if (/\.env/i.test(command)) {
    const hit = bashEnvRead(command, parse);
    if (hit) return denyAudited(envDeny(hit, deps.display), [], command);
  }

  if (!hasSentinel) return null;

  const names = sentinelNames(parse);
  if (names.length === 0 && parse.problems.length === 0) return null; // sentinels only in comments
  try {
    substitute(command, parse);
  } catch (e) {
    if (e instanceof SubstitutionError) return denyAudited(e.message, names, command);
    throw e;
  }
  if (names.length === 0) {
    return denyAudited(`This command is too complex to verify for secret use (${parse.problems.join('; ')}).`, names, command);
  }

  let backend: SecretBackend;
  try {
    backend = deps.getBackend();
  } catch (e) {
    return denyAudited(`secret-broker is not available: ${(e as Error).message}. Run \`${deps.display} doctor\`.`, names, command);
  }
  const sessionId = input.session_id ?? '';
  let metas: SecretMeta[] = [];
  let grants: Grant[] = [];
  try {
    metas = await backend.listMeta();
    const needsGrant = names.some((n) => metas.find((m) => m.name === n)?.policy?.tier === 'grant');
    if (needsGrant && sessionId) grants = await backend.getGrants(sessionId);
  } catch (e) {
    // Unhealthy store: say so (the message is value-free), never "missing".
    if (e instanceof VaultUnhealthyError) return denyAudited(e.message, names, command);
    throw e;
  }
  const verdict = checkPolicy({ parse, names, metas, grants, sessionId });
  if (!verdict.ok) return denyAudited(verdict.reason, names, command);
  if (!sessionId) return denyAudited('No session id was supplied to the hook, so no ticket can be issued.', names, command);

  const ticket = deps.mint({
    sessionId,
    agentId: input.agent_id ?? null,
    toolUseId: input.tool_use_id ?? null,
    names,
    command,
  });
  deps.audit({ ...base, names, command, decision: 'allow' });
  return allow(
    { ...ti, command: `${deps.invocation} exec --ticket ${ticket.nonce} -- ${shq(command)}` },
    `secret-broker: ${names.join(', ')} injected at run time; output is redacted.`,
  );
}

function directDenyText(display: string): string {
  return (
    'Do not call secretrun exec (or its hook) directly — write {{secret:NAME}} in an ordinary Bash command ' +
    `and the broker runs it for you. \`${display} list\` shows the names you can use.`
  );
}
