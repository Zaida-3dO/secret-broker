// Single-use tickets (design §3 rule 4). The hook mints one per allowed secret command; `secretrun
// exec` refuses to run without redeeming a valid, unexpired, unconsumed ticket whose command hash
// matches the command it was handed. A same-user process can still forge one (design §1) — this
// stops the model from replaying or re-targeting a command, not a deliberate attacker.
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ensurePrivateDir, stateDir } from './paths.js';
import type { Ticket } from './types.js';

/**
 * Ticket lifetime. Design §3 says ≈30 s; the first e2e run measured 67 s between the hook's
 * decision and `secretrun exec` starting (the first Bash call of a session builds Claude Code's
 * shell snapshot; the machine was under load), so the default is 120 s. A ticket is single-use,
 * bound to the command's hash, and its nonce is never shown to the model, so the longer window
 * buys a replay nothing. Override with `ticketTtlSeconds` in config.json.
 */
export const TICKET_TTL_MS = 120_000;
const NONCE_RE = /^[0-9a-f]{64}$/;

export function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

export function ticketDir(base: string = stateDir()): string {
  return path.join(base, 'tickets');
}

export interface MintInput {
  sessionId: string;
  agentId: string | null;
  toolUseId: string | null;
  names: string[];
  command: string;
}

export function mintTicket(input: MintInput, opts: { dir?: string; now?: number; ttlMs?: number } = {}): Ticket {
  const dir = opts.dir ?? ticketDir();
  ensurePrivateDir(dir);
  const now = opts.now ?? Date.now();
  const ticket: Ticket = {
    nonce: randomBytes(32).toString('hex'),
    sessionId: input.sessionId,
    agentId: input.agentId,
    toolUseId: input.toolUseId,
    names: [...input.names],
    commandSha256: sha256(input.command),
    expiresAt: new Date(now + (opts.ttlMs ?? TICKET_TTL_MS)).toISOString(),
  };
  const file = path.join(dir, `${ticket.nonce}.json`);
  fs.writeFileSync(file, JSON.stringify(ticket), { flag: 'wx', mode: 0o600 });
  sweep(dir, now);
  return ticket;
}

export class TicketError extends Error {
  constructor(
    message: string,
    /** The ticket, when it was read before being rejected (for the audit line). */
    readonly ticket: Ticket | null = null,
  ) {
    super(message);
  }
}

/**
 * Atomically consume a ticket and verify it. The rename is the consume: of two concurrent
 * redeemers only one rename succeeds. The ticket is gone afterwards whatever the verdict.
 */
export function redeemTicket(nonce: string, command: string, opts: { dir?: string; now?: number } = {}): Ticket {
  if (!NONCE_RE.test(nonce)) throw new TicketError('invalid ticket');
  const dir = opts.dir ?? ticketDir();
  const file = path.join(dir, `${nonce}.json`);
  const claimed = `${file}.redeeming-${process.pid}-${randomBytes(4).toString('hex')}`;
  try {
    fs.renameSync(file, claimed);
  } catch {
    throw new TicketError('unknown or already-used ticket');
  }
  let ticket: Ticket;
  try {
    ticket = JSON.parse(fs.readFileSync(claimed, 'utf8')) as Ticket;
  } catch {
    throw new TicketError('unreadable ticket');
  } finally {
    try {
      fs.unlinkSync(claimed);
    } catch {
      /* already gone */
    }
  }
  const now = opts.now ?? Date.now();
  if (ticket.nonce !== nonce) throw new TicketError('ticket does not match its nonce');
  if (!(Date.parse(ticket.expiresAt) > now)) throw new TicketError('ticket expired', ticket);
  if (ticket.commandSha256 !== sha256(command)) throw new TicketError('ticket was issued for a different command', ticket);
  return ticket;
}

/** Remove tickets (and abandoned claims) older than five minutes. Best effort. */
function sweep(dir: string, now: number): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return;
  }
  for (const e of entries) {
    const f = path.join(dir, e);
    try {
      if (now - fs.statSync(f).mtimeMs > 5 * 60_000) fs.unlinkSync(f);
    } catch {
      /* ignore */
    }
  }
}
