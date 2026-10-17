// Audit log (design §7): one JSON line per hook decision and per exec, in
// %LOCALAPPDATA%\secret-broker\audit.jsonl. Commands are logged as written — with sentinels,
// never values. Failures to write are swallowed: the audit must never break a command.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ensurePrivateDir, stateDir } from './paths.js';

export interface AuditEntry {
  kind: 'hook' | 'exec' | 'broker-resolve';
  session_id: string | null;
  agent_id: string | null;
  tool_use_id?: string | null;
  tool?: string;
  names: string[];
  command: string;
  decision: 'allow' | 'deny' | 'run' | 'refuse' | 'error';
  reason?: string;
  exit_code?: number | null;
  duration_ms?: number;
}

export function auditPath(base: string = stateDir()): string {
  return path.join(base, 'audit.jsonl');
}

export function audit(entry: AuditEntry, base: string = stateDir()): void {
  try {
    ensurePrivateDir(base);
    const line = JSON.stringify({ ts: new Date().toISOString(), machine: os.hostname(), ...entry });
    fs.appendFileSync(auditPath(base), line + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    /* never break the command */
  }
}
