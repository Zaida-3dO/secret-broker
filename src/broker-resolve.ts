// `secretrun broker-resolve [resolve] <NAME>` — the private implementation of browser-broker's
// generic BROKER_SECRET_RESOLVER contract (browser-broker src/secrets/resolver.ts, 6ea991e):
//
//   invoked as  <BROKER_SECRET_RESOLVER> resolve NAME   (no shell, 5 s budget, stderr discarded)
//   stdout      one JSON object {value, origins: ["https://host[:port]"], fields?: ["password"|"username"|"otp"]}
//   failure     non-zero exit; nothing on stdout
//
// Reads ONLY the logins project (`projects.logins`) with the separate browser identity
// (`browserIdentity`, default `browser-<machine>`), so a PC identity's open/grant secrets can never
// be typed into a page. `origins` and `fields` come from the secret's own metadata (comma lists);
// a login without `origins` is refused here rather than left for the broker to refuse.
//
// Agents must never run this (it prints a value): the hook denies it like `exec`.
import * as os from 'node:os';
import { audit as defaultAudit, type AuditEntry } from './audit.js';
import { loadConfig, type Config } from './backend/index.js';
import { InfisicalBackend, metadataMap } from './backend/infisical.js';
import type { KeyringStore } from './keyring.js';

export const FIELD_KINDS = ['password', 'username', 'otp'] as const;
const NAME_RE = /^[A-Za-z0-9_./-]{1,128}$/;

export class ResolveError extends Error {}

export interface ResolveOptions {
  cfg?: Config;
  store?: () => Promise<KeyringStore>;
  timeoutMs?: number;
  audit?: (e: AuditEntry) => void;
}

export interface Resolved {
  value: string;
  origins: string[];
  fields?: string[];
}

export function defaultBrowserIdentity(): string {
  return `browser-${os.hostname().toLowerCase()}`;
}

/** Exact `scheme://host[:port]` (what browser-broker's normaliseOrigin accepts), or null. */
export function exactOrigin(s: string): string | null {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (u.username || u.password || u.search || u.hash || u.pathname !== '/' || /^[a-z]+:\/\/[^/]*\/./i.test(s)) return null;
  return u.origin;
}

export async function brokerResolve(name: string, o: ResolveOptions = {}): Promise<Resolved> {
  if (!NAME_RE.test(name)) throw new ResolveError('invalid secret name');
  const cfg = o.cfg ?? loadConfig();
  if (cfg.backend !== 'infisical' || !cfg.url) throw new ResolveError('secret-broker is not on the Infisical backend');
  if (!cfg.projects?.logins) throw new ResolveError('config has no projects.logins — re-run `secretrun setup`');
  const identity = typeof cfg.browserIdentity === 'string' && cfg.browserIdentity ? cfg.browserIdentity : defaultBrowserIdentity();
  const backend = new InfisicalBackend({
    url: cfg.url,
    identity,
    environment: cfg.environment,
    projects: { logins: cfg.projects.logins },
    scope: 'logins',
    store: o.store,
    timeoutMs: o.timeoutMs,
  });
  // `{{secret:login/github}}` and `{{secret:github}}` both name the logins project's `github`.
  let at = await backend.locateMeta(name);
  let resolvedName = name;
  if (!at && name.startsWith('login/')) {
    resolvedName = name.slice('login/'.length);
    at = await backend.locateMeta(resolvedName);
  }
  if (!at) throw new ResolveError(`no login named ${name}`);
  const md = metadataMap(at.metadata);
  const origins: string[] = [];
  for (const raw of (md.get('origins') ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const origin = exactOrigin(raw);
    if (!origin) throw new ResolveError(`${name}: "origins" metadata has an entry that is not an exact origin`);
    origins.push(origin);
  }
  if (!origins.length) throw new ResolveError(`${name} has no "origins" metadata; a login must say where it may be typed`);
  const fieldsRaw = (md.get('fields') ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const f of fieldsRaw) {
    if (!(FIELD_KINDS as readonly string[]).includes(f)) throw new ResolveError(`${name}: "fields" may only name ${FIELD_KINDS.join(', ')}`);
  }
  const [v] = await backend.getValues([resolvedName]);
  if (!v?.value) throw new ResolveError(`${name} has an empty value`);
  (o.audit ?? defaultAudit)({ kind: 'broker-resolve', session_id: null, agent_id: null, names: [name], command: `broker-resolve ${name}`, decision: 'run' });
  return fieldsRaw.length ? { value: v.value, origins, fields: fieldsRaw } : { value: v.value, origins };
}
