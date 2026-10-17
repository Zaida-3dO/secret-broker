// InfisicalBackend — the real vault (design §2, §4, §5).
//
// - Universal Auth login with the machine credential stored by `secretrun setup` in Credential
//   Manager (`new Entry('secret-broker', 'infisical-<identity>')`, never withTarget — keyring.ts).
// - The access token is cached in Credential Manager too (`infisical-<identity>.token`) until its
//   TTL (minus a minute), so a command costs one ~30 ms fetch instead of a ~150 ms login.
// - Scope is by PROJECT (folders are not an access boundary on the free tier): `open` holds
//   open-tier secrets and the `/grants` records; `grant.<group>` projects hold grant-tier secrets
//   and are readable only during a grant window the operator opened (a temporary viewer role); `logins` is
//   the browser identity's project.
// - Policy lives in `secretMetadata` (tier, commands, hosts, description), listed with
//   `viewSecretValue=false`, so the hook learns policy without any value leaving the server.
// - `getValues` fetches exactly the named secrets, one request each.
//
// Names: a secret `KEY` at folder `/` is `KEY`; at `/db` it is `db/KEY`. `/grants` is never a
// secret source.
import { keyringAccount, nativeKeyring, readMachineCredential, type KeyringStore } from '../keyring.js';
import type { Grant, SecretBackend, SecretMeta, SecretPolicy, SecretValue } from '../types.js';
import { checkVaultUrl, describeFailure, vaultRequest, VaultUnhealthyError, type VaultResponse } from './infisical-http.js';

export interface InfisicalProjects {
  /** agents-open: open-tier secrets + `/grants` records. */
  open?: string;
  /** agents-logins: browser credentials (read by the browser identity only). */
  logins?: string;
  /** agents-grant-<group>: group → project id. */
  grant?: Record<string, string>;
}

export interface InfisicalOptions {
  url: string;
  identity: string;
  projects: InfisicalProjects;
  environment?: string;
  /** `agents` (open + grant projects, the default) or `logins` (browser identity). */
  scope?: 'agents' | 'logins';
  store?: () => Promise<KeyringStore>;
  timeoutMs?: number;
  now?: () => number;
}

export const GRANTS_PATH = '/grants';
const TOKEN_MARGIN_MS = 60_000;

interface Located {
  name: string;
  policy: SecretPolicy | null;
  projectId: string;
  secretPath: string;
  key: string;
  metadata: RawSecret['secretMetadata'];
}

interface RawSecret {
  secretKey?: string;
  secretPath?: string;
  secretMetadata?: { key?: string; value?: string }[];
}

export function tokenAccount(identity: string): string {
  return `${keyringAccount(identity)}.token`;
}

export function secretName(secretPath: string, key: string): string {
  const p = (secretPath || '/').replace(/^\/+|\/+$/g, '');
  return p ? `${p}/${key}` : key;
}

export function splitName(name: string): { secretPath: string; key: string } {
  const i = name.lastIndexOf('/');
  return i === -1 ? { secretPath: '/', key: name } : { secretPath: `/${name.slice(0, i)}`, key: name.slice(i + 1) };
}

export function metadataMap(md: RawSecret['secretMetadata']): Map<string, string> {
  const m = new Map<string, string>();
  for (const e of md ?? []) if (e && typeof e.key === 'string') m.set(e.key.toLowerCase(), typeof e.value === 'string' ? e.value : '');
  return m;
}

/** design §5: `tier`, `commands` (comma list), `hosts` (comma list), `description`. No/invalid tier → null (denied). */
export function policyFromMetadata(md: RawSecret['secretMetadata']): SecretPolicy | null {
  const m = metadataMap(md);
  const tier = m.get('tier')?.trim().toLowerCase();
  if (tier !== 'open' && tier !== 'grant') return null;
  const list = (v: string | undefined) => {
    const xs = (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    return xs.length ? xs : undefined;
  };
  const description = m.get('description')?.trim();
  return { tier, commands: list(m.get('commands')), hosts: list(m.get('hosts')), description: description || undefined };
}

export class InfisicalBackend implements SecretBackend {
  readonly url: string;
  private readonly env: string;
  private readonly now: () => number;
  private storeP: Promise<KeyringStore> | null = null;
  private token: string | null = null;
  private indexP: Promise<Map<string, Located>> | null = null;

  constructor(private readonly opts: InfisicalOptions) {
    this.url = checkVaultUrl(opts.url);
    this.env = opts.environment ?? 'prod';
    this.now = opts.now ?? Date.now;
    const scope = opts.scope ?? 'agents';
    if (scope === 'agents' && !opts.projects.open) throw new Error('config: Infisical needs projects.open (re-run `secretrun setup`)');
    if (scope === 'logins' && !opts.projects.logins) throw new Error('config: Infisical needs projects.logins (re-run `secretrun setup`)');
  }

  private store(): Promise<KeyringStore> {
    return (this.storeP ??= (this.opts.store ?? nativeKeyring)());
  }

  // ------------------------------------------------------------------ auth

  private async login(): Promise<string> {
    const store = await this.store();
    const cred = await readMachineCredential(this.opts.identity, store);
    const r = await vaultRequest(this.url, 'POST', '/api/v1/auth/universal-auth/login', {
      body: { clientId: cred.clientId, clientSecret: cred.clientSecret },
      timeoutMs: this.opts.timeoutMs,
    });
    if (r.status !== 200 || typeof r.json?.accessToken !== 'string') {
      throw new Error(`Infisical login for ${this.opts.identity} failed (${describeFailure('POST', '/api/v1/auth/universal-auth/login', r)}) — re-run \`secretrun setup\``);
    }
    const ttlMs = (Number(r.json.expiresIn) || 0) * 1000;
    if (ttlMs > TOKEN_MARGIN_MS) {
      try {
        store.set(tokenAccount(this.opts.identity), JSON.stringify({ url: this.url, accessToken: r.json.accessToken, expiresAt: this.now() + ttlMs }));
      } catch {
        /* cache is an optimisation */
      }
    }
    return r.json.accessToken as string;
  }

  private async cachedToken(): Promise<string | null> {
    try {
      const raw = (await this.store()).get(tokenAccount(this.opts.identity));
      if (!raw) return null;
      const t = JSON.parse(raw) as { url?: string; accessToken?: string; expiresAt?: number };
      if (t.url !== this.url || typeof t.accessToken !== 'string' || typeof t.expiresAt !== 'number') return null;
      return t.expiresAt - TOKEN_MARGIN_MS > this.now() ? t.accessToken : null;
    } catch {
      return null;
    }
  }

  private async dropCachedToken(): Promise<void> {
    this.token = null;
    try {
      (await this.store()).delete(tokenAccount(this.opts.identity));
    } catch {
      /* ignore */
    }
  }

  /** GET with the machine token; re-logs in once on 401 (expired/revoked cached token). */
  private async get(path: string, query: Record<string, string | undefined>): Promise<VaultResponse> {
    let fresh = false;
    if (!this.token) {
      this.token = await this.cachedToken();
      if (!this.token) {
        this.token = await this.login();
        fresh = true;
      }
    }
    let r = await vaultRequest(this.url, 'GET', path, { token: this.token, query, timeoutMs: this.opts.timeoutMs });
    if (r.status === 401 && !fresh) {
      await this.dropCachedToken();
      this.token = await this.login();
      r = await vaultRequest(this.url, 'GET', path, { token: this.token, query, timeoutMs: this.opts.timeoutMs });
    }
    if (r.status === 401) throw new Error(`Infisical rejected the access token for ${this.opts.identity} — re-run \`secretrun setup\``);
    return r;
  }

  // ------------------------------------------------------------------ listing

  private projectList(): { id: string; optional: boolean }[] {
    const p = this.opts.projects;
    if ((this.opts.scope ?? 'agents') === 'logins') return [{ id: p.logins!, optional: false }];
    return [{ id: p.open!, optional: false }, ...Object.values(p.grant ?? {}).map((id) => ({ id, optional: true }))];
  }

  private async listProject(projectId: string, optional: boolean): Promise<RawSecret[]> {
    const path = '/api/v4/secrets';
    const r = await this.get(path, {
      projectId,
      environment: this.env,
      secretPath: '/',
      recursive: 'true',
      viewSecretValue: 'false',
    });
    if (r.status === 200) return Array.isArray(r.json?.secrets) ? (r.json.secrets as RawSecret[]) : [];
    // A grant project outside its window is 403 (no-access role) — not an error, just nothing visible.
    if (optional && (r.status === 403 || r.status === 404)) return [];
    throw new Error(`Infisical: cannot list secrets (${describeFailure('GET', path, r)})`);
  }

  private index(): Promise<Map<string, Located>> {
    return (this.indexP ??= (async () => {
      const out = new Map<string, Located>();
      const dup = new Set<string>();
      for (const { id, optional } of this.projectList()) {
        for (const s of await this.listProject(id, optional)) {
          if (typeof s.secretKey !== 'string' || !s.secretKey) continue;
          const secretPath = typeof s.secretPath === 'string' && s.secretPath ? s.secretPath : '/';
          if (secretPath === GRANTS_PATH || secretPath.startsWith(`${GRANTS_PATH}/`)) continue;
          const name = secretName(secretPath, s.secretKey);
          if (out.has(name)) dup.add(name);
          out.set(name, { name, policy: policyFromMetadata(s.secretMetadata), projectId: id, secretPath, key: s.secretKey, metadata: s.secretMetadata });
        }
      }
      // The same name in two projects is ambiguous: unusable until the operator renames one.
      for (const n of dup) out.get(n)!.policy = null;
      return out;
    })());
  }

  async listMeta(): Promise<SecretMeta[]> {
    return [...(await this.index()).values()].map((e) => ({ name: e.name, policy: e.policy }));
  }

  /** A visible secret's raw metadata (the browser resolver reads origins/fields from it), or null. */
  async locateMeta(name: string): Promise<{ name: string; metadata: { key?: string; value?: string }[] } | null> {
    const e = (await this.index()).get(name);
    return e ? { name: e.name, metadata: e.metadata ?? [] } : null;
  }

  // ------------------------------------------------------------------ values

  async getValues(names: string[]): Promise<SecretValue[]> {
    const idx = await this.index();
    const missing: string[] = [];
    const denied: string[] = [];
    const out: SecretValue[] = [];
    for (const name of names) {
      const e = idx.get(name);
      if (!e) {
        missing.push(name);
        continue;
      }
      const path = `/api/v4/secrets/${encodeURIComponent(e.key)}`;
      const r = await this.get(path, { projectId: e.projectId, environment: this.env, secretPath: e.secretPath, viewSecretValue: 'true' });
      const v = r.json?.secret?.secretValue;
      if (r.status === 200 && typeof v === 'string' && r.json.secret.secretValueHidden !== true) out.push({ name, value: v });
      else if (r.status === 403) denied.push(name);
      else if (r.status === 404 || r.status === 200) missing.push(name);
      else throw new Error(`Infisical: cannot read ${name} (${describeFailure('GET', path, r)})`);
    }
    if (denied.length) throw new Error(`not permitted to read secret(s): ${denied.join(', ')} (a grant window may have expired)`);
    if (missing.length) throw new Error(`no value for secret(s): ${missing.join(', ')}`);
    return out;
  }

  // ------------------------------------------------------------------ grants (design §4 layer 2)

  async getGrants(sessionId: string): Promise<Grant[]> {
    const open = this.opts.projects.open;
    if (!open || !sessionId) return [];
    const path = '/api/v4/secrets';
    const r = await this.get(path, {
      projectId: open,
      environment: this.env,
      secretPath: GRANTS_PATH,
      viewSecretValue: 'false',
      metadataFilter: `key=session,value=${sessionId}`,
    });
    if (r.status === 404) return []; // no /grants folder yet
    if (r.status !== 200) throw new Error(`Infisical: cannot read grants (${describeFailure('GET', path, r)})`);
    const now = this.now();
    const out: Grant[] = [];
    for (const s of (Array.isArray(r.json?.secrets) ? r.json.secrets : []) as RawSecret[]) {
      const m = metadataMap(s.secretMetadata);
      const g: Grant = {
        secret: m.get('secret') ?? '',
        sessionId: m.get('session') ?? '',
        expiresAt: m.get('expiresat') ?? '',
        grantedBy: m.get('grantedby') ?? '',
      };
      // Never trust the server-side filter alone.
      if (g.secret && g.sessionId === sessionId && Date.parse(g.expiresAt) > now) out.push(g);
    }
    return out;
  }
}

export { VaultUnhealthyError };
