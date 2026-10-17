// `secretrun grant <session> <NAME> [--ttl 8h] [--group g] [--identity pc-x] [--dry-run]` against
// Infisical (design §4). Run by the operator in their own terminal:
//
//   1. prompt for his Infisical email + password (password hidden); log in, select the organisation;
//   2. find NAME in the configured grant projects (`agents-grant-<group>`), check it is grant tier;
//   3. layer 1 (server-enforced window): give the PC identity a TEMPORARY `viewer` role on that
//      project, paired with the permanent `no-access` role (a temporary-only membership is refused).
//      An existing longer window is kept, never shortened;
//   4. layer 2 (session scope): write the grant record into `agents-open:/grants`, with the policy
//      fields in secretMetadata (session, secret, expiresAt, grantedBy, group) — PCs read it only;
//   5. log out and drop the token. The granting credential is never stored anywhere.
//
// Nothing here prints a password or a token.
import { createHash } from 'node:crypto';
import type { Config } from './backend/index.js';
import { checkVaultUrl, describeFailure, vaultRequest, type RequestOptions, type VaultResponse } from './backend/infisical-http.js';
import { GRANTS_PATH, metadataMap, splitName } from './backend/infisical.js';

export interface GrantOptions {
  cfg: Config;
  sessionId: string;
  name: string;
  ttlMs: number;
  group?: string;
  identity?: string;
  dryRun?: boolean;
  /** Ask a question in the operator's terminal; `hidden` for the password. */
  prompt: (question: string, hidden: boolean) => Promise<string>;
  log?: (line: string) => void;
  now?: () => number;
  timeoutMs?: number;
}

export class GrantError extends Error {}

export const SESSION_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
export const NAME_RE = /^[A-Za-z0-9_./-]{1,128}$/;

/** Deterministic record key, so granting the same secret to the same session again updates it. */
export function grantKey(sessionId: string, name: string): string {
  return `GRANT_${createHash('sha256').update(`${sessionId}\n${name}`).digest('hex').slice(0, 32)}`;
}

export async function runInfisicalGrant(o: GrantOptions): Promise<void> {
  const log = o.log ?? ((l: string) => process.stdout.write(l + '\n'));
  const now = o.now ?? Date.now;
  const cfg = o.cfg;
  if (cfg.backend !== 'infisical' || !cfg.url) throw new GrantError('config is not on the Infisical backend');
  const url = checkVaultUrl(cfg.url);
  const env = cfg.environment ?? 'prod';
  const identity = o.identity ?? cfg.identity;
  const open = cfg.projects?.open;
  const groups = cfg.projects?.grant ?? {};
  if (!identity) throw new GrantError('no identity: pass --identity pc-<machine>');
  if (!open) throw new GrantError('config has no projects.open — re-run `secretrun setup`');
  if (!SESSION_RE.test(o.sessionId)) throw new GrantError(`invalid session id ${JSON.stringify(o.sessionId)}`);
  if (!NAME_RE.test(o.name)) throw new GrantError(`invalid secret name ${JSON.stringify(o.name)}`);
  if (o.group && !groups[o.group]) throw new GrantError(`no grant group ${o.group} in config (have: ${Object.keys(groups).join(', ') || 'none'})`);
  const candidates = o.group ? [o.group] : Object.keys(groups);
  if (!candidates.length) throw new GrantError('config has no grant projects (projects.grant) — re-run `secretrun setup`');
  const ttlS = Math.ceil(o.ttlMs / 1000);
  const expiresAt = new Date(now() + ttlS * 1000).toISOString();
  const key = grantKey(o.sessionId, o.name);

  if (o.dryRun) {
    log('dry run — nothing is contacted, nothing is written, no password is asked for');
    log(`1. prompt for your Infisical email + password (hidden); POST /api/v3/auth/login at ${url}; select the organisation`);
    log(`2. find ${o.name} in grant project(s): ${candidates.map((g) => `agents-grant-${g}`).join(', ')} (${env}); require tier=grant`);
    log(`3. ${identity}: no-access (permanent) + viewer (temporary, ${ttlS}s, until ${expiresAt}) on that project — a longer existing window is kept`);
    log(`4. write grant record ${GRANTS_PATH}/${key} in agents-open: session ${o.sessionId}, secret ${o.name}, expires ${expiresAt}`);
    log('5. log out and drop the token');
    return;
  }

  const email = (await o.prompt('Infisical email: ', false)).trim();
  const password = await o.prompt('Infisical password (hidden): ', true);
  if (!email || !password) throw new GrantError('email and password are required');

  let token: string | null = null;
  const call = async (method: string, path: string, opts: RequestOptions = {}): Promise<VaultResponse> =>
    vaultRequest(url, method, path, { ...opts, token: token ?? undefined, timeoutMs: o.timeoutMs });
  const must = (r: VaultResponse, method: string, path: string, ok = [200]) => {
    if (!ok.includes(r.status)) throw new GrantError(describeFailure(method, path, r));
    return r;
  };
  try {
    const login = must(await call('POST', '/api/v3/auth/login', { body: { email, password } }), 'POST', '/api/v3/auth/login');
    if (typeof login.json?.accessToken !== 'string') {
      throw new GrantError('login did not return a session token (MFA on this account is not supported here)');
    }
    token = login.json.accessToken as string;
    let orgId = cfg.organizationId;
    if (!orgId) {
      const orgs = must(await call('GET', '/api/v1/organization'), 'GET', '/api/v1/organization').json?.organizations ?? [];
      if (!orgs.length) throw new GrantError('your account has no organisation');
      orgId = orgs[0].id as string;
    }
    const sel = must(await call('POST', '/api/v3/auth/select-organization', { body: { organizationId: orgId } }), 'POST', '/api/v3/auth/select-organization');
    if (typeof sel.json?.token !== 'string') throw new GrantError('select-organization did not return a token');
    token = sel.json.token as string;
    log('logged in');

    // 2. which grant project holds the secret
    const { secretPath, key: secretKey } = splitName(o.name);
    let group: string | null = null;
    for (const g of candidates) {
      const p = `/api/v4/secrets/${encodeURIComponent(secretKey)}`;
      const r = await call('GET', p, { query: { projectId: groups[g], environment: env, secretPath, viewSecretValue: 'false' } });
      if (r.status === 404) continue;
      must(r, 'GET', p);
      const tier = metadataMap(r.json?.secret?.secretMetadata).get('tier')?.trim().toLowerCase();
      if (tier !== 'grant') throw new GrantError(`${o.name} in agents-grant-${g} has tier ${JSON.stringify(tier ?? null)}, not "grant" — fix its metadata first`);
      group = g;
      break;
    }
    if (!group) throw new GrantError(`no secret ${o.name} in ${candidates.map((g) => `agents-grant-${g}`).join(', ')}`);
    const projectId = groups[group];

    // the PC identity's id
    const ids = must(await call('GET', '/api/v1/identities', { query: { orgId } }), 'GET', '/api/v1/identities').json?.identities ?? [];
    const found = (ids as any[]).find((x) => (x.identity?.name ?? x.name) === identity); // eslint-disable-line @typescript-eslint/no-explicit-any
    if (!found) throw new GrantError(`no machine identity ${identity} in the organisation`);
    const identityId: string = found.identity?.id ?? found.identityId ?? found.id;

    // 3. layer 1 — temporary viewer, never shortening a longer live window
    const memPath = `/api/v1/projects/${projectId}/memberships/identities/${identityId}`;
    const cur = await call('GET', memPath);
    if (cur.status !== 200 && cur.status !== 404) must(cur, 'GET', memPath);
    const roles: any[] = cur.status === 200 ? (cur.json?.identityMembership?.roles ?? []) : []; // eslint-disable-line @typescript-eslint/no-explicit-any
    const permanent = roles.filter((r) => !r.isTemporary && r.role !== 'no-access').map((r) => r.role);
    if (permanent.length) {
      log(`WARNING: ${identity} already holds permanent ${permanent.join(', ')} on agents-grant-${group}; the server window is always open — left unchanged`);
    } else {
      let rangeS = ttlS;
      for (const r of roles) {
        const end = Date.parse(r.temporaryAccessEndTime ?? '');
        if (r.isTemporary && r.role === 'viewer' && end > now()) rangeS = Math.max(rangeS, Math.ceil((end - now()) / 1000));
      }
      const body = {
        roles: [
          { role: 'no-access' },
          { role: 'viewer', isTemporary: true, temporaryMode: 'relative', temporaryRange: `${rangeS}s`, temporaryAccessStartTime: new Date(now()).toISOString() },
        ],
      };
      const method = cur.status === 200 ? 'PATCH' : 'POST';
      must(await call(method, memPath, { body }), method, memPath);
      log(`${identity}: temporary viewer on agents-grant-${group} for ${rangeS}s`);
    }

    // 4. layer 2 — the grant record
    const fr = await call('POST', '/api/v1/folders', { body: { workspaceId: open, environment: env, name: GRANTS_PATH.slice(1), path: '/' } });
    if (fr.status !== 200 && fr.status !== 400 && fr.status !== 409) must(fr, 'POST', '/api/v1/folders');
    const grantedBy = email;
    const record = {
      projectId: open,
      environment: env,
      secretPath: GRANTS_PATH,
      secretValue: JSON.stringify({ secret: o.name, sessionId: o.sessionId, expiresAt, grantedBy, group }),
      secretMetadata: [
        { key: 'session', value: o.sessionId },
        { key: 'secret', value: o.name },
        { key: 'expiresAt', value: expiresAt },
        { key: 'grantedBy', value: grantedBy },
        { key: 'group', value: group },
      ],
    };
    const recPath = `/api/v4/secrets/${key}`;
    let w = await call('POST', recPath, { body: { ...record, type: 'shared' } });
    if (w.status === 400 || w.status === 409) w = await call('PATCH', recPath, { body: record });
    must(w, 'POST/PATCH', recPath);
    log(`granted ${o.name} to session ${o.sessionId} until ${expiresAt}`);
  } finally {
    if (token) {
      try {
        await call('POST', '/api/v1/auth/logout', { body: {} });
      } catch {
        /* best effort */
      }
      token = null;
    }
  }
}

/** Hidden/visible line prompt on a real terminal (adapted from the identity bootstrap script). */
export function ttyPrompt(question: string, hidden: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new GrantError('secretrun grant needs a terminal to ask for your Infisical login — run it yourself, not through an agent'));
      return;
    }
    process.stdout.write(question);
    let buf = '';
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const done = () => {
      stdin.removeListener('data', onData);
      stdin.setRawMode?.(false);
      stdin.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          done();
          resolve(buf);
          return;
        }
        if (ch === '\u0003') {
          done();
          reject(new GrantError('cancelled'));
          return;
        }
        if (ch === '\u007f' || ch === '\b') {
          buf = buf.slice(0, -1);
          continue;
        }
        if (ch >= ' ') {
          buf += ch;
          if (!hidden) process.stdout.write(ch);
        }
      }
    };
    stdin.on('data', onData);
  });
}
