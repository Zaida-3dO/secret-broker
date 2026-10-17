// A local fake of the Infisical v0.166 API surface secretrun uses, mirroring the request/response
// shapes verified against a live Infisical:
//   POST /api/v1/auth/universal-auth/login {clientId, clientSecret} -> {accessToken, expiresIn, tokenType}
//   GET  /api/v4/secrets?projectId&environment&secretPath&recursive&viewSecretValue&metadataFilter -> {secrets:[…]}
//   GET  /api/v4/secrets/{key}?projectId&environment&secretPath&viewSecretValue -> {secret:{…}}
//   POST/PATCH /api/v4/secrets/{key} (user token)
//   POST /api/v1/folders {workspaceId, environment, name, path}
//   POST /api/v3/auth/login {email,password} -> {accessToken}; GET /api/v1/organization;
//   POST /api/v3/auth/select-organization -> {token}; POST /api/v1/auth/logout
//   GET  /api/v1/identities?orgId -> {identities:[{identityId, identity:{id,name}}]}
//   GET/POST/PATCH /api/v1/projects/{p}/memberships/identities/{i} {roles:[…]}
// Permissions: an identity reads a project only while it holds a live non-`no-access` role there
// (403 otherwise, as 403 on a missing role); viewers cannot write.
import { randomBytes } from 'node:crypto';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
const dummyUserSecret = () => `DUMMY-SECRET-${randomBytes(6).toString('hex')}`;

export interface FakeSecret {
  project: string;
  path: string;
  key: string;
  value: string;
  metadata?: Record<string, string>;
}
export interface FakeRole {
  role: string;
  isTemporary: boolean;
  temporaryRange?: string;
  temporaryAccessStartTime?: string;
  temporaryAccessEndTime?: string;
}
export interface FakeRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  token: string | null;
  body: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

export const ORG_ID = 'org-1';
export const HIDDEN = '<hidden-by-infisical>';

export class FakeInfisical {
  url = '';
  requests: FakeRequest[] = [];
  secrets: FakeSecret[] = [];
  folders = new Set<string>(); // `${project}|${path}`
  identities = new Map<string, { id: string; clientId: string; clientSecret: string }>();
  memberships = new Map<string, FakeRole[]>(); // `${project}|${identityId}`
  user = { email: 'operator@example.test', password: dummyUserSecret() };
  fault: null | '500' | 'hang' = null;
  ignoreMetadataFilter = false;
  tokenTtl = 3600;
  private tokens = new Map<string, { kind: 'identity'; id: string } | { kind: 'user' }>();
  private server: http.Server | null = null;
  private hung: http.ServerResponse[] = [];

  addIdentity(name: string): { id: string; clientId: string; clientSecret: string } {
    const v = { id: `id-${name}`, clientId: `cid-${name}`, clientSecret: `DUMMY-SECRET-${randomBytes(8).toString('hex')}` };
    this.identities.set(name, v);
    return v;
  }
  member(project: string, identity: string, roles: FakeRole[]): void {
    this.memberships.set(`${project}|${this.identities.get(identity)!.id}`, roles);
  }
  revokeAllTokens(): void {
    this.tokens.clear();
  }
  logins(): number {
    return this.requests.filter((r) => r.path === '/api/v1/auth/universal-auth/login').length;
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }
  async stop(): Promise<void> {
    for (const r of this.hung) r.destroy();
    this.server?.closeAllConnections();
    await new Promise<void>((r) => this.server!.close(() => r()));
  }

  private canRead(project: string, identityId: string): boolean {
    const roles = this.memberships.get(`${project}|${identityId}`) ?? [];
    const now = Date.now();
    return roles.some((r) => r.role !== 'no-access' && (!r.isTemporary || Date.parse(r.temporaryAccessEndTime ?? '') > now));
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const u = new URL(req.url ?? '/', 'http://x');
    let raw = '';
    for await (const c of req) raw += c;
    const body = raw ? JSON.parse(raw) : undefined;
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '') || null;
    const method = req.method ?? 'GET';
    this.requests.push({ method, path: u.pathname, query: Object.fromEntries(u.searchParams), token, body });
    if (this.fault === 'hang') {
      this.hung.push(res);
      return;
    }
    const send = (status: number, json: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(json));
    };
    if (this.fault === '500') return send(500, { message: 'Something went wrong', error: 'Find one' });
    const p = u.pathname;
    const q = Object.fromEntries(u.searchParams);

    if (method === 'POST' && p === '/api/v1/auth/universal-auth/login') {
      const id = [...this.identities.values()].find((i) => i.clientId === body?.clientId && i.clientSecret === body?.clientSecret);
      if (!id) return send(401, { message: 'Invalid credentials' });
      const t = `tok-${randomBytes(8).toString('hex')}`;
      this.tokens.set(t, { kind: 'identity', id: id.id });
      return send(200, { accessToken: t, expiresIn: this.tokenTtl, accessTokenMaxTTL: 86400, tokenType: 'Bearer' });
    }
    if (method === 'POST' && p === '/api/v3/auth/login') {
      if (body?.email !== this.user.email || body?.password !== this.user.password) return send(400, { message: 'Failed to authenticate' });
      const t = `utok-${randomBytes(8).toString('hex')}`;
      this.tokens.set(t, { kind: 'user' });
      return send(200, { accessToken: t });
    }
    const who = token ? this.tokens.get(token) : undefined;
    if (!who) return send(401, { message: 'Token missing or invalid' });
    const isUser = who.kind === 'user';
    const readable = (project: string) => isUser || this.canRead(project, (who as { id: string }).id);

    if (p === '/api/v1/organization' && method === 'GET' && isUser) return send(200, { organizations: [{ id: ORG_ID, name: 'Org' }] });
    if (p === '/api/v3/auth/select-organization' && isUser) {
      const t = `utok-${randomBytes(8).toString('hex')}`;
      this.tokens.set(t, { kind: 'user' });
      return send(200, { token: t });
    }
    if (p === '/api/v1/auth/logout' && isUser) {
      this.tokens.delete(token!);
      return send(200, { message: 'ok' });
    }
    if (p === '/api/v1/identities' && isUser) {
      return send(200, { identities: [...this.identities.entries()].map(([name, i]) => ({ id: `orgmem-${i.id}`, identityId: i.id, identity: { id: i.id, name } })) });
    }
    if (p === '/api/v1/folders' && method === 'POST' && isUser) {
      const k = `${body.workspaceId}|/${body.name}`;
      if (this.folders.has(k)) return send(400, { message: 'Folder already exists' });
      this.folders.add(k);
      return send(200, { folder: { name: body.name } });
    }
    const mem = /^\/api\/v1\/projects\/([^/]+)\/memberships\/identities\/([^/]+)$/.exec(p);
    if (mem && isUser) {
      const k = `${mem[1]}|${mem[2]}`;
      if (method === 'GET') {
        const roles = this.memberships.get(k);
        return roles ? send(200, { identityMembership: { roles: roles.map((r, i) => ({ id: `r${i}`, ...r })) } }) : send(404, { message: 'not found' });
      }
      if (method === 'POST' && this.memberships.has(k)) return send(400, { message: 'Identity is already a member' });
      if (method === 'PATCH' && !this.memberships.has(k)) return send(404, { message: 'not found' });
      const roles: FakeRole[] = (body.roles ?? [{ role: body.role ?? 'no-access' }]).map((r: FakeRole) => {
        if (!r.isTemporary) return { role: r.role, isTemporary: false };
        const secs = Number(/^(\d+)s$/.exec(r.temporaryRange ?? '')?.[1]);
        return { ...r, temporaryAccessEndTime: new Date(Date.parse(r.temporaryAccessStartTime!) + secs * 1000).toISOString() };
      });
      if (!roles.some((r) => !r.isTemporary)) return send(400, { message: 'Identity must have at least one permanent role' });
      this.memberships.set(k, roles);
      return send(200, { identityMembership: { roles } });
    }

    const shape = (s: FakeSecret, hide: boolean) => ({
      secretKey: s.key,
      secretPath: s.path,
      secretValue: hide ? HIDDEN : s.value,
      secretValueHidden: hide,
      secretMetadata: Object.entries(s.metadata ?? {}).map(([key, value]) => ({ key, value, isEncrypted: false })),
      type: 'shared',
    });
    if (p === '/api/v4/secrets' && method === 'GET') {
      if (!readable(q.projectId)) return send(403, { message: 'You are not allowed to describeSecret on secrets' });
      const base = q.secretPath ?? '/';
      let list = this.secrets.filter(
        (s) => s.project === q.projectId && (s.path === base || (q.recursive === 'true' && (base === '/' || s.path.startsWith(`${base}/`)))),
      );
      const mf = /^key=([^,]+),value=(.*)$/.exec(q.metadataFilter ?? '');
      if (mf && !this.ignoreMetadataFilter) list = list.filter((s) => s.metadata?.[mf[1]] === mf[2]);
      return send(200, { secrets: list.map((s) => shape(s, q.viewSecretValue === 'false')), imports: [] });
    }
    const one = /^\/api\/v4\/secrets\/([^/]+)$/.exec(p);
    if (one) {
      const key = decodeURIComponent(one[1]);
      const proj = method === 'GET' ? q.projectId : body?.projectId;
      const path = (method === 'GET' ? q.secretPath : body?.secretPath) ?? '/';
      if (!readable(proj)) return send(403, { message: 'You are not allowed to describeSecret on secrets' });
      const found = this.secrets.find((s) => s.project === proj && s.path === path && s.key === key);
      if (method === 'GET') return found ? send(200, { secret: shape(found, q.viewSecretValue === 'false') }) : send(404, { message: 'Secret not found' });
      if (!isUser) return send(403, { message: 'You are not allowed to create on secrets' });
      const metadata = Object.fromEntries(((body.secretMetadata ?? []) as { key: string; value: string }[]).map((m) => [m.key, m.value]));
      if (method === 'POST') {
        if (found) return send(400, { message: 'Secret already exist' });
        this.secrets.push({ project: proj, path, key, value: body.secretValue, metadata });
        return send(200, { secret: { secretKey: key } });
      }
      if (method === 'PATCH') {
        if (!found) return send(404, { message: 'Secret not found' });
        found.value = body.secretValue ?? found.value;
        found.metadata = metadata;
        return send(200, { secret: { secretKey: key } });
      }
    }
    return send(404, { message: `fake: no route ${method} ${p}` });
  }
}
