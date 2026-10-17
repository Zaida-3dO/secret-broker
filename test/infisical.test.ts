import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { after, afterEach, beforeEach, describe, it } from 'node:test';
import { getBackend, NotConfiguredError, type Config } from '../src/backend/index.js';
import { checkVaultUrl, VaultUnhealthyError } from '../src/backend/infisical-http.js';
import { InfisicalBackend, policyFromMetadata, splitName, secretName, tokenAccount, type InfisicalProjects } from '../src/backend/infisical.js';
import { grantKey, runInfisicalGrant } from '../src/grant.js';
import { decide, type HookDeps } from '../src/hook-core.js';
import { encodeCredential, keyringAccount, type KeyringStore } from '../src/keyring.js';
import { mapProjects, runSetup } from '../src/setup.js';
import type { SecretBackend } from '../src/types.js';
import { dummy } from './helpers.js';
import { FakeInfisical } from './infisical-fake.js';

const OPEN = 'proj-open';
const GRANT = 'proj-grant-default';
const LOGINS = 'proj-logins';
const PROJECTS: InfisicalProjects = { open: OPEN, logins: LOGINS, grant: { default: GRANT } };

function memStore(): KeyringStore & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return { data, set: (a, s) => void data.set(a, s), get: (a) => data.get(a) ?? null, delete: (a) => data.delete(a) };
}

let fake: FakeInfisical;
let store: ReturnType<typeof memStore>;
let values: Record<string, string>;

function backend(extra: Partial<ConstructorParameters<typeof InfisicalBackend>[0]> = {}): InfisicalBackend {
  return new InfisicalBackend({ url: fake.url, identity: 'pc-test', projects: PROJECTS, store: async () => store, ...extra });
}

beforeEach(async () => {
  fake = new FakeInfisical();
  await fake.start();
  const id = fake.addIdentity('pc-test');
  fake.addIdentity('browser-test');
  fake.member(OPEN, 'pc-test', [{ role: 'viewer', isTemporary: false }]);
  fake.member(GRANT, 'pc-test', [{ role: 'no-access', isTemporary: false }]);
  values = { CF: dummy(), DB: dummy(), NOPOL: dummy(), GR: dummy() };
  fake.secrets.push(
    { project: OPEN, path: '/', key: 'CF_API_TOKEN', value: values.CF, metadata: { tier: 'open', commands: 'curl, wrangler', hosts: 'api.cloudflare.com', description: 'cf token' } },
    { project: OPEN, path: '/db', key: 'APP_DB_URL', value: values.DB, metadata: { tier: 'open', commands: 'psql' } },
    { project: OPEN, path: '/', key: 'NO_POLICY', value: values.NOPOL },
    { project: GRANT, path: '/', key: 'PROD_DEPLOY', value: values.GR, metadata: { tier: 'grant', commands: './deploy.sh' } },
  );
  store = memStore();
  store.set(keyringAccount('pc-test'), encodeCredential({ clientId: id.clientId, clientSecret: id.clientSecret }));
});
afterEach(async () => {
  await fake.stop();
});

describe('InfisicalBackend: listing (policy without values)', () => {
  it('lists names + policy from secretMetadata with viewSecretValue=false, folders as path/KEY', async () => {
    const metas = await backend().listMeta();
    const byName = Object.fromEntries(metas.map((m) => [m.name, m.policy]));
    assert.deepEqual(Object.keys(byName).sort(), ['CF_API_TOKEN', 'NO_POLICY', 'db/APP_DB_URL']);
    assert.deepEqual(byName.CF_API_TOKEN, { tier: 'open', commands: ['curl', 'wrangler'], hosts: ['api.cloudflare.com'], description: 'cf token' });
    assert.equal(byName.NO_POLICY, null);
    const lists = fake.requests.filter((r) => r.path === '/api/v4/secrets');
    assert.ok(lists.length >= 1);
    for (const r of lists) assert.equal(r.query.viewSecretValue, 'false');
    assert.ok(!fake.requests.some((r) => r.path.startsWith('/api/v4/secrets/')), 'listing must not fetch any single secret');
    const dumped = JSON.stringify(metas);
    for (const v of Object.values(values)) assert.ok(!dumped.includes(v));
  });

  it('skips /grants records and a grant project outside its window (403), without failing', async () => {
    fake.secrets.push({ project: OPEN, path: '/grants', key: 'GRANT_x', value: '{}', metadata: { session: 's1' } });
    const names = (await backend().listMeta()).map((m) => m.name);
    assert.ok(!names.some((n) => n.startsWith('grants/')));
    assert.ok(!names.includes('PROD_DEPLOY'));
  });

  it('lists grant-tier names while the PC holds a live temporary viewer role', async () => {
    fake.member(GRANT, 'pc-test', [
      { role: 'no-access', isTemporary: false },
      { role: 'viewer', isTemporary: true, temporaryAccessEndTime: new Date(Date.now() + 60_000).toISOString() },
    ]);
    const m = (await backend().listMeta()).find((x) => x.name === 'PROD_DEPLOY');
    assert.equal(m?.policy?.tier, 'grant');
  });

  it('marks a name that exists in two projects as unusable', async () => {
    fake.member(GRANT, 'pc-test', [{ role: 'viewer', isTemporary: false }]);
    fake.secrets.push({ project: GRANT, path: '/', key: 'CF_API_TOKEN', value: dummy(), metadata: { tier: 'grant' } });
    const m = (await backend().listMeta()).find((x) => x.name === 'CF_API_TOKEN');
    assert.equal(m?.policy, null);
  });

  it('a failure on the open project is an error, not an empty list', async () => {
    fake.memberships.delete(`${OPEN}|id-pc-test`);
    await assert.rejects(backend().listMeta(), /cannot list secrets.*403/);
  });
});

describe('InfisicalBackend: values', () => {
  it('fetches exactly the named secrets, from the right project and folder', async () => {
    const v = await backend().getValues(['db/APP_DB_URL']);
    assert.deepEqual(v, [{ name: 'db/APP_DB_URL', value: values.DB }]);
    const singles = fake.requests.filter((r) => r.path.startsWith('/api/v4/secrets/'));
    assert.equal(singles.length, 1);
    assert.equal(singles[0].path, '/api/v4/secrets/APP_DB_URL');
    assert.equal(singles[0].query.secretPath, '/db');
    assert.equal(singles[0].query.projectId, OPEN);
  });

  it('names a missing secret without a value, and an expired grant window as not permitted', async () => {
    await assert.rejects(backend().getValues(['NOPE']), /no value for secret\(s\): NOPE/);
    fake.member(GRANT, 'pc-test', [
      { role: 'no-access', isTemporary: false },
      { role: 'viewer', isTemporary: true, temporaryAccessEndTime: new Date(Date.now() + 60_000).toISOString() },
    ]);
    const b = backend();
    await b.listMeta(); // window open while listing…
    fake.member(GRANT, 'pc-test', [{ role: 'no-access', isTemporary: false }]); // …closes before the fetch
    await assert.rejects(b.getValues(['PROD_DEPLOY']), /not permitted to read secret\(s\): PROD_DEPLOY/);
  });
});

describe('InfisicalBackend: token cache in Credential Manager', () => {
  it('logs in once, then reuses the cached token across instances (processes)', async () => {
    await backend().listMeta();
    assert.equal(fake.logins(), 1);
    assert.ok(store.get(tokenAccount('pc-test')));
    assert.equal(tokenAccount('pc-test'), 'infisical-pc-test.token');
    await backend().listMeta();
    await backend().getValues(['CF_API_TOKEN']);
    assert.equal(fake.logins(), 1);
  });

  it('logs in again once the cached token reaches its TTL', async () => {
    await backend().listMeta();
    const later = Date.now() + 3600_000;
    await backend({ now: () => later }).listMeta();
    assert.equal(fake.logins(), 2);
  });

  it('re-logs in once when the server rejects a cached token (401)', async () => {
    await backend().listMeta();
    fake.revokeAllTokens();
    const metas = await backend().listMeta();
    assert.ok(metas.length > 0);
    assert.equal(fake.logins(), 2);
  });

  it('a wrong stored credential is a clear setup error, never a value', async () => {
    store.set(keyringAccount('pc-test'), encodeCredential({ clientId: 'cid-pc-test', clientSecret: 'DUMMY-SECRET-wrong000000' }));
    await assert.rejects(backend().listMeta(), (e: Error) => /login for pc-test failed/.test(e.message) && !e.message.includes('DUMMY-SECRET-wrong'));
  });
});

describe('InfisicalBackend: unhealthy store', () => {
  it('HTTP 5xx is "vault unhealthy", not "missing"', async () => {
    await backend().listMeta(); // warm token
    fake.fault = '500';
    await assert.rejects(backend().getValues(['CF_API_TOKEN']), (e: Error) => e instanceof VaultUnhealthyError && !/no value/.test(e.message));
    await assert.rejects(backend().listMeta(), VaultUnhealthyError);
  });

  it('a hang is cut off by the hard timeout and reported unhealthy', async () => {
    fake.fault = 'hang';
    const t0 = Date.now();
    await assert.rejects(backend({ timeoutMs: 300 }).listMeta(), (e: Error) => e instanceof VaultUnhealthyError && /no answer within 300 ms/.test(e.message));
    assert.ok(Date.now() - t0 < 3000);
  });

  it('connection refused is unhealthy', async () => {
    const url = fake.url;
    await fake.stop();
    const b = new InfisicalBackend({ url, identity: 'pc-test', projects: PROJECTS, store: async () => store, timeoutMs: 3000 });
    await assert.rejects(b.listMeta(), VaultUnhealthyError);
    fake = new FakeInfisical();
    await fake.start(); // for afterEach
  });

  it('the default timeout is 5 s', async () => {
    const { DEFAULT_TIMEOUT_MS } = await import('../src/backend/infisical-http.js');
    assert.equal(DEFAULT_TIMEOUT_MS, 5000);
  });

  it('the hook denies with the unhealthy reason instead of a generic one', async () => {
    const sick: SecretBackend = {
      listMeta: async () => {
        throw new VaultUnhealthyError('GET /api/v4/secrets: HTTP 500');
      },
      getValues: async () => [],
      getGrants: async () => [],
    };
    const deps: HookDeps = {
      getBackend: () => sick,
      mint: () => {
        throw new Error('no mint');
      },
      audit: () => {},
      invocation: 'secretrun',
      display: 'secretrun',
      internals: () => ({ dirs: [], files: [] }),
    };
    const out = await decide({ session_id: 's', tool_name: 'Bash', tool_input: { command: 'curl -H "x: {{secret:CF_API_TOKEN}}" https://api.cloudflare.com/x' } }, deps);
    assert.equal(out?.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out!.hookSpecificOutput.permissionDecisionReason!, /vault unhealthy/);
  });
});

describe('InfisicalBackend: grants (layer 2 records)', () => {
  const rec = (session: string, secret: string, expiresAt: string) => ({
    project: OPEN,
    path: '/grants',
    key: grantKey(session, secret),
    value: '{}',
    metadata: { session, secret, expiresAt, grantedBy: 'operator' },
  });
  it('returns only live records for this session, reading metadata with viewSecretValue=false', async () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    const past = new Date(Date.now() - 1000).toISOString();
    fake.secrets.push(rec('s1', 'PROD_DEPLOY', future), rec('s1', 'OLD', past), rec('s2', 'PROD_DEPLOY', future));
    fake.ignoreMetadataFilter = true; // the client must not rely on the server-side filter
    const g = await backend().getGrants('s1');
    assert.deepEqual(g, [{ secret: 'PROD_DEPLOY', sessionId: 's1', expiresAt: future, grantedBy: 'operator' }]);
    const r = fake.requests.find((x) => x.query.secretPath === '/grants')!;
    assert.equal(r.query.viewSecretValue, 'false');
    assert.equal(r.query.metadataFilter, 'key=session,value=s1');
  });
});

describe('secretrun grant (Infisical, two layers)', () => {
  const cfg = (): Config => ({ backend: 'infisical', url: fake.url, identity: 'pc-test', projects: PROJECTS, organizationId: 'org-1' });
  const prompt = async (q: string) => (/password/.test(q) ? fake.user.password : fake.user.email);

  it('opens a temporary viewer window + writes the session record; the PC then passes both layers', async () => {
    const lines: string[] = [];
    const before = Date.now();
    await runInfisicalGrant({ cfg: cfg(), sessionId: 'sess-1', name: 'PROD_DEPLOY', ttlMs: 3600_000, prompt, log: (l) => lines.push(l) });
    const roles = fake.memberships.get(`${GRANT}|id-pc-test`)!;
    assert.deepEqual(roles.map((r) => [r.role, r.isTemporary]), [['no-access', false], ['viewer', true]]);
    assert.equal(roles[1].temporaryRange, '3600s');
    assert.ok(Date.parse(roles[1].temporaryAccessEndTime!) >= before + 3600_000 - 2000);
    const b = backend();
    assert.ok((await b.listMeta()).some((m) => m.name === 'PROD_DEPLOY'));
    assert.deepEqual((await b.getGrants('sess-1')).map((g) => g.secret), ['PROD_DEPLOY']);
    assert.deepEqual(await b.getGrants('other'), []);
    assert.deepEqual(await b.getValues(['PROD_DEPLOY']), [{ name: 'PROD_DEPLOY', value: values.GR }]);
    // logged out; the password never appears in output
    assert.ok(fake.requests.some((r) => r.path === '/api/v1/auth/logout'));
    assert.ok(!lines.join('\n').includes(fake.user.password));
    assert.ok(fake.folders.has(`${OPEN}|/grants`));
  });

  it('never shortens a longer live window; a second grant updates rather than duplicates', async () => {
    const end = new Date(Date.now() + 10 * 3600_000).toISOString();
    fake.member(GRANT, 'pc-test', [
      { role: 'no-access', isTemporary: false },
      { role: 'viewer', isTemporary: true, temporaryAccessEndTime: end },
    ]);
    await runInfisicalGrant({ cfg: cfg(), sessionId: 'sess-1', name: 'PROD_DEPLOY', ttlMs: 60_000, prompt, log: () => {} });
    await runInfisicalGrant({ cfg: cfg(), sessionId: 'sess-1', name: 'PROD_DEPLOY', ttlMs: 60_000, prompt, log: () => {} });
    const range = Number(/^(\d+)s$/.exec(fake.memberships.get(`${GRANT}|id-pc-test`)![1].temporaryRange!)![1]);
    assert.ok(range > 9 * 3600, `range ${range}s should keep the 10 h window`);
    assert.equal(fake.secrets.filter((s) => s.path === '/grants').length, 1);
  });

  it('refuses a secret whose tier is not grant, and an unknown name', async () => {
    fake.secrets.push({ project: GRANT, path: '/', key: 'OOPS', value: dummy(), metadata: { tier: 'open' } });
    await assert.rejects(runInfisicalGrant({ cfg: cfg(), sessionId: 's', name: 'OOPS', ttlMs: 1000, prompt, log: () => {} }), /not "grant"/);
    await assert.rejects(runInfisicalGrant({ cfg: cfg(), sessionId: 's', name: 'NOPE', ttlMs: 1000, prompt, log: () => {} }), /no secret NOPE/);
    assert.ok(!fake.memberships.get(`${GRANT}|id-pc-test`)!.some((r) => r.isTemporary));
  });

  it('dry run contacts nothing and asks for nothing', async () => {
    let asked = false;
    const lines: string[] = [];
    await runInfisicalGrant({
      cfg: cfg(),
      sessionId: 'sess-1',
      name: 'PROD_DEPLOY',
      ttlMs: 60_000,
      dryRun: true,
      prompt: async () => {
        asked = true;
        return '';
      },
      log: (l) => lines.push(l),
    });
    assert.equal(asked, false);
    assert.equal(fake.requests.length, 0);
    assert.match(lines.join('\n'), /temporary, 60s/);
  });
});

describe('config + setup wiring', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretrun-inf-'));
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  it('getBackend builds an InfisicalBackend and refuses a config without projects.open', () => {
    assert.ok(getBackend({ backend: 'infisical', url: 'https://vault.example.test', identity: 'pc-x', projects: { open: 'p' } }) instanceof InfisicalBackend);
    assert.throws(() => getBackend({ backend: 'infisical', url: 'https://vault.example.test', identity: 'pc-x' }), NotConfiguredError);
  });

  it('refuses plain http except loopback', () => {
    assert.throws(() => checkVaultUrl('http://vault.example.test'), /must be https/);
    assert.equal(checkVaultUrl('http://127.0.0.1:1/'), 'http://127.0.0.1:1');
  });

  it('maps bootstrap project slugs', () => {
    assert.deepEqual(mapProjects({ 'agents-open': 'a', 'agents-logins': 'b', 'agents-grant-default': 'c', 'agents-grant-': 'x', containers: 'd' }), {
      open: 'a',
      logins: 'b',
      grant: { default: 'c' },
    });
  });

  it('setup writes the project ids from projects.json into config', async () => {
    const dir = path.join(root, 'setup');
    const boot = path.join(dir, 'bootstrap');
    fs.mkdirSync(boot, { recursive: true });
    fs.writeFileSync(path.join(boot, 'pc-test.json'), JSON.stringify({ apiUrl: 'https://vault.example.test', identity: 'pc-test', clientId: 'c', clientSecret: dummy() }));
    fs.writeFileSync(path.join(boot, 'projects.json'), JSON.stringify({ organizationId: 'org-9', projects: { 'agents-open': 'po', 'agents-grant-default': 'pg' } }));
    const configPath = path.join(dir, 'config.json');
    await runSetup({ identity: 'pc-test', bootstrapDir: boot, configPath, store: memStore(), log: () => {} });
    const c = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.deepEqual(c, { backend: 'infisical', url: 'https://vault.example.test', identity: 'pc-test', projects: { open: 'po', grant: { default: 'pg' } }, organizationId: 'org-9' });
  });
});

describe('name mapping + metadata policy', () => {
  it('round-trips folder names', () => {
    assert.equal(secretName('/', 'A'), 'A');
    assert.equal(secretName('/db/x', 'A'), 'db/x/A');
    assert.deepEqual(splitName('db/x/A'), { secretPath: '/db/x', key: 'A' });
    assert.deepEqual(splitName('A'), { secretPath: '/', key: 'A' });
  });
  it('invalid tier is no policy', () => {
    assert.equal(policyFromMetadata([{ key: 'tier', value: 'opne' }]), null);
    assert.equal(policyFromMetadata([{ key: 'Tier', value: ' GRANT ' }])?.tier, 'grant');
  });
});
