import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { after, describe, it } from 'node:test';
import { keyringAccount, readMachineCredential, type KeyringStore } from '../src/keyring.js';
import { runSetup, SetupError } from '../src/setup.js';
import { dummy } from './helpers.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretrun-setup-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

function fakeStore(opts: { corrupt?: boolean } = {}): KeyringStore & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    set: (a, s) => void data.set(a, opts.corrupt ? s.slice(1) : s),
    get: (a) => data.get(a) ?? null,
    delete: (a) => data.delete(a),
  };
}

let n = 0;
function fixture(cfg?: unknown) {
  const dir = path.join(root, `case-${n++}`);
  const bootstrapDir = path.join(dir, 'bootstrap');
  fs.mkdirSync(bootstrapDir, { recursive: true });
  const secret = dummy();
  const file = path.join(bootstrapDir, 'pc-test.json');
  fs.writeFileSync(
    file,
    JSON.stringify({ apiUrl: 'https://vault.example.test', identity: 'pc-test', clientId: 'cid-123', clientSecret: secret }),
  );
  const configPath = path.join(dir, 'config.json');
  if (cfg) fs.writeFileSync(configPath, JSON.stringify(cfg));
  const lines: string[] = [];
  return { dir, bootstrapDir, file, configPath, secret, lines, log: (l: string) => lines.push(l) };
}

describe('secretrun setup', () => {
  it('stores the credential, reads it back, writes infisical config, deletes the bootstrap file', async () => {
    const f = fixture();
    const store = fakeStore();
    await runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store, log: f.log });
    assert.equal(fs.existsSync(f.file), false, 'bootstrap file deleted');
    assert.deepEqual(await readMachineCredential('pc-test', store), { clientId: 'cid-123', clientSecret: f.secret });
    assert.ok(store.data.has(keyringAccount('pc-test')));
    assert.deepEqual(JSON.parse(fs.readFileSync(f.configPath, 'utf8')), {
      backend: 'infisical',
      url: 'https://vault.example.test',
      identity: 'pc-test',
    });
    assert.ok(!f.lines.join('\n').includes(f.secret), 'never prints the secret');
  });
  it('keeps the bootstrap file when the credential does not read back', async () => {
    const f = fixture();
    await assert.rejects(
      runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore({ corrupt: true }), log: f.log }),
      /did not read back/,
    );
    assert.ok(fs.existsSync(f.file));
    assert.equal(fs.existsSync(f.configPath), false);
  });
  it('leaves a FileBackend config alone unless --switch-backend', async () => {
    const f = fixture({ backend: 'file', file: 'x.json' });
    await runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore(), log: f.log });
    assert.equal(JSON.parse(fs.readFileSync(f.configPath, 'utf8')).backend, 'file');
    assert.equal(fs.existsSync(f.file), false, 'credential still moved into the store');
  });
  it('--switch-backend replaces a FileBackend config and keeps a copy', async () => {
    const f = fixture({ backend: 'file', file: 'x.json' });
    await runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore(), switchBackend: true, log: f.log });
    assert.equal(JSON.parse(fs.readFileSync(f.configPath, 'utf8')).backend, 'infisical');
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.dir, 'config.file-backend.json'), 'utf8')).backend, 'file');
  });
  it('dry run changes nothing', async () => {
    const f = fixture();
    const store = fakeStore();
    await runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store, dryRun: true, log: f.log });
    assert.ok(fs.existsSync(f.file));
    assert.equal(store.data.size, 0);
    assert.equal(fs.existsSync(f.configPath), false);
  });
  it('refuses a bootstrap file for another identity', async () => {
    const f = fixture();
    fs.renameSync(f.file, path.join(f.bootstrapDir, 'pc-other.json'));
    await assert.rejects(
      runSetup({ identity: 'pc-other', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore(), log: f.log }),
      SetupError,
    );
  });
  it('fails clearly with neither a bootstrap file nor a stored credential', async () => {
    const f = fixture();
    fs.unlinkSync(f.file);
    await assert.rejects(
      runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore(), log: f.log }),
      /bootstrap/,
    );
  });
  it('a malformed bootstrap file error never echoes its content', async () => {
    const f = fixture();
    fs.writeFileSync(f.file, `{"clientSecret":"${f.secret}"`);
    await assert.rejects(
      runSetup({ identity: 'pc-test', bootstrapDir: f.bootstrapDir, configPath: f.configPath, store: fakeStore(), log: f.log }),
      (e: Error) => !e.message.includes(f.secret),
    );
  });
  it('readMachineCredential explains a missing credential', async () => {
    await assert.rejects(readMachineCredential('pc-none', fakeStore()), /secretrun setup/);
  });
});
