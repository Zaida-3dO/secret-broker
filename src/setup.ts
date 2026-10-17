// `secretrun setup` — run by the operator in their own terminal, once per PC, after
// the operator's identity bootstrap has written %LOCALAPPDATA%\secret-broker\bootstrap\pc-<machine>.json.
//
//   1. read the bootstrap file ({apiUrl, identity, clientId, clientSecret});
//   2. store {clientId, clientSecret} in Windows Credential Manager under
//      new Entry('secret-broker', 'infisical-<identity>')  (never withTarget — design §3 rule 8);
//   3. read it back through a fresh entry and compare;
//   4. write config {"backend":"infisical","url":…,"identity":…,"projects":{open,logins,grant:{…}}}, the
//      project ids taken from the bootstrap's projects.json (agents-open → open, agents-logins → logins,
//      agents-grant-<g> → grant.<g>) — unless the current config uses the dev FileBackend, which is
//      left untouched until `--switch-backend`;
//   5. delete the bootstrap file.
// It never prints the client secret.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config } from './backend/index.js';
import type { InfisicalProjects } from './backend/infisical.js';
import { encodeCredential, keyringAccount, KEYRING_SERVICE, nativeKeyring, type KeyringStore } from './keyring.js';
import { configPath as defaultConfigPath, stateDir } from './paths.js';


export interface SetupOptions {
  identity?: string;
  bootstrapDir?: string;
  configPath?: string;
  store?: KeyringStore;
  switchBackend?: boolean;
  dryRun?: boolean;
  log?: (line: string) => void;
}

interface BootstrapFile {
  apiUrl?: string;
  identity?: string;
  clientId?: string;
  clientSecret?: string;
}

export class SetupError extends Error {}

/** Map bootstrap projects.json ({projects: {slug: id}}) onto config projects. */
export function mapProjects(slugs: Record<string, unknown>): InfisicalProjects {
  const out: InfisicalProjects = {};
  for (const [slug, id] of Object.entries(slugs)) {
    if (typeof id !== 'string' || !id) continue;
    if (slug === 'agents-open') out.open = id;
    else if (slug === 'agents-logins') out.logins = id;
    else if (slug.startsWith('agents-grant-') && slug.length > 'agents-grant-'.length) {
      (out.grant ??= {})[slug.slice('agents-grant-'.length)] = id;
    }
  }
  return out;
}

export function defaultIdentity(): string {
  return `pc-${os.hostname().toLowerCase()}`;
}

export async function runSetup(opts: SetupOptions = {}): Promise<void> {
  const log = opts.log ?? ((l: string) => process.stdout.write(l + '\n'));
  const identity = opts.identity ?? defaultIdentity();
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(identity)) throw new SetupError(`invalid identity name ${JSON.stringify(identity)}`);
  const dir = opts.bootstrapDir ?? path.join(stateDir(), 'bootstrap');
  const file = path.join(dir, `${identity}.json`);
  const cfgPath = opts.configPath ?? defaultConfigPath();
  const account = keyringAccount(identity);

  let boot: BootstrapFile | null = null;
  if (fs.existsSync(file)) {
    try {
      boot = JSON.parse(fs.readFileSync(file, 'utf8')) as BootstrapFile;
    } catch {
      throw new SetupError(`${file} is not valid JSON`); // never echo its content
    }
    if (typeof boot.clientId !== 'string' || !boot.clientId || typeof boot.clientSecret !== 'string' || !boot.clientSecret) {
      throw new SetupError(`${file} has no clientId/clientSecret`);
    }
    if (boot.identity && boot.identity !== identity) {
      throw new SetupError(`${file} is for identity ${boot.identity}, not ${identity}`);
    }
  }

  const store = opts.store ?? (opts.dryRun ? null : await nativeKeyring());
  if (opts.dryRun) {
    log(`dry run — nothing will be changed`);
    log(boot ? `would store the credential from ${file}` : `no bootstrap file at ${file}`);
    log(`  in Credential Manager: service ${KEYRING_SERVICE}, account ${account}`);
    log(`would write ${cfgPath} (backend infisical) unless it currently uses the FileBackend`);
    if (boot) log(`would delete ${file}`);
    return;
  }

  if (boot) {
    const encoded = encodeCredential({ clientId: boot.clientId!, clientSecret: boot.clientSecret! });
    store!.set(account, encoded);
    const back = store!.get(account);
    if (back !== encoded) {
      throw new SetupError(`the credential did not read back from Credential Manager (account ${account}); the bootstrap file was kept`);
    }
    log(`stored the machine credential for ${identity} in Credential Manager (service ${KEYRING_SERVICE}, account ${account}) and read it back`);
  } else if (store!.get(account)) {
    log(`no bootstrap file at ${file}; Credential Manager already holds ${account}`);
  } else {
    throw new SetupError(`no bootstrap file at ${file} and no stored credential for ${identity}. Provision the identity first (see docs/operations.md, "Deploying a vault").`);
  }

  // Config.
  let current: Config | null = null;
  try {
    current = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as Config;
  } catch {
    current = null;
  }
  // A browser identity (used only by `secretrun broker-resolve`) never becomes the PC identity.
  if (identity.startsWith('browser-')) {
    if (current?.backend === 'infisical') {
      fs.writeFileSync(cfgPath, JSON.stringify({ ...current, browserIdentity: identity }, null, 2) + '\n');
      log(`set browserIdentity ${identity} in ${cfgPath}`);
    } else {
      log(`left ${cfgPath} unchanged (not on Infisical yet); broker-resolve defaults to browser-<machine>`);
    }
    if (boot) {
      fs.unlinkSync(file);
      log(`deleted ${file}`);
    }
    return;
  }
  const existingUrl = current?.backend === 'infisical' ? current.url : undefined;
  const url = boot?.apiUrl && /^https:\/\//.test(boot.apiUrl) ? boot.apiUrl.replace(/\/$/, '') : existingUrl;
  if (!url) throw new SetupError('no https vault URL: the bootstrap file needs an "apiUrl" (or the config an existing "url")');
  let projects: InfisicalProjects | undefined = current?.backend === 'infisical' ? current.projects : undefined;
  let organizationId: string | undefined = current?.backend === 'infisical' ? current.organizationId : undefined;
  const projFile = path.join(dir, 'projects.json');
  if (fs.existsSync(projFile)) {
    try {
      const pj = JSON.parse(fs.readFileSync(projFile, 'utf8')) as { organizationId?: unknown; projects?: Record<string, unknown> };
      projects = mapProjects(pj.projects ?? {});
      if (typeof pj.organizationId === 'string') organizationId = pj.organizationId;
    } catch {
      throw new SetupError(`${projFile} is not valid JSON`);
    }
  }
  if (current?.backend === 'file' && !opts.switchBackend) {
    log(`left ${cfgPath} on the dev FileBackend (pass --switch-backend to point it at Infisical)`);
  } else {
    if (!projects?.open) log(`WARNING: no project ids (no ${projFile}); secret commands will fail until it is present and setup is re-run`);
    const next: Config = { ...(current?.backend === 'infisical' ? current : {}), backend: 'infisical', url, identity };
    if (projects) next.projects = projects;
    if (organizationId) next.organizationId = organizationId;
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    if (current && current.backend === 'file') {
      const keep = path.join(path.dirname(cfgPath), 'config.file-backend.json');
      fs.writeFileSync(keep, JSON.stringify(current, null, 2) + '\n');
      log(`saved the previous FileBackend config as ${keep}`);
    }
    fs.writeFileSync(cfgPath, JSON.stringify(next, null, 2) + '\n');
    log(`wrote ${cfgPath}: backend infisical, ${url}, identity ${identity}`);
  }

  if (boot) {
    fs.unlinkSync(file);
    if (fs.existsSync(file)) throw new SetupError(`could not delete ${file} — delete it by hand`);
    log(`deleted ${file}`);
  }
}
