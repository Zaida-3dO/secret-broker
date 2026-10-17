// The PC's Infisical machine credential in Windows Credential Manager (design §3 rule 8).
//
// Always `new Entry(service, user)` — NEVER `Entry.withTarget(...)`: on an existing cmdkey
// credential it returned "" and blanked the stored blob (verified on Claude Code 2.1.183). Write with the same library
// that reads. `@napi-rs/keyring` is imported lazily so the FileBackend path never loads it.
//
// InfisicalBackend reads its credential (and caches its access token) through this module.

export const KEYRING_SERVICE = 'secret-broker';

export interface MachineCredential {
  clientId: string;
  clientSecret: string;
}

/** Minimal store interface — the native keyring in production, a fake in tests. */
export interface KeyringStore {
  set(account: string, secret: string): void;
  get(account: string): string | null;
  delete(account: string): boolean;
}

export function keyringAccount(identity: string): string {
  return `infisical-${identity}`;
}

export async function nativeKeyring(): Promise<KeyringStore> {
  const { Entry } = await import('@napi-rs/keyring');
  const entry = (account: string) => new Entry(KEYRING_SERVICE, account);
  return {
    set: (account, secret) => entry(account).setPassword(secret),
    get: (account) => entry(account).getPassword() ?? null,
    delete: (account) => entry(account).deletePassword(),
  };
}

export function encodeCredential(c: MachineCredential): string {
  return JSON.stringify({ clientId: c.clientId, clientSecret: c.clientSecret });
}

/** Read the stored machine credential for an identity. Errors never include the secret. */
export async function readMachineCredential(identity: string, store?: KeyringStore): Promise<MachineCredential> {
  const s = store ?? (await nativeKeyring());
  const raw = s.get(keyringAccount(identity));
  if (!raw) throw new Error(`no machine credential for ${identity} in Credential Manager — run \`secretrun setup\``);
  let parsed: Partial<MachineCredential>;
  try {
    parsed = JSON.parse(raw) as Partial<MachineCredential>;
  } catch {
    throw new Error(`the stored machine credential for ${identity} is not readable — re-run \`secretrun setup\``);
  }
  if (typeof parsed.clientId !== 'string' || typeof parsed.clientSecret !== 'string') {
    throw new Error(`the stored machine credential for ${identity} is incomplete — re-run \`secretrun setup\``);
  }
  return { clientId: parsed.clientId, clientSecret: parsed.clientSecret };
}
