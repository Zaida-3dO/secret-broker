// Shared contracts between the hook, the CLI, the backends and the redactor.
// See docs/design.md.

/** Per-secret usage policy (design §5). A secret with no policy is denied. */
export interface SecretPolicy {
  tier: 'open' | 'grant';
  /** Program names allowed in a command that carries this secret. Every simple command must match. */
  commands?: string[];
  /** Hosts allowed where visible in argv (e.g. curl URLs). */
  hosts?: string[];
  description?: string;
}

/** What the hook may know: names and policy only. Never a value. */
export interface SecretMeta {
  name: string;
  policy: SecretPolicy | null;
}

export interface SecretValue {
  name: string;
  value: string;
}

/** design §4 */
export interface Grant {
  secret: string;
  sessionId: string;
  expiresAt: string; // ISO
  grantedBy: string;
}

/** Vault abstraction. FileBackend for dev/tests; InfisicalBackend later. */
export interface SecretBackend {
  /** Names + policy for every secret this identity can see. Must not return values. */
  listMeta(): Promise<SecretMeta[]>;
  /** Values for exactly these names. Throws naming (never revealing) any it cannot resolve. */
  getValues(names: string[]): Promise<SecretValue[]>;
  /** Live (unexpired) grants for a session. */
  getGrants(sessionId: string): Promise<Grant[]>;
}

/** design §3 rule 4 */
export interface Ticket {
  nonce: string;
  sessionId: string;
  agentId: string | null;
  toolUseId: string | null;
  names: string[];
  commandSha256: string;
  expiresAt: string; // ISO
}

/** design §6 */
export interface Redactor {
  push(chunk: Buffer): Buffer;
  flush(): Buffer;
}
