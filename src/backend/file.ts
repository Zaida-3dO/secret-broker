// FileBackend — DEV/TEST ONLY. INSECURE: values sit in a plaintext JSON file that any process
// running as this user can read. Use it with dummy values (`DUMMY-SECRET-<hex>`) only; real
// secrets belong in Infisical (InfisicalBackend, a later task).
//
// File shape: { "secrets": [{ "name", "value", "policy": SecretPolicy | null }], "grants": [Grant] }
import * as fs from 'node:fs';
import type { Grant, SecretBackend, SecretMeta, SecretPolicy, SecretValue } from '../types.js';

interface FileSecret {
  name: string;
  value: string;
  policy?: SecretPolicy | null;
}

interface FileShape {
  secrets: FileSecret[];
  grants?: Grant[];
}

export class FileBackend implements SecretBackend {
  constructor(readonly file: string) {}

  private read(): FileShape {
    let raw: string;
    try {
      raw = fs.readFileSync(this.file, 'utf8');
    } catch (e) {
      throw new Error(`FileBackend: cannot read ${this.file} (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
    }
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch {
      // Never include the parse error: its message quotes file content, which may be a value.
      throw new Error(`FileBackend: ${this.file} is not valid JSON`);
    }
    const d = data as Partial<FileShape>;
    if (!d || !Array.isArray(d.secrets)) throw new Error(`FileBackend: ${this.file} has no "secrets" array`);
    return { secrets: d.secrets, grants: Array.isArray(d.grants) ? d.grants : [] };
  }

  async listMeta(): Promise<SecretMeta[]> {
    return this.read().secrets.map((s) => ({ name: s.name, policy: normalisePolicy(s.policy) }));
  }

  async getValues(names: string[]): Promise<SecretValue[]> {
    const all = this.read().secrets;
    const missing: string[] = [];
    const out: SecretValue[] = [];
    for (const n of names) {
      const s = all.find((x) => x.name === n);
      if (!s || typeof s.value !== 'string') missing.push(n);
      else out.push({ name: n, value: s.value });
    }
    if (missing.length) throw new Error(`no value for secret(s): ${missing.join(', ')}`);
    return out;
  }

  async getGrants(sessionId: string): Promise<Grant[]> {
    const now = Date.now();
    return (this.read().grants ?? []).filter(
      (g) => g.sessionId === sessionId && Date.parse(g.expiresAt) > now,
    );
  }

  /** Dev only — the real grant path is the operator's Infisical login (design §4). */
  addGrant(grant: Grant): void {
    const d = this.read();
    d.grants = [...(d.grants ?? []), grant];
    fs.writeFileSync(this.file, JSON.stringify(d, null, 2) + '\n', 'utf8');
  }
}

function normalisePolicy(p: SecretPolicy | null | undefined): SecretPolicy | null {
  if (!p || (p.tier !== 'open' && p.tier !== 'grant')) return null;
  const list = (v: unknown) =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : undefined;
  return {
    tier: p.tier,
    commands: list(p.commands),
    hosts: list(p.hosts),
    description: typeof p.description === 'string' ? p.description : undefined,
  };
}
