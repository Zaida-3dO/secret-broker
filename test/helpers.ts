import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/** dist/src — where the compiled cli.js and hook.js live. */
export const DIST_SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');
export const CLI = path.join(DIST_SRC, 'cli.js');
export const HOOK = path.join(DIST_SRC, 'hook.js');

export function dummy(): string {
  return `DUMMY-SECRET-${randomBytes(12).toString('hex')}`;
}

export interface Sandbox {
  dir: string;
  stateDir: string;
  configPath: string;
  secretsPath: string;
  values: Record<string, string>;
  env: NodeJS.ProcessEnv;
  cleanup(): void;
}

/** Temp dir with a FileBackend secrets file, config and state dir. */
export function sandbox(extra: { name: string; policy: unknown; value?: string }[] = []): Sandbox {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretrun-test-'));
  const stateDir = path.join(dir, 'state');
  const secretsPath = path.join(dir, 'secrets.json');
  const configPath = path.join(dir, 'config.json');
  const values: Record<string, string> = {};
  const secrets = [
    { name: 'TOK', policy: { tier: 'open', commands: ['curl', 'printf', 'cat', 'head', 'bash', 'sleep', 'seq', 'wc', 'jq', 'tail'], hosts: [] } },
    { name: 'TOK2', policy: { tier: 'open', commands: ['printf', 'cat'] } },
    { name: 'GATED', policy: { tier: 'grant', commands: ['printf'] } },
    { name: 'HOSTED', policy: { tier: 'open', commands: ['curl'], hosts: ['example.com'] } },
    ...extra,
  ].map((s) => {
    const value = (s as { value?: string }).value ?? dummy();
    values[s.name] = value;
    return { name: s.name, value, policy: s.policy };
  });
  fs.writeFileSync(secretsPath, JSON.stringify({ secrets, grants: [] }, null, 2));
  fs.writeFileSync(configPath, JSON.stringify({ backend: 'file', file: secretsPath }));
  const env = { ...process.env, SECRETRUN_CONFIG: configPath, SECRETRUN_STATE_DIR: stateDir };
  return {
    dir,
    stateDir,
    configPath,
    secretsPath,
    values,
    env,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** Assert no value of the sandbox appears in text (also checks common encodings of it). */
export function leaks(text: string, values: Record<string, string>): string[] {
  const hits: string[] = [];
  for (const [name, v] of Object.entries(values)) {
    if (text.includes(v) || text.includes(Buffer.from(v).toString('base64'))) hits.push(name);
  }
  return hits;
}
