// Backend selection from %APPDATA%\secret-broker\config.json (or SECRETRUN_CONFIG):
//   { "backend": "file", "file": "C:/path/to/dev-secrets.json" }
//   { "backend": "infisical", "url": "https://vault.example.internal", "identity": "pc-example", "environment": "prod",
//     "projects": { "open": "<id>", "logins": "<id>", "grant": { "default": "<id>" } } }   (written by `secretrun setup`)
import * as fs from 'node:fs';
import { configPath } from '../paths.js';
import type { SecretBackend } from '../types.js';
import { FileBackend } from './file.js';
import { InfisicalBackend, type InfisicalProjects } from './infisical.js';

export interface Config {
  backend: 'file' | 'infisical';
  /** FileBackend (dev): path of the secrets JSON. */
  file?: string;
  /** InfisicalBackend: base URL and machine identity (credential in Credential Manager, see keyring.ts). */
  url?: string;
  identity?: string;
  /** Infisical environment slug (default prod). */
  environment?: string;
  projects?: InfisicalProjects;
  organizationId?: string;
  /** Browser identity for `secretrun broker-resolve` (default browser-<machine>). */
  browserIdentity?: string;
  ticketTtlSeconds?: number;
  [k: string]: unknown;
}

export class NotConfiguredError extends Error {}

export function loadConfig(): Config {
  const p = configPath();
  let raw: string;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch {
    throw new NotConfiguredError(`secret-broker is not configured (no ${p})`);
  }
  try {
    return JSON.parse(raw) as Config;
  } catch {
    throw new NotConfiguredError(`secret-broker config ${p} is not valid JSON`);
  }
}

export function getBackend(cfg: Config = loadConfig()): SecretBackend {
  switch (cfg.backend) {
    case 'file':
      if (!cfg.file) throw new NotConfiguredError('config: backend "file" needs "file"');
      return new FileBackend(cfg.file);
    case 'infisical':
      if (!cfg.url || !cfg.identity) throw new NotConfiguredError('config: backend "infisical" needs "url" and "identity"');
      if (!cfg.projects?.open) throw new NotConfiguredError('config: backend "infisical" needs "projects.open" — re-run `secretrun setup`');
      return new InfisicalBackend({ url: cfg.url, identity: cfg.identity, environment: cfg.environment, projects: cfg.projects });
    default:
      throw new NotConfiguredError(`config: unknown backend ${JSON.stringify((cfg as Config).backend)}`);
  }
}
