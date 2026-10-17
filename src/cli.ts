#!/usr/bin/env node
// secretrun — see docs/operations.md.
//
//   secretrun exec --ticket <nonce> -- '<command>'   (emitted by the hook; never typed by hand)
//   secretrun list [--json]                          names, tier, commands, hosts, description
//   secretrun scrub                                  stdin → stdout with every visible value redacted
//   secretrun doctor                                 read-only health check
//   secretrun hook-snippet                           print the settings.json hook registration
//   secretrun grant <session> <NAME> [--ttl 8h] [--group g] [--identity pc-x] [--dry-run]
//                                                    Operator only: Infisical two-layer grant (design §4); dev record on FileBackend
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { getBackend, loadConfig } from './backend/index.js';
import { FileBackend } from './backend/file.js';
import { runExec } from './exec.js';
import { configPath, fwd, gitBashPath, hookPath, secretrunDisplay, stateDir } from './paths.js';
import { runSetup } from './setup.js';
import { GrantError, runInfisicalGrant, ttyPrompt } from './grant.js';
import { brokerResolve } from './broker-resolve.js';
import { hookSnippet } from './snippet.js';
import { createRedactor } from './redact/index.js';
import type { SecretValue } from './types.js';

const USAGE = `usage: secretrun <list|scrub|doctor|hook-snippet|grant|exec> ...
  list [--json]                       secrets you can use by name ({{secret:NAME}} in a Bash command)
  scrub                               copy stdin to stdout with every known value redacted
  doctor                              check the install (read-only)
  hook-snippet                        print the ~/.claude/settings.json hook registration
  grant <session> <NAME> [--ttl 8h] [--group g] [--identity pc-x] [--dry-run]
                                      The operator, in their own terminal: grant a grant-tier secret to a session
                                      (asks for your Infisical login; FileBackend: dev record)
  setup [--identity pc-x] [--switch-backend] [--dry-run]
                                      The operator, once per PC: move the bootstrap machine credential into
                                      Credential Manager and delete the bootstrap file
  exec --ticket <nonce> -- '<cmd>'    run by the hook's rewrite; not for direct use
  broker-resolve resolve <NAME>       browser-broker's BROKER_SECRET_RESOLVER; prints a value — never for agents`;

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case 'exec':
      return execCmd(rest);
    case 'list':
      return listCmd(rest);
    case 'scrub':
      return scrubCmd();
    case 'doctor':
      return doctorCmd();
    case 'hook-snippet':
      process.stdout.write(JSON.stringify(hookSnippet(), null, 2) + '\n');
      return 0;
    case 'grant':
      return grantCmd(rest);
    case 'setup':
      return setupCmd(rest);
    case 'broker-resolve':
      return brokerResolveCmd(rest);
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      process.stdout.write(USAGE + '\n');
      return cmd === undefined ? 2 : 0;
    default:
      process.stderr.write(`secretrun: unknown command ${JSON.stringify(cmd)}\n${USAGE}\n`);
      return 2;
  }
}

async function execCmd(args: string[]): Promise<number> {
  if (args.length !== 4 || args[0] !== '--ticket' || args[2] !== '--') {
    process.stderr.write(
      "secretrun: refused: exec is run by the secret-broker hook. Write {{secret:NAME}} in a Bash command instead.\n",
    );
    return 126;
  }
  return runExec({ ticket: args[1], command: args[3] });
}

async function listCmd(args: string[]): Promise<number> {
  const metas = await getBackend().listMeta();
  const rows = metas
    .map((m) => ({
      name: m.name,
      tier: m.policy?.tier ?? '(no policy — unusable)',
      commands: m.policy?.commands ?? [],
      hosts: m.policy?.hosts ?? [],
      description: m.policy?.description ?? '',
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  if (args.includes('--json')) {
    process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
    return 0;
  }
  if (!rows.length) {
    process.stdout.write('No secrets are available to this machine.\n');
    return 0;
  }
  process.stdout.write('Use a secret by name in a Bash command: {{secret:NAME}} (the value is injected and redacted).\n\n');
  for (const r of rows) {
    process.stdout.write(`${r.name}  [${r.tier}]\n`);
    if (r.description) process.stdout.write(`    ${r.description}\n`);
    process.stdout.write(`    commands: ${r.commands.join(', ') || '(none)'}\n`);
    if (r.hosts.length) process.stdout.write(`    hosts:    ${r.hosts.join(', ')}\n`);
  }
  return 0;
}

async function scrubCmd(): Promise<number> {
  const backend = getBackend();
  const metas = await backend.listMeta();
  const values: SecretValue[] = [];
  for (const m of metas) {
    try {
      values.push(...(await backend.getValues([m.name])));
    } catch {
      /* not visible to this identity right now (e.g. grant tier outside a window) */
    }
  }
  const usable = values.filter((v) => v.value.length >= 8);
  const short = values.filter((v) => v.value.length < 8).map((v) => v.name);
  if (short.length) process.stderr.write(`secretrun scrub: not redacting (shorter than 8 chars): ${short.join(', ')}\n`);
  const red = createRedactor(usable);
  await new Promise<void>((resolve, reject) => {
    process.stdin.on('data', (c: Buffer) => {
      const out = red.push(c);
      if (out.length) process.stdout.write(out);
    });
    process.stdin.on('end', () => {
      const out = red.flush();
      if (out.length) process.stdout.write(out);
      resolve();
    });
    process.stdin.on('error', reject);
  });
  return 0;
}

async function doctorCmd(): Promise<number> {
  let ok = true;
  const line = (good: boolean, msg: string) => {
    if (!good) ok = false;
    process.stdout.write(`${good ? 'ok  ' : 'FAIL'}  ${msg}\n`);
  };
  process.stdout.write(`secretrun: ${secretrunDisplay()}\n`);
  line(fs.existsSync(hookPath()), `hook script ${fwd(hookPath())}`);
  const bash = gitBashPath();
  line(!!bash, `Git Bash ${bash ? fwd(bash) : 'not found (set CLAUDE_CODE_GIT_BASH_PATH)'}`);
  try {
    const cfg = loadConfig();
    line(true, `config ${fwd(configPath())} (backend: ${cfg.backend})`);
    if (cfg.backend === 'file') process.stdout.write('      WARNING: FileBackend stores values in plaintext — dev/test only.\n');
    const metas = await getBackend(cfg).listMeta();
    line(true, `backend reachable, ${metas.length} secret(s) visible`);
    const noPolicy = metas.filter((m) => !m.policy).map((m) => m.name);
    if (noPolicy.length) process.stdout.write(`      note: no policy (unusable): ${noPolicy.join(', ')}\n`);
  } catch (e) {
    line(false, `backend: ${(e as Error).message}`);
  }
  try {
    fs.mkdirSync(stateDir(), { recursive: true });
    fs.accessSync(stateDir(), fs.constants.W_OK);
    line(true, `state dir ${fwd(stateDir())}`);
  } catch {
    line(false, `state dir ${fwd(stateDir())} not writable`);
  }
  const settings = path.join(os.homedir(), '.claude', 'settings.json');
  let registered = false;
  try {
    const s = JSON.parse(fs.readFileSync(settings, 'utf8')) as { hooks?: { PreToolUse?: unknown[] } };
    registered = JSON.stringify(s.hooks?.PreToolUse ?? []).includes(fwd(hookPath()).replace(/"/g, ''));
  } catch {
    /* unreadable → not registered */
  }
  line(registered, `hook registered in ${fwd(settings)}${registered ? '' : ' — run `secretrun hook-snippet` for the entry (installing is a manual step)'}`);
  return ok ? 0 : 1;
}

async function setupCmd(args: string[]): Promise<number> {
  const val = (flag: string) => {
    const i = args.indexOf(flag);
    return i === -1 ? undefined : args[i + 1];
  };
  try {
    await runSetup({
      identity: val('--identity'),
      bootstrapDir: val('--bootstrap-dir'),
      switchBackend: args.includes('--switch-backend'),
      dryRun: args.includes('--dry-run'),
    });
    return 0;
  } catch (e) {
    process.stderr.write(`secretrun setup: ${(e as Error).message}
`);
    return 1;
  }
}

async function brokerResolveCmd(args: string[]): Promise<number> {
  const rest = args[0] === 'resolve' ? args.slice(1) : args;
  if (rest.length !== 1) {
    process.stderr.write('usage: secretrun broker-resolve resolve <NAME>\n');
    return 2;
  }
  try {
    const r = await brokerResolve(rest[0]);
    process.stdout.write(JSON.stringify(r));
    return 0;
  } catch (e) {
    // stderr is discarded by browser-broker; messages here never carry a value anyway.
    process.stderr.write(`secretrun broker-resolve: ${(e as Error).message}\n`);
    return 1;
  }
}

async function grantCmd(args: string[]): Promise<number> {
  const [sessionId, name, ...opts] = args;
  if (!sessionId || !name || sessionId.startsWith('-') || name.startsWith('-')) {
    process.stderr.write('usage: secretrun grant <session> <NAME> [--ttl 8h] [--group g] [--identity pc-x] [--dry-run]\n');
    return 2;
  }
  const val = (flag: string) => {
    const i = opts.indexOf(flag);
    return i === -1 ? undefined : opts[i + 1];
  };
  let ttlMs = 8 * 3600_000;
  if (opts.includes('--ttl')) {
    const m = /^(\d+)([smhd])$/.exec(val('--ttl') ?? '');
    if (!m || Number(m[1]) <= 0) {
      process.stderr.write('secretrun grant: --ttl takes e.g. 30m, 8h, 1d\n');
      return 2;
    }
    ttlMs = Number(m[1]) * { s: 1000, m: 60_000, h: 3600_000, d: 86_400_000 }[m[2] as 's' | 'm' | 'h' | 'd'];
  }
  const cfg = loadConfig();
  if (cfg.backend === 'infisical') {
    try {
      await runInfisicalGrant({
        cfg,
        sessionId,
        name,
        ttlMs,
        group: val('--group'),
        identity: val('--identity'),
        dryRun: opts.includes('--dry-run'),
        prompt: ttyPrompt,
      });
      return 0;
    } catch (e) {
      process.stderr.write(`secretrun grant: ${(e as Error).message}\n`);
      return e instanceof GrantError ? 2 : 1;
    }
  }
  if (cfg.backend !== 'file' || !cfg.file) {
    process.stderr.write('secretrun grant: unsupported backend\n');
    return 2;
  }
  const fb = new FileBackend(cfg.file);
  const metas = await fb.listMeta();
  if (!metas.some((m) => m.name === name)) {
    process.stderr.write(`secretrun grant: no secret named ${name}\n`);
    return 1;
  }
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  fb.addGrant({ secret: name, sessionId, expiresAt, grantedBy: os.userInfo().username });
  process.stdout.write(`granted ${name} to session ${sessionId} until ${expiresAt} (DEV FileBackend)\n`);
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    // Messages from our own code never carry values; still, keep it to one line, no stack.
    process.stderr.write(`secretrun: error: ${(e as Error)?.message ?? 'unknown'}\n`);
    process.exitCode = 1;
  },
);
