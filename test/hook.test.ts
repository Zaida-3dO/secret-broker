import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { after, describe, it } from 'node:test';
import type { AuditEntry } from '../src/audit.js';
import { FileBackend } from '../src/backend/file.js';
import { decide, directInvocation, shq, type HookDeps, type HookInput, type HookOutput } from '../src/hook-core.js';
import { normPath } from '../src/internals.js';
import { lex } from '../src/lex.js';
import { mintTicket, type MintInput } from '../src/ticket.js';
import type { SecretBackend } from '../src/types.js';
import { HOOK, leaks, sandbox } from './helpers.js';

const sb = sandbox();
after(() => sb.cleanup());

function deps(over: Partial<HookDeps> = {}): HookDeps & { minted: MintInput[]; audits: AuditEntry[] } {
  const minted: MintInput[] = [];
  const audits: AuditEntry[] = [];
  const backend = new FileBackend(sb.secretsPath);
  // A backend whose getValues throws: proves the hook never asks for values.
  const guarded: SecretBackend = {
    listMeta: () => backend.listMeta(),
    getGrants: (s) => backend.getGrants(s),
    getValues: () => {
      throw new Error('hook must never call getValues');
    },
  };
  return {
    getBackend: () => guarded,
    mint: (i) => {
      minted.push(i);
      return mintTicket(i, { dir: path.join(sb.stateDir, 'tickets') });
    },
    audit: (e) => audits.push(e),
    invocation: 'SR',
    display: 'secretrun',
    internals: () => ({
      dirs: [normPath(path.join(sb.stateDir, 'bootstrap')), normPath(path.join(sb.stateDir, 'tickets'))],
      files: [normPath(sb.secretsPath)],
    }),
    minted,
    audits,
    ...over,
  };
}

const bash = (command: string, extra: Record<string, unknown> = {}): HookInput => ({
  session_id: 'sess-1',
  agent_id: 'agent-9',
  tool_use_id: 'tu-1',
  tool_name: 'Bash',
  tool_input: { command, ...extra },
  hook_event_name: 'PreToolUse',
});
const decision = (o: HookOutput | null) => o?.hookSpecificOutput.permissionDecision ?? null;
const reason = (o: HookOutput | null) => o?.hookSpecificOutput.permissionDecisionReason ?? '';

describe('hook decide: sentinel commands', () => {
  it('allows and rewrites, preserving every other tool_input field', async () => {
    const d = deps();
    const cmd = "curl -s -H 'Authorization: Bearer {{secret:TOK}}' https://example.com";
    const out = await decide(bash(cmd, { description: 'call api', timeout: 5000, run_in_background: true }), d);
    assert.equal(decision(out), 'allow');
    const ui = out!.hookSpecificOutput.updatedInput!;
    assert.equal(ui.description, 'call api');
    assert.equal(ui.timeout, 5000);
    assert.equal(ui.run_in_background, true);
    assert.match(ui.command as string, /^SR exec --ticket [0-9a-f]{64} -- '/);
    assert.ok((ui.command as string).endsWith(shq(cmd)));
    assert.deepEqual(d.minted[0], { sessionId: 'sess-1', agentId: 'agent-9', toolUseId: 'tu-1', names: ['TOK'], command: cmd });
    assert.equal(d.audits[0].decision, 'allow');
  });
  it('the hook output never contains a value', async () => {
    const d = deps();
    const out = await decide(bash('curl -H {{secret:TOK}} https://example.com'), d);
    assert.deepEqual(leaks(JSON.stringify(out), sb.values), []);
    const denied = await decide(bash('echo {{secret:TOK}}'), d);
    assert.deepEqual(leaks(JSON.stringify(denied), sb.values), []);
  });
  it('shq round-trips through bash quoting rules', () => {
    assert.equal(shq("a'b"), `'a'\\''b'`);
  });
  it('denies echo with a teaching reason', async () => {
    const out = await decide(bash('echo {{secret:TOK2}}'), deps());
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /`echo` is not an allowed program for TOK2/);
  });
  it('denies a quoted heredoc', async () => {
    const out = await decide(bash("cat <<'EOF'\n{{secret:TOK}}\nEOF"), deps());
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /quoted heredoc/);
  });
  it('denies an unknown secret', async () => {
    const out = await decide(bash('curl {{secret:NOPE}} https://example.com'), deps());
    assert.match(reason(out), /no secret named NOPE/);
  });
  it('denies a grant-tier secret without a grant', async () => {
    const out = await decide(bash('printf %s {{secret:GATED}}'), deps());
    assert.match(reason(out), /grant GATED to session sess-1/);
  });
  it('denies when the backend is not configured', async () => {
    const out = await decide(
      bash('curl {{secret:TOK}} https://example.com'),
      deps({
        getBackend: () => {
          throw new Error('not configured');
        },
      }),
    );
    assert.equal(decision(out), 'deny');
  });
  it('denies a malformed sentinel instead of running it literally', async () => {
    const out = await decide(bash('curl {{secret:bad name}} https://example.com'), deps());
    assert.equal(decision(out), 'deny');
  });
  it('a sentinel only in a comment passes through untouched', async () => {
    assert.equal(await decide(bash('ls # {{secret:TOK}}'), deps()), null);
  });
  it('does not mint a ticket on deny', async () => {
    const d = deps();
    await decide(bash('echo {{secret:TOK2}}'), d);
    assert.equal(d.minted.length, 0);
  });
  it('a command without a sentinel is not touched', async () => {
    assert.equal(await decide(bash('ls -la'), deps()), null);
  });
});

describe('hook decide: other tools', () => {
  it('PowerShell with a sentinel is denied with "use the Bash tool"', async () => {
    const out = await decide({ ...bash('Write-Output {{secret:TOK}}'), tool_name: 'PowerShell' }, deps());
    assert.match(reason(out), /Bash tool/);
  });
  it('PowerShell reading .env is denied', async () => {
    const out = await decide({ ...bash('Get-Content .env'), tool_name: 'PowerShell' }, deps());
    assert.match(reason(out), /\.env/);
  });
  it('Read of .env is denied and teaches {{secret:NAME}} + list', async () => {
    const out = await decide({ tool_name: 'Read', tool_input: { file_path: 'C:/p/.env.local' }, session_id: 's' }, deps());
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /\{\{secret:NAME\}\}/);
    assert.match(reason(out), /secretrun list/);
  });
  it('Read of .env.example is allowed', async () => {
    assert.equal(await decide({ tool_name: 'Read', tool_input: { file_path: 'C:/p/.env.example' } }, deps()), null);
  });
  it('Grep on .env is denied', async () => {
    const out = await decide({ tool_name: 'Grep', tool_input: { pattern: 'KEY', path: '.env' } }, deps());
    assert.equal(decision(out), 'deny');
  });
  it('Bash cat .env is denied', async () => {
    assert.equal(decision(await decide(bash('cat .env'), deps())), 'deny');
  });
});

describe('hook decide: broker internals', () => {
  const boot = path.join(sb.stateDir, 'bootstrap', 'pc-example.json');
  const fwdBoot = boot.replace(/\\/g, '/');
  const cases: [string, HookInput][] = [
    ['Read of a bootstrap credential', { tool_name: 'Read', tool_input: { file_path: boot } }],
    ['Read with forward slashes and other case', { tool_name: 'Read', tool_input: { file_path: fwdBoot.toUpperCase() } }],
    ['Grep over the tickets dir', { tool_name: 'Grep', tool_input: { pattern: 'x', path: path.join(sb.stateDir, 'tickets') } }],
    ['Read of the FileBackend JSON', { tool_name: 'Read', tool_input: { file_path: sb.secretsPath } }],
    ['Bash cat of a bootstrap file', bash(`cat "${fwdBoot}"`)],
    ['Bash ls of the generic bootstrap path', bash('ls "$LOCALAPPDATA/secret-broker/bootstrap/"')],
    ['Bash ls of the tickets dir via ~', bash('ls ~/AppData/Local/secret-broker/tickets')],
    ['Bash cat of the store by bare name from its own dir', { ...bash('cat secrets.json'), cwd: path.dirname(sb.secretsPath) }],
    ['PowerShell Get-Content of a bootstrap file', { ...bash(`Get-Content '${boot}'`), tool_name: 'PowerShell' }],
  ];
  for (const [name, input] of cases) {
    it(`denies: ${name}`, async () => {
      const out = await decide(input, deps());
      assert.equal(decision(out), 'deny', name);
      assert.match(reason(out), /secret-broker internal/);
    });
  }
  it('allows unrelated paths', async () => {
    assert.equal(await decide({ tool_name: 'Read', tool_input: { file_path: 'C:/proj/bootstrap/tickets.md' } }, deps()), null);
    assert.equal(await decide(bash('cat package.json'), deps()), null);
  });
  it('the hook process reaches the guard for a command naming only the store file', () => {
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ ...bash('cat secrets.json'), cwd: path.dirname(sb.secretsPath) }),
      env: sb.env,
      encoding: 'utf8',
    });
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });
});

describe('hook decide: direct secretrun invocation', () => {
  const cases: [string, boolean][] = [
    ['secretrun exec --ticket abc -- "ls"', true],
    ['"C:/x/secret-broker/dist/src/cli.js" exec --ticket abc -- ls', true],
    ['node C:/x/secret-broker/dist/src/cli.js exec -- ls', true],
    ['node "$f" exec --ticket abc -- ls', true],
    ['secretrun grant sess X', true],
    ['echo {} | node C:/x/secret-broker/dist/src/hook.js', true],
    ['secretrun list', false],
    ['"C:/Program Files/nodejs/node.exe" "C:/x/secret-broker/dist/src/cli.js" list', false],
    ['secretrun doctor', false],
    ['git commit -m "secretrun exec: tidy"', false],
  ];
  for (const [cmd, expected] of cases) {
    it(`${expected ? 'denies' : 'allows'}: ${cmd}`, () => {
      assert.equal(directInvocation(cmd, lex(cmd), 'C:/elsewhere/dist/src/cli.js'), expected);
    });
  }
  it('decide denies a direct exec with a friendly reason', async () => {
    const out = await decide(bash('secretrun exec --ticket ' + 'a'.repeat(64) + " -- 'ls'"), deps());
    assert.match(reason(out), /Do not call secretrun exec/);
  });
});

describe('hook process (dist/src/hook.js)', () => {
  const run = (input: string, env: NodeJS.ProcessEnv = sb.env) =>
    spawnSync(process.execPath, [HOOK], { input, env: { ...env, SECRETRUN_HOOK_TIMING: '1' }, encoding: 'utf8' });

  it('fast path: no sentinel → exit 0, no stdout', () => {
    const r = run(JSON.stringify(bash('ls -la && git status')));
    assert.equal(r.status, 0);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /secretrun-hook fast/);
  });
  it('fast path adds < 50 ms of Node work', () => {
    const work: number[] = [];
    const total: number[] = [];
    for (let i = 0; i < 5; i++) {
      const r = run(JSON.stringify(bash('npm test -- --grep something')));
      const m = /fast total=([\d.]+)ms work=([\d.]+)ms/.exec(r.stderr)!;
      total.push(Number(m[1]));
      work.push(Number(m[2]));
    }
    work.sort((a, b) => a - b);
    total.sort((a, b) => a - b);
    // `work` excludes waiting on the stdin pipe, which on a loaded machine is scheduler noise.
    assert.ok(work[2] < 50, `median work ${work[2]}ms (total ${total[2]}ms)`);
  });
  it('slow path: rewrites a sentinel command', () => {
    const r = run(JSON.stringify(bash('curl -H {{secret:TOK}} https://example.com')));
    assert.equal(r.status, 0);
    const out = JSON.parse(r.stdout) as HookOutput;
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow');
    const cmd = out.hookSpecificOutput.updatedInput!.command as string;
    assert.match(cmd, /^MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='\*' "[A-Z]:\/[^"]+node\.exe" "[A-Z]:\/[^"]+\/cli\.js" exec --ticket [0-9a-f]{64} -- '/);
    assert.ok(!cmd.includes('\\'), 'one spelling: forward slashes');
    assert.deepEqual(leaks(r.stdout + r.stderr, sb.values), []);
    const audit = fs.readFileSync(path.join(sb.stateDir, 'audit.jsonl'), 'utf8');
    assert.match(audit, /"kind":"hook".*"decision":"allow"/);
    assert.deepEqual(leaks(audit, sb.values), []);
  });
  it('fail-safe: unparseable input with a sentinel → generic deny', () => {
    const r = run('{not json {{secret:TOK}}');
    assert.equal(r.status, 0);
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });
  it('fail-safe: internal error (unreadable backend) with a sentinel → deny', () => {
    const env = { ...sb.env, SECRETRUN_CONFIG: path.join(sb.dir, 'missing.json') };
    const r = run(JSON.stringify(bash('curl -H {{secret:TOK}} https://example.com')), env);
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, 'deny');
  });
  it('fail-safe: unparseable input without a sentinel → silent exit 0', () => {
    const r = run('{not json .env');
    assert.equal(r.status, 0);
    assert.equal(r.stdout, '');
  });
});
