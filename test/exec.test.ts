// End-to-end through the real binaries (no Claude Code): hook.js decides and rewrites, then the
// rewritten command runs in Git Bash exactly as the Bash tool would run it.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { after, describe, it } from 'node:test';
import { PassThrough } from 'node:stream';
import { pump } from '../src/exec.js';
import { gitBashPath } from '../src/paths.js';
import { mintTicket } from '../src/ticket.js';
import { CLI, HOOK, leaks, sandbox } from './helpers.js';

const bash = gitBashPath();
const sb = sandbox([
  { name: 'SHORT', policy: { tier: 'open', commands: ['printf'] }, value: 'abc' },
]);
after(() => sb.cleanup());

/** Run a model-written command the way Claude Code would: hook first, then Git Bash. */
function viaHook(command: string, opts: { input?: string; session?: string } = {}) {
  const hookIn = JSON.stringify({
    session_id: opts.session ?? 'sess-e',
    tool_use_id: 'tu',
    tool_name: 'Bash',
    tool_input: { command, description: 'x' },
  });
  const h = spawnSync(process.execPath, [HOOK], { input: hookIn, env: sb.env, encoding: 'utf8' });
  const out = h.stdout ? JSON.parse(h.stdout) : null;
  const decision = out?.hookSpecificOutput?.permissionDecision ?? 'none';
  if (decision !== 'allow') return { decision, reason: out?.hookSpecificOutput?.permissionDecisionReason ?? '', stdout: '', stderr: '', status: -1, hookRaw: h.stdout };
  const rewritten = out.hookSpecificOutput.updatedInput.command as string;
  const r = spawnSync(bash!, ['-c', rewritten], { env: sb.env, input: opts.input ?? '', encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return { decision, reason: '', stdout: r.stdout, stderr: r.stderr, status: r.status, hookRaw: h.stdout, rewritten };
}

function directExec(nonce: string, command: string) {
  return spawnSync(bash!, ['-c', `MSYS_NO_PATHCONV=1 "${process.execPath.replace(/\\/g, '/')}" "${CLI.replace(/\\/g, '/')}" exec --ticket ${nonce} -- '${command.replace(/'/g, `'\\''`)}'`], {
    env: sb.env,
    encoding: 'utf8',
  });
}

const ticketDir = path.join(sb.stateDir, 'tickets');

describe('exec via hook in Git Bash', { skip: !bash }, () => {
  it('runs the command with the value and redacts it from stdout', () => {
    const r = viaHook('printf "v=%s\\n" "{{secret:TOK}}"');
    assert.equal(r.decision, 'allow');
    assert.equal(r.stdout, 'v=[secret:TOK]\n');
    assert.equal(r.status, 0);
    assert.deepEqual(leaks(r.stdout + r.stderr + r.hookRaw, sb.values), []);
  });
  it('the program really received the value (length check without printing it)', () => {
    const r = viaHook('printf %s {{secret:TOK}} | wc -c');
    assert.equal(r.stdout.trim(), String(sb.values.TOK.length));
  });
  it('the child does not inherit the MSYS switches the rewrite sets for node', () => {
    const r = viaHook('printf "%s:%s:%s\\n" "${MSYS_NO_PATHCONV-unset}" "${MSYS2_ARG_CONV_EXCL-unset}" {{secret:TOK}}');
    assert.equal(r.decision, 'allow', r.reason);
    assert.ok(r.rewritten?.includes('MSYS_NO_PATHCONV=1'), 'precondition: the rewrite sets it for node');
    assert.equal(r.stdout, 'unset:unset:[secret:TOK]\n');
  });
  it('redacts stderr', () => {
    const r = viaHook('printf "%s" {{secret:TOK}} 1>&2');
    assert.equal(r.stderr, '[secret:TOK]');
    assert.deepEqual(leaks(r.stdout + r.stderr, sb.values), []);
  });
  it('passes the exit code through', () => {
    const r = viaHook('printf %s {{secret:TOK}} >/dev/null; bash -c "exit 7"');
    assert.equal(r.status, 7);
  });
  it('passes stdin through', () => {
    const r = viaHook('cat; printf "%s" {{secret:TOK}} >/dev/null', { input: 'hello-stdin\n' });
    assert.equal(r.stdout, 'hello-stdin\n');
  });
  it('50 KB+ of output containing the value is fully redacted', () => {
    const r = viaHook('for i in $(seq 1 2500); do printf "line %s {{secret:TOK}} end\\n" "$i"; done');
    assert.ok(r.stdout.length > 50_000, `only ${r.stdout.length} bytes`);
    assert.deepEqual(leaks(r.stdout, sb.values), []);
    assert.equal(r.stdout.split('[secret:TOK]').length - 1, 2500);
  });
  it('heredoc, single quotes and env-prefix all deliver the value', () => {
    const r = viaHook("X={{secret:TOK}} bash -c 'printf %s \"$X\"' | wc -c; printf '%s' 'a{{secret:TOK}}' | wc -c; cat <<EOF | wc -c\n{{secret:TOK}}\nEOF");
    const lens = r.stdout.trim().split(/\s+/).map(Number);
    const n = sb.values.TOK.length;
    assert.deepEqual(lens, [n, n + 1, n + 1]);
  });
  it('a tab-separated command with a POSIX path round-trips through argv', () => {
    // Git Bash rewrites some native-program arguments (`X=/tmp<TAB>printf` → `X=C:/.../tmp…`),
    // which would break the ticket hash. Probing found no sentinel-bearing argument it rewrites, so
    // this passes with or without MSYS_NO_PATHCONV; the prefix itself is pinned by the hook test.
    const r = viaHook('X=/tmp;printf	%s	{{secret:TOK2}}');
    assert.equal(r.decision, 'allow');
    assert.equal(r.stdout, '[secret:TOK2]', r.stderr);
  });
  it('policy denies echo before anything runs', () => {
    const r = viaHook('echo {{secret:TOK2}}');
    assert.equal(r.decision, 'deny');
  });
});

describe('exec refusals', { skip: !bash }, () => {
  it('refuses a fake ticket', () => {
    const r = directExec('a'.repeat(64), 'printf %s {{secret:TOK}}');
    assert.equal(r.status, 126);
    assert.match(r.stderr, /unknown or already-used ticket/);
    assert.deepEqual(leaks(r.stdout + r.stderr, sb.values), []);
  });
  it('refuses a replayed ticket', () => {
    const cmd = 'printf %s {{secret:TOK}}';
    const t = mintTicket({ sessionId: 's', agentId: null, toolUseId: null, names: ['TOK'], command: cmd }, { dir: ticketDir });
    assert.equal(directExec(t.nonce, cmd).status, 0);
    const again = directExec(t.nonce, cmd);
    assert.equal(again.status, 126);
  });
  it('refuses a ticket for a different command', () => {
    const t = mintTicket({ sessionId: 's', agentId: null, toolUseId: null, names: ['TOK'], command: 'printf %s {{secret:TOK}}' }, { dir: ticketDir });
    const r = directExec(t.nonce, 'printf %s {{secret:TOK}} | base64');
    assert.equal(r.status, 126);
    assert.match(r.stderr, /different command/);
  });
  it('re-checks policy even with a valid ticket (hand-forged ticket for echo)', () => {
    const cmd = 'echo {{secret:TOK2}}';
    const t = mintTicket({ sessionId: 's', agentId: null, toolUseId: null, names: ['TOK2'], command: cmd }, { dir: ticketDir });
    const r = directExec(t.nonce, cmd);
    assert.equal(r.status, 126);
    assert.match(r.stderr, /not an allowed program/);
    assert.deepEqual(leaks(r.stdout + r.stderr, sb.values), []);
  });
  it('refuses when the ticket names differ from the command', () => {
    const cmd = 'printf %s {{secret:TOK2}}';
    const t = mintTicket({ sessionId: 's', agentId: null, toolUseId: null, names: ['TOK'], command: cmd }, { dir: ticketDir });
    assert.match(directExec(t.nonce, cmd).stderr, /different secrets/);
  });
  it('refuses a grant-tier secret without a grant, and allows it with one', () => {
    const cmd = 'printf %s {{secret:GATED}}';
    const t = mintTicket({ sessionId: 'gs', agentId: null, toolUseId: null, names: ['GATED'], command: cmd }, { dir: ticketDir });
    assert.match(directExec(t.nonce, cmd).stderr, /grant-tier/);
    const g = spawnSync(process.execPath, [CLI, 'grant', 'gs', 'GATED', '--ttl', '1m'], { env: sb.env, encoding: 'utf8' });
    assert.equal(g.status, 0, g.stderr);
    const t2 = mintTicket({ sessionId: 'gs', agentId: null, toolUseId: null, names: ['GATED'], command: cmd }, { dir: ticketDir });
    const r = directExec(t2.nonce, cmd);
    assert.equal(r.stdout, '[secret:GATED]');
  });
  it('refuses a secret too short to redact', () => {
    const cmd = 'printf %s {{secret:SHORT}}';
    const t = mintTicket({ sessionId: 's', agentId: null, toolUseId: null, names: ['SHORT'], command: cmd }, { dir: ticketDir });
    const r = directExec(t.nonce, cmd);
    assert.equal(r.status, 126);
    assert.ok(!r.stdout.includes('abc'));
  });
  it('rejects a malformed exec argv', () => {
    const r = spawnSync(process.execPath, [CLI, 'exec', '--session', 'x', '--', 'ls'], { env: sb.env, encoding: 'utf8' });
    assert.equal(r.status, 126);
  });
  it('writes exec audit lines without values', () => {
    const audit = fs.readFileSync(path.join(sb.stateDir, 'audit.jsonl'), 'utf8');
    assert.match(audit, /"kind":"exec".*"decision":"run"/);
    assert.match(audit, /"kind":"exec".*"decision":"refuse"/);
    assert.deepEqual(leaks(audit, sb.values), []);
  });
});

describe('exec stream pump (idle flush)', () => {
  // Records the calls exec makes on a redactor: the hold-back itself is the redactor's job.
  function recorder() {
    const calls: string[] = [];
    return {
      calls,
      push: (c: Buffer) => {
        calls.push(`push:${c.toString()}`);
        return Buffer.alloc(0);
      },
      flush: () => {
        calls.push('flush');
        return Buffer.from('F');
      },
    };
  }
  it('chunks closer together than the idle window are not flushed between', async () => {
    const src = new PassThrough();
    const dst = new PassThrough();
    const red = recorder();
    const done = pump(src, dst, red, 100);
    src.write('a');
    await new Promise((r) => setTimeout(r, 30));
    src.write('b');
    await new Promise((r) => setTimeout(r, 30));
    assert.deepEqual(red.calls, ['push:a', 'push:b']);
    await new Promise((r) => setTimeout(r, 150));
    assert.deepEqual(red.calls, ['push:a', 'push:b', 'flush'], 'one idle flush after 100 ms of silence');
    src.end();
    await done;
    assert.deepEqual(red.calls, ['push:a', 'push:b', 'flush', 'flush'], 'and a final flush at end');
    assert.equal(dst.read()?.toString(), 'FF');
  });
});

describe('cli', () => {
  it('list shows names and policy, never values', () => {
    const r = spawnSync(process.execPath, [CLI, 'list'], { env: sb.env, encoding: 'utf8' });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /TOK {2}\[open\]/);
    assert.match(r.stdout, /hosts: {4}example\.com/);
    assert.deepEqual(leaks(r.stdout, sb.values), []);
  });
  it('scrub redacts every visible value from stdin', () => {
    const input = `a ${sb.values.TOK} b ${sb.values.HOSTED} c ${sb.values.GATED}\n`;
    const r = spawnSync(process.execPath, [CLI, 'scrub'], { env: sb.env, input, encoding: 'utf8' });
    assert.equal(r.stdout, 'a [secret:TOK] b [secret:HOSTED] c [secret:GATED]\n');
  });
  it('hook-snippet prints absolute paths, both matchers and timeout 10', () => {
    const r = spawnSync(process.execPath, [CLI, 'hook-snippet'], { env: sb.env, encoding: 'utf8' });
    const s = JSON.parse(r.stdout);
    const pre = s.hooks.PreToolUse;
    assert.deepEqual(pre.map((e: { matcher: string }) => e.matcher), ['Bash', 'Read|Grep|PowerShell']);
    assert.equal(pre[0].hooks[0].timeout, 10);
    assert.match(pre[0].hooks[0].command, /^"[A-Z]:\/.+node\.exe" "[A-Z]:\/.+\/hook\.js"$/);
  });
  it('doctor runs read-only and reports the backend', () => {
    const r = spawnSync(process.execPath, [CLI, 'doctor'], { env: sb.env, encoding: 'utf8' });
    assert.match(r.stdout, /backend reachable, 5 secret/);
    assert.deepEqual(leaks(r.stdout, sb.values), []);
  });
});
