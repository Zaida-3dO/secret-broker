import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { after, describe, it } from 'node:test';
import { mintTicket, redeemTicket, sha256, TicketError } from '../src/ticket.js';
import { sandbox } from './helpers.js';

const sb = sandbox();
after(() => sb.cleanup());
const dir = path.join(sb.stateDir, 'tickets');
const base = { sessionId: 's1', agentId: null, toolUseId: 't1', names: ['TOK'], command: 'curl {{secret:TOK}}' };

describe('tickets', () => {
  it('mint writes a ticket file with the command hash and no command text', () => {
    const t = mintTicket(base, { dir });
    const raw = fs.readFileSync(path.join(dir, `${t.nonce}.json`), 'utf8');
    assert.equal(JSON.parse(raw).commandSha256, sha256(base.command));
    assert.ok(!raw.includes('curl'));
    assert.match(t.nonce, /^[0-9a-f]{64}$/);
  });
  it('redeem returns the ticket once', () => {
    const t = mintTicket(base, { dir });
    const r = redeemTicket(t.nonce, base.command, { dir });
    assert.deepEqual(r.names, ['TOK']);
    assert.equal(r.sessionId, 's1');
    assert.throws(() => redeemTicket(t.nonce, base.command, { dir }), /already-used/);
  });
  it('redeem rejects a different command and still consumes the ticket', () => {
    const t = mintTicket(base, { dir });
    assert.throws(() => redeemTicket(t.nonce, base.command + ' ', { dir }), /different command/);
    assert.throws(() => redeemTicket(t.nonce, base.command, { dir }), /already-used/);
  });
  it('redeem rejects an expired ticket', () => {
    const t = mintTicket(base, { dir, now: Date.now() - 121_000 });
    assert.throws(() => redeemTicket(t.nonce, base.command, { dir }), /expired/);
  });
  it('a ticket just inside its 120 s window is accepted', () => {
    const t = mintTicket(base, { dir, now: Date.now() - 119_000 });
    assert.equal(redeemTicket(t.nonce, base.command, { dir }).nonce, t.nonce);
  });
  it('rejects malformed nonces (no path traversal)', () => {
    assert.throws(() => redeemTicket('../config', base.command, { dir }), TicketError);
    assert.throws(() => redeemTicket('a'.repeat(63), base.command, { dir }), /invalid ticket/);
  });
  it('rejects an unknown nonce', () => {
    assert.throws(() => redeemTicket('f'.repeat(64), base.command, { dir }), /unknown/);
  });
  it('rejects a ticket whose file nonce differs from its name', () => {
    const t = mintTicket(base, { dir });
    const other = 'e'.repeat(64);
    fs.renameSync(path.join(dir, `${t.nonce}.json`), path.join(dir, `${other}.json`));
    assert.throws(() => redeemTicket(other, base.command, { dir }), /does not match/);
  });
  it('concurrent redeem: exactly one wins', async () => {
    const t = mintTicket(base, { dir });
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => Promise.resolve().then(() => redeemTicket(t.nonce, base.command, { dir }))),
    );
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  });
});
