# secret-broker — design v2

Agents use secrets **by name, never by value**. An agent writes `{{secret:NAME}}` in a Bash
command; the real value is injected at execution time inside `secretrun`, and never enters the
model's context, the session transcript, hook logs, or external telemetry.

Facts marked "probe" or "verified" below were established empirically on Claude Code 2.1.183 and
Infisical 0.166.x.

---

## 1. Threat model — read this first

**Protects against accidental leaks:** secret values landing in transcripts (`~/.claude/projects/**`),
`tool-results/*.txt`, `tasks/*.output`, debug logs, subagent transcripts, any server
or local telemetry spool a hook feeds, chat logs committed to git; agents `cat`-ing `.env` files.

**Does not protect against a deliberately hostile / prompt-injected agent.** It runs as the same
Windows user, so it can transform output (`tr`, `rev`, base64), write values to files, read process
environments, read the user's credential store, or exfiltrate over the network. Every control below
that a same-user process could defeat is a **speed bump that turns an accident into a deliberate
act**, and is described as such. Scoped, least-privilege agent credentials are what limit the blast
radius when that happens.

## 2. Components

| Component | Where | Role |
|---|---|---|
| **Infisical** (self-hosted, v0.166.x) | operator-hosted; e.g. `vault.example.internal`, reachable from the PCs only on a private network | Source of truth. **Scope by project — folder-level access control is paid**: `agents-open` (open-tier secrets + `/grants` records), `agents-logins` (browser), one `agents-grant-<group>` project per grant group, `containers` (a render identity only). PC identities hold `viewer` (read-only, verified 403 on writes). |
| **`secretrun`** | this repo; Node ≥ 22, TypeScript compiled to `dist/` | Ticket redemption, policy, fetch, sentinel substitution, spawn Git Bash, **redact at source**, audit. |
| **Hook** `secretrun-hook` | this repo; registered in **user-level** `~/.claude/settings.json` (all repos) | PreToolUse on `Bash` (narrow matcher, explicit `timeout: 10`). Rewrites sentinel commands, mints tickets, decides allow/deny, guards `.env*`. |
| **Backend interface** | `src/backend/` | `SecretBackend`. `FileBackend` (dev/tests) and `InfisicalBackend`. |
| **Redactor** | `src/redact/` | Streaming redaction library. |
| **Browser resolver** | `secretrun broker-resolve` | Resolves `{{secret:login/…}}` at a browser tool's fill sinks via a `BROKER_SECRET_RESOLVER` command (generic contract). |

**Not an MCP server**, deliberately: an MCP result lands in model context, which is where a value
must never be.

## 3. The Bash path, end to end

```
model writes:   curl -s -H "Authorization: Bearer {{secret:CF_API_TOKEN}}" https://api.cloudflare.com/client/v4/user/tokens/verify
hook (Pre):     1. sees the RAW command (it is never re-fed its own rewrite — probe #6)
                2. names = [CF_API_TOKEN]; load policy metadata (names + policy only, never values)
                3. policy check (command shape, host, tier/grant)  -> deny with reason, or continue
                4. mint ticket {nonce, session_id, agent_id, tool_use_id, names, sha256(original cmd), exp ≈ 30s}
                5. emit updatedInput.command = "<ABS>/secretrun" exec --ticket <nonce> -- '<original, single-quoted>'
                   + permissionDecision: "allow"            (probe #1/#2: required; the hook IS the policy point)
secretrun:      redeem ticket (consume; verify cmd hash, expiry) -> resolve grants -> fetch values
                -> lex + substitute sentinels by quote context -> spawn Git Bash with values in env only
                -> stream stdout/stderr through redactor -> exit code passthrough -> audit line
model sees:     the API response, with any value occurrence replaced by [secret:CF_API_TOKEN]
```

### Hard rules (each is a probe result)
1. **Absolute path to `secretrun`** in the emitted command — the Bash tool's PATH comes from Claude
   Code's shell snapshot, not the launching environment (probe #1, "command not found"). The
   installer fixes one canonical path; always emit it in one spelling (Windows `C:/…` form).
2. **The hook returns `permissionDecision`** on every sentinel command: `allow`, or `deny` with a
   reason. Permission rules are evaluated on the *rewritten* string, so the user's existing
   `Bash(…)` allow rules do not apply to secret commands — the hook is the policy point.
3. **`ask` only when a human is present.** In `-p` and bypass sessions `ask` acts as a hard deny
   (probe #2). Unattended "needs the operator" → `deny` with a reason that tells the agent how to request a
   grant. **No reason text may ever contain a value** — the model sees it.
4. **Tickets, not `--session`.** `secretrun` never trusts a session id given on its command line —
   probe #6 bypassed a string-match deny with `node "$f" exec --session OTHER …`. The hook mints a
   random single-use ticket bound to `{session_id, agent_id, tool_use_id, names, sha256(command),
   expiry}`; `secretrun exec` refuses without a valid unconsumed ticket whose hash matches the
   command it was given. The nonce appears in the transcript's `hook_success` record but is consumed
   before the model can reuse it. Ticket store: `%LOCALAPPDATA%\secret-broker\tickets\` (owner-only
   ACL). Same-user forging remains possible — a speed bump, per §1. The string-match deny of direct
   `secretrun` calls stays, as a friendly fast error, not as the control.
5. **The hook never fetches, holds, or prints a value.** Its stdout is persisted in the transcript
   (`hook_success`), debug logs, `-p` permission denials, and handed to every PostToolUse hook —
   including any other PostToolUse hook, such as one that ships commands to an external service.
6. **Redaction happens inside `secretrun`, streamed, with a hold-back window** — so
   `tool-results/*.txt` (>30k output), `tasks/*.output` (background commands, read later with
   Read/cat on 2.1.183) and any other hook all see clean bytes (probe #8). No PostToolUse hook is
   needed for Bash.
7. **Redaction is a backstop, not the control.** Transforms like `tr a-z A-Z` pass straight through
   (probe). The primary control is policy on the *command shape* (§5). The redactor still covers
   cheap encodings (§6).
8. **Native keyring.** The PC's Infisical machine credential lives in Windows Credential Manager,
   read and written with `@napi-rs/keyring` `new Entry(service, user)` (~1.5 ms vs 0.6–1.8 s via
   PowerShell). **Never** `Entry.withTarget` on an existing cmdkey credential — it blanked the blob.
   Write with the same library that reads.
9. **Latency budget.** The hook runs on every Bash call (~0.3–0.65 s idle, measured under load).
   Keep it one small Node script that does a cheap substring test for `{{secret:` / `.env` first and
   exits immediately otherwise; do no keyring/network work in the hook. Explicit `timeout: 10`.
10. **Drop `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`** — on 2.1.183 it strips only two vars and forces
    bypass sessions back to default mode (probe #4).

### Sentinel substitution (lexer)
Sentinel grammar: `{{secret:NAME}}`, `NAME` = `[A-Za-z0-9_./-]{1,128}`.
Rewrite each sentinel to `"${__SR_<i>}"` according to its quote context:
- unquoted → `"${__SR_i}"`; inside double quotes → `${__SR_i}`;
- inside single quotes → close, insert `"${__SR_i}"`, reopen;
- inside an **unquoted** heredoc body → `${__SR_i}`; inside a **quoted** heredoc (`<<'EOT'`,
  `<<"EOT"`) → **refuse** with a clear error naming the secret (probe #7);
- env-prefix form `VAR={{secret:X}} cmd` → `VAR="${__SR_i}" cmd` (keeps the value out of argv).
Spawn `C:\Program Files\Git\bin\bash.exe` (or `CLAUDE_CODE_GIT_BASH_PATH`), **never**
`System32\bash.exe` (WSL). Only the named values enter the child env. Kill the child tree on
exit/interrupt (`taskkill /T /F`). PowerShell-tool sentinels: deny with "use the Bash tool" (v1).

## 4. Grants and tiers 

- Each secret has a **tier**: `open` (any session, within its policy) or `grant` (only sessions the operator
  has granted). **Default for anything the operator adds: `open`** until he says otherwise.
- Infisical can only grant **per identity (= per PC)**, never per Claude session, and a viewer reads
  every folder in its project (probe). So a grant is **two layers**:
  1. **Server-enforced time window:** the operator's admin identity gives the PC identity a **temporary
     `viewer` role** on the relevant `agents-grant-<group>` project (paired with a permanent
     `no-access` role). On expiry the same token gets 403 — verified.
  2. **Client-enforced session scope:** a grant record `{secret, session_id, expiresAt, grantedBy}`
     in `agents-open:/grants` (PCs read-only, so an agent cannot grant itself). `secretrun` only
     fetches a grant-tier value for a ticket whose `session_id` has a live record.
  A deliberate same-user bypass could read grant-tier values during an open window — within §1.
- Keyed on `session_id`, so **subagents inherit** their parent's grants (intended: a team of subagents works under
  one grant). `--resume`/`--continue` keep grants; `--fork-session` drops them (new id).
- the operator grants with `secretrun grant <session> <NAME> [--ttl 8h]` in their own terminal: it prompts for
  **his** Infisical login, does both layers, and discards the token — **the granting credential is
  never stored on a PC**. Later: an approval button in a chat app (roadmap 5; the admin credential would then
  live only on the approving service). A missing grant → `deny`, reason: "ask the operator to grant NAME to session <id>".

## 5. Policy

Stored per secret in Infisical **`secretMetadata`** (key/value, ≤1020 chars per value; verified
readable by a viewer with `viewSecretValue=false`, i.e. policy without the value; server-side
`metadataFilter` works). Keys: `tier`, `commands` (comma list), `hosts` (comma list), `description`.
A secret with no policy is **denied**.

**Infisical client rules** (probe): universal-auth login ~150 ms, fetch ~50 ms, cached
token ~32 ms → cache the access token in Credential Manager until its TTL. Hard 5 s timeout. A 5xx or
hang means "store unhealthy", never "secret missing"; do not trust `/api/status` (it says OK with the
DB down). No audit log on the free tier → §7 is the only audit.

```yaml
CF_API_TOKEN:  {tier: open,  commands: [curl, wrangler, npx], hosts: [api.cloudflare.com], description: "agent-scoped CF token, DNS edit on example.com"}
APP_DB_URL_RO: {tier: open,  commands: [psql, prisma, npx]}
PROD_DEPLOY:   {tier: grant, commands: [./deploy.sh]}
```
- `commands`: allowed program names, matched on **every** simple command in the pipeline/list that
  can see the env (all of them can — so a compound command must have every element allowed, or be
  denied). `echo`, `printf`, `printenv`, `env`, `set`, `cat`, `tee`, `base64`, `xxd`, `od`, `tr`,
  `rev` and redirections to files are never implicitly allowed alongside a secret.
- `hosts`: enforced where the host is visible in argv (curl URLs). For wrangler/psql it guards
  against mistakes, not containment.

## 6. Redactor contract (`src/redact/`)

`createRedactor(secrets: {name, value}[], opts?) => { push(chunk: Buffer): Buffer; flush(): Buffer }`
- Replaces with `[secret:NAME]`: exact value; base64 (standard + URL-safe, all three byte
  alignments); hex (lower/upper); URL-encoding; JSON-escaped; UTF-16LE; upper/lower-case variants;
  derived sub-secrets (password component of `scheme://user:pw@host` URLs).
- Streaming: hold back `maxPatternLen-1` bytes across chunk boundaries; `flush()` on idle (caller
  schedules ~100 ms) and on exit. Never splits a multi-byte UTF-8 char in output.
- Refuse (throw) secrets shorter than 8 chars. Overlapping matches: longest wins.
- Pure, dependency-free, fast enough for 50 MB of output.

## 7. Audit
`%LOCALAPPDATA%\secret-broker\audit.jsonl`: ts, machine, session_id, agent_id, names, command with
sentinels (never values), decision, exit code, duration.

## 8. Roadmap
1. Core, redactor and hook against `FileBackend`; Infisical client; end-to-end with dummy secrets.
2. Hardening: roll-out to more machines, scrubbing forwarded hook payloads, a leak suite in CI.
3. Migrating container secrets (render pattern) — only after the dummy end-to-end passes.
4. Browser resolver for logins.
5. Optional: a credential proxy, an approvals channel for grants.
