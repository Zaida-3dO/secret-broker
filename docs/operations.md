# secret-broker — operations

How to install, check, use and administer `secretrun`. The why is in [design.md](design.md).

> **Status:** core + hook + `FileBackend`. `FileBackend` keeps values in a plaintext JSON file and is
> for development and tests with dummy values only. Real secrets wait for `InfisicalBackend`.

## Install

```bash
cd <repo> && npm ci && npm run check      # build + unit tests
```

The build lands in `dist/src/` (the shared `tsconfig.json` compiles `src/` and `test/` side by side):
`dist/src/cli.js` is `secretrun`, `dist/src/hook.js` is `secretrun-hook`.

1. **Config** — `%APPDATA%\secret-broker\config.json` (or the file named by `SECRETRUN_CONFIG`):

   ```json
   { "backend": "file", "file": "%USERPROFILE%/secret-broker-dev/secrets.json" }
   ```

   Optional: `"ticketTtlSeconds": 120` (5–600; default 120 — see "Limits").

2. **State** — tickets and the audit log live in `%LOCALAPPDATA%\secret-broker\` (or
   `SECRETRUN_STATE_DIR`). The directories are created on first use with an owner-only ACL.

3. **Register the hook** — a manual, operator-approved step. Print the entry and merge it into
   `~/.claude/settings.json` by hand:

   ```bash
   node dist/src/cli.js hook-snippet
   ```

   It registers the same script twice under `PreToolUse`: `matcher: "Bash"` (secret commands, `.env`
   reads, direct `secretrun` calls) and `matcher: "Read|Grep|PowerShell"` (`.env` reads and
   PowerShell sentinels), each with absolute paths and `"timeout": 10`.

   **Exactly one hook may return `updatedInput` for Bash** across every settings layer — when two do,
   the one that finishes last silently wins (verified on Claude Code 2.1.183).

4. **Check** — `node dist/src/cli.js doctor` (read-only): prints the absolute invocation, finds Git
   Bash, reads the config, reaches the backend, and checks that `~/.claude/settings.json` mentions
   the hook.

## Machine credential (`secretrun setup`, the operator, once per PC)

Your vault bootstrap (see "Deploying a vault") writes each PC identity's Universal Auth client id + secret to
`%LOCALAPPDATA%\secret-broker\bootstrap\<identity>.json`. Then, **in the operator's own terminal**:

```bash
node dist/src/cli.js setup --dry-run          # show the plan; changes nothing
node dist/src/cli.js setup                    # identity defaults to pc-<hostname>; --identity pc-x to override
```

It stores `{clientId, clientSecret}` in Windows Credential Manager under service `secret-broker`,
account `infisical-<identity>` (`@napi-rs/keyring` `new Entry(service, account)` — never
`withTarget`), reads it back through a fresh entry, writes the config
`{"backend":"infisical","url":"https://vault.example.internal","identity":"pc-<machine>"}`, and deletes the
bootstrap file. It never prints the secret. While the config still points at the dev FileBackend it
moves the credential but leaves the config alone; `--switch-backend` replaces it (keeping a copy as
`config.file-backend.json`). `InfisicalBackend` itself is a later task — `src/keyring.ts`
`readMachineCredential()` is the seam it reads through.

The hook denies Read/Grep/Bash/PowerShell access to the broker's internals — the `bootstrap\` and
`tickets\` folders under `%LOCALAPPDATA%\secret-broker\` and the FileBackend JSON named in the config
— with a reason saying so.

## How an agent uses it

Write the secret **by name** in an ordinary Bash command:

```bash
curl -sS -H "Authorization: Bearer {{secret:CF_API_TOKEN}}" https://api.cloudflare.com/client/v4/user/tokens/verify
```

- The hook checks the command against the secret's policy and either denies it with a reason or
  rewrites it to `secretrun exec --ticket <nonce> -- '<command>'` and allows it. The model never sees
  the rewrite.
- `secretrun` puts the value only in the child shell's environment, substitutes the sentinel for a
  variable reference that suits its quoting, and redacts the value from stdout and stderr as
  `[secret:CF_API_TOKEN]`.
- Sentinels work unquoted, in double quotes, in single quotes, in `$'…'`, in env-prefix form
  (`TOKEN={{secret:X}} wrangler …`) and in **unquoted** heredocs (`<<EOF`). They are refused in quoted
  heredocs (`<<'EOF'`), backticks, `${…}` and `$((…))`.
- To see what exists: `"<node>" "<repo>/dist/src/cli.js" list` (names, tier, allowed commands,
  hosts, description — never values). The hook's `.env` denial prints the exact command.
- Use the **Bash** tool. A sentinel in the PowerShell tool is denied.
- Reading `.env*` files (except `.example`/`.sample`/`.template`) with Bash, PowerShell, Read or
  Grep is denied.

### What gets denied, and why

| Shape | Reason |
|---|---|
| A program the secret's `commands` does not list, anywhere in the line (pipes, `&&`, `;`, `$(…)`, backticks, `<(…)`) | every simple command can see the value |
| `echo printf printenv env set export declare cat tee base64 xxd od hexdump tr rev sed awk python python3 node perl ruby sh bash` anywhere in argv, unless the secret lists it | they print or transform the value |
| `>`, `>>`, `&>`, `>&file`, `2>file`, `curl -o/-O/-D/--trace…` (except `/dev/null` and `-`) | a file would hold unredacted output |
| curl/wget to a host not in `hosts`; a non-literal URL; `curl -L/-x/--proxy/--resolve/--connect-to/-K` with a host-restricted secret | the value could go to another host |
| `case`, functions, arrays, `[[ ]]`, command substitution inside `${…}`/`$((…))` | too complex to verify — simplify |
| A grant-tier secret with no live grant for the session | "ask the operator to grant NAME to session <id>" |
| Calling `secretrun exec` / the hook yourself | the hook runs it for you |

## How the operator adds a secret (FileBackend, dev)

Add an entry to the secrets file named in the config:

```json
{
  "secrets": [
    {
      "name": "CF_API_TOKEN",
      "value": "DUMMY-SECRET-…",
      "policy": {
        "tier": "open",
        "commands": ["curl", "wrangler", "npx"],
        "hosts": ["api.cloudflare.com"],
        "description": "agent-scoped CF token, DNS edit on example.com"
      }
    }
  ],
  "grants": []
}
```

- **No `policy` → the secret cannot be used.** `tier` is `open` (default) or `grant`.
- `commands` are program names as the agent types them (`curl`, `./deploy.sh`). A bare name matches
  only a bare program (`curl`, `curl.exe`), never `/tmp/x/curl`.
- `hosts` supports `*.example.com`.
- Values must be at least 8 characters (the redactor refuses shorter ones).
- Dev grant for a grant-tier secret: `node dist/src/cli.js grant <session-id> <NAME> --ttl 8h`.
  The real grant path (Infisical, two layers, design §4) is a later task.

## Deploying a vault

`InfisicalBackend` needs a reachable, self-hosted [Infisical](https://infisical.com) instance served
over HTTPS (for example `https://vault.example.internal`; plain `http` is refused).

1. Self-host Infisical (its official Docker Compose setup is enough) and keep the database backed up.
2. Create the projects listed in design §2: one for open-tier secrets (also holds the `/grants`
   records), one for browser logins, and one `agents-grant-<group>` project per grant group.
3. Create one Universal Auth machine identity per PC, named `pc-<machine>`, with the `viewer` role on
   the projects it needs (read-only; writes must return 403). Add a `no-access` role for the grant
   projects so a temporary `viewer` role can open and close a window.
4. Write each identity's client id, client secret and the vault URL to
   `%LOCALAPPDATA%\secret-broker\bootstrap\pc-<machine>.json` as
   `{"apiUrl": "https://vault.example.internal", "identity": "pc-<machine>", "clientId": "...", "clientSecret": "..."}`,
   plus an optional `projects.json` mapping project names to ids.
5. On each PC run `node dist/src/cli.js setup` (see above). It moves the credential into Windows
   Credential Manager and deletes the bootstrap file.

The vault URL has no built-in default: it comes from the bootstrap file or the config's `url`.

## Audit

`%LOCALAPPDATA%\secret-broker\audit.jsonl` — one line per hook decision (`kind: "hook"`, allow/deny
and reason) and per exec (`kind: "exec"`, run/refuse, exit code, duration). Commands are logged as
the agent wrote them, with sentinels; never values.

## Limits (honest list)

- **A same-user process can defeat all of this** (design §1): read the FileBackend, forge a ticket,
  read a process environment. It stops accidents, not a hostile agent.
- **Idle flush vs. split writes.** Output is flushed after 100 ms of silence. A program that writes
  part of a value, pauses longer than that, then writes the rest, emits it in two unredacted halves.
- **Redaction is a backstop.** A transform the redactor does not know (`tr`, `rev`, arithmetic on
  bytes) passes through; the command-shape policy is what stops `| base64`.
- **Hosts are checked where visible.** curl/wget URLs only; for wrangler/psql the policy guards
  against mistakes, not containment. Unknown curl options are treated as flags, so their values are
  checked as URLs — a false deny, never a false allow.
- **`.env` guard is a speed bump.** `grep -r . .` or a script that opens the file is not caught.
- **Ticket lifetime is 120 s, not the design's 30 s.** The first e2e run measured 67 s between
  the hook's decision and `secretrun exec` starting (first Bash call of a session, loaded machine);
  a 30 s ticket expired. Tickets are single-use, hash-bound and never shown to the model.

## Tests

- `npm run check` — build + unit tests (`node:test`). Some exec tests spawn Git Bash and are slow on
  a loaded machine.
- `npm run e2e` — **spends tokens.** Runs headless Haiku sessions in a scratch project registered
  with this build's hook and greps every transcript, `tool-results/`, `tasks/*.output`, the `-p`
  result and and (optionally, via `E2E_EXTRA_SINK`) one more file for the dummy values (raw, base64, hex, upper-case,
  URL-encoded). `--only=curl,echo` runs a subset; `--keep` leaves the scratch folders for
  inspection. It never edits `~/.claude/settings.json`.
