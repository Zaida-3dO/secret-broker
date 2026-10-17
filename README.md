# secret-broker

Agents use secrets **by name, never by value**. An agent writes `{{secret:NAME}}` in a Bash command;
a Claude Code hook rewrites it to run through `secretrun`, which injects the value into the child
process only and redacts it from output. Backed by self-hosted Infisical.

Start with [docs/design.md](docs/design.md). 

Never commit a real secret, even in tests — use values like `DUMMY-SECRET-<hex>`.

## Usage

```bash
npm ci && npm run check                 # build + unit tests
node dist/src/cli.js doctor             # read-only health check
node dist/src/cli.js list               # names, tier, allowed commands, hosts — never values
node dist/src/cli.js hook-snippet       # the ~/.claude/settings.json entry (install by hand, with the operator's OK)
npm run e2e                             # headless Claude Code leak test (spends tokens)
```

An agent then writes, in the Bash tool:

```bash
curl -sS -H "Authorization: Bearer {{secret:CF_API_TOKEN}}" https://api.cloudflare.com/client/v4/user/tokens/verify
```

Install, policy format, what gets denied and the known limits: [docs/operations.md](docs/operations.md).

## License

MIT.
