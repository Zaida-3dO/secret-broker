// The ~/.claude/settings.json registration for the hook (printed by `secretrun hook-snippet`;
// installing it is a manual, operator-approved step). Narrow matchers and an explicit timeout
// (design §3 rules 9 and 1: absolute paths, one spelling).
import { fwd, hookPath } from './paths.js';

export function hookSnippet(): unknown {
  const command = `"${fwd(process.execPath)}" "${fwd(hookPath())}"`;
  const entry = { type: 'command', command, timeout: 10 };
  return {
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [entry] },
        { matcher: 'Read|Grep|PowerShell', hooks: [entry] },
      ],
    },
  };
}
