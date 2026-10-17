import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';
import { lex, programBase, sentinelNames, substitute, SubstitutionError, type SimpleCommand } from '../src/lex.js';
import { gitBashPath } from '../src/paths.js';

const sub = (c: string) => substitute(c).script;
const progs = (c: string) =>
  lex(c)
    .commands.filter((x) => x.words.length && !x.keyword)
    .map((x) => x.words[0].text);
const problems = (c: string) => lex(c).problems;

describe('substitute: quote contexts (design §3)', () => {
  const cases: [string, string, string][] = [
    ['unquoted', 'curl -H {{secret:A}} x', 'curl -H "${__SR_0}" x'],
    ['unquoted glued to text', 'curl -u user:{{secret:A}} x', 'curl -u user:"${__SR_0}" x'],
    ['double quotes', 'curl -H "Authorization: Bearer {{secret:A}}" x', 'curl -H "Authorization: Bearer ${__SR_0}" x'],
    ['single quotes', "curl -d 'tok={{secret:A}}&x=1' u", `curl -d 'tok='"\${__SR_0}"'&x=1' u`],
    ['single quotes, whole content', "curl -d '{{secret:A}}' u", `curl -d ''"\${__SR_0}"'' u`],
    ['ANSI-C quoting', "curl -d $'a\\n{{secret:A}}b' u", `curl -d $'a\\n'"\${__SR_0}"$'b' u`],
    ['locale $"…" is like double', 'curl -d $"x{{secret:A}}" u', 'curl -d $"x${__SR_0}" u'],
    ['env-prefix form', 'TOKEN={{secret:A}} wrangler whoami', 'TOKEN="${__SR_0}" wrangler whoami'],
    ['env-prefix quoted', 'TOKEN="{{secret:A}}" wrangler whoami', 'TOKEN="${__SR_0}" wrangler whoami'],
    ['two secrets', 'curl -u {{secret:A}}:{{secret:B}} u', 'curl -u "${__SR_0}":"${__SR_1}" u'],
    ['same secret twice uses one index', 'c {{secret:A}} {{secret:B}} {{secret:A}}', 'c "${__SR_0}" "${__SR_1}" "${__SR_0}"'],
    ['unquoted heredoc', 'curl -d @- u <<EOF\n{"t":"{{secret:A}}"}\nEOF', 'curl -d @- u <<EOF\n{"t":"${__SR_0}"}\nEOF'],
    ['heredoc <<- with tabs', 'curl -d @- u <<-EOF\n\t{{secret:A}}\n\tEOF', 'curl -d @- u <<-EOF\n\t${__SR_0}\n\tEOF'],
    ['inside $(…) resets quoting', 'curl -H "X: $(printf %s {{secret:A}})" u', 'curl -H "X: $(printf %s "${__SR_0}")" u'],
    ['escaped quote in double quotes', 'curl -d "a\\"{{secret:A}}\\"" u', 'curl -d "a\\"${__SR_0}\\"" u'],
    ['escaped single quote outside', "curl -d it\\'s{{secret:A}} u", `curl -d it\\'s"\${__SR_0}" u`],
    ['comment is left alone', 'curl u # {{secret:A}}', 'curl u # {{secret:A}}'],
    ['hash inside a word is not a comment', 'curl u#{{secret:A}}', 'curl u#"${__SR_0}"'],
    ['name with dots and slashes', 'curl -H {{secret:login/site.pw}} u', 'curl -H "${__SR_0}" u'],
    ['pipeline', 'curl -H {{secret:A}} u | jq .', 'curl -H "${__SR_0}" u | jq .'],
    ['single quote right after double', `x "a"'{{secret:A}}'`, `x "a"''"\${__SR_0}"''`],
    ['line continuation', 'curl \\\n -H "{{secret:A}}" u', 'curl \\\n -H "${__SR_0}" u'],
  ];
  for (const [name, input, expected] of cases) {
    it(name, () => assert.equal(sub(input), expected));
  }

  it('names are listed in order of first appearance', () => {
    assert.deepEqual(substitute('c {{secret:B}} {{secret:A}} {{secret:B}}').names, ['B', 'A']);
  });
  it('names exclude comment-only sentinels', () => {
    assert.deepEqual(sentinelNames(lex('c {{secret:A}} # {{secret:B}}')), ['A']);
  });

  const refused: [string, string, RegExp][] = [
    ['quoted heredoc', "cat <<'EOF'\n{{secret:A}}\nEOF", /quoted heredoc/],
    ['double-quoted heredoc', 'cat <<"EOF"\n{{secret:A}}\nEOF', /quoted heredoc/],
    ['backslash-quoted heredoc', 'cat <<\\EOF\n{{secret:A}}\nEOF', /quoted heredoc/],
    ['backticks', 'curl -H `printf %s {{secret:A}}` u', /backticks/],
    ['arithmetic', 'echo $(( {{secret:A}} + 1 ))', /arithmetic/],
    ['parameter expansion', 'echo ${X:-{{secret:A}}}', /\$\{\.\.\.\}/],
  ];
  for (const [name, input, re] of refused) {
    it(`refuses: ${name}`, () => {
      assert.throws(() => substitute(input), (e: unknown) => e instanceof SubstitutionError && re.test(e.message) && e.message.includes('{{secret:A}}'));
    });
  }

  it('quoted heredoc body is refused even when the same secret is used elsewhere', () => {
    assert.throws(() => substitute("curl -H {{secret:A}} u <<'E'\n{{secret:A}}\nE"), SubstitutionError);
  });
  it('heredoc body after the delimiter line is code again', () => {
    assert.equal(sub("cat <<'E'\nlit\nE\ncurl -H {{secret:A}} u"), `cat <<'E'\nlit\nE\ncurl -H "\${__SR_0}" u`);
  });
});

describe('sentinel grammar', () => {
  it('rejects an over-long name', () => assert.ok(problems(`c {{secret:${'a'.repeat(129)}}}`).some((p) => /malformed/.test(p))));
  it('accepts a 128-char name', () => assert.deepEqual(problems(`c {{secret:${'a'.repeat(128)}}}`), []));
  it('rejects invalid characters', () => assert.ok(problems('c {{secret:a b}}').some((p) => /malformed/.test(p))));
  it('rejects a missing close', () => assert.ok(problems('c {{secret:AB').some((p) => /malformed/.test(p))));
  it('rejects an empty name', () => assert.ok(problems('c {{secret:}}').some((p) => /malformed/.test(p))));
  it('backslash before sentinel in double quotes is ambiguous', () =>
    assert.ok(problems('c "\\{{secret:A}}"').some((p) => /backslash/.test(p))));
  it('escaped brace unquoted is not a sentinel', () => assert.deepEqual(sentinelNames(lex('c \\{{secret:A}}')), []));
});

describe('command extraction for policy', () => {
  const cases: [string, string, string[]][] = [
    ['simple', 'curl -s u', ['curl']],
    ['pipe', 'curl u | jq .', ['curl', 'jq']],
    ['pipe stderr', 'curl u |& jq .', ['curl', 'jq']],
    ['and/or/semicolon', 'a && b || c ; d', ['a', 'b', 'c', 'd']],
    ['background', 'a & b', ['a', 'b']],
    ['newline separated', 'a\nb', ['a', 'b']],
    ['$( ) unquoted', 'curl $(cat f) u', ['curl', 'cat']],
    ['$( ) in double quotes', 'curl "x $(printenv) y" u', ['curl', 'printenv']],
    ['nested $( )', 'a "$(b "$(c)")"', ['a', 'b', 'c']],
    ['backticks', 'a `b`', ['a', 'b']],
    ['backticks in double quotes', 'a "`b \\"q\\"`"', ['a', 'b']],
    ['subshell', '(a; b) | c', ['a', 'b', 'c']],
    ['brace group', '{ a; b; } | c', ['a', 'b', 'c']],
    ['process substitution', 'diff <(a) >(b)', ['diff', 'a', 'b']],
    ['assignment prefix', 'X=1 Y="2" curl u', ['curl']],
    ['assignment only', 'X={{secret:A}}', []],
    ['if/then/fi', 'if a; then b; else c; fi', ['a', 'b', 'c']],
    ['while loop', 'while a; do b; done', ['a', 'b']],
    ['for loop header is not a command', 'for i in x y; do curl $i; done', ['curl']],
    ['negation', '! a', ['a']],
    ['time keyword', 'time a', ['a']],
    ['$( ) inside unquoted heredoc', 'a <<EOF\n$(b)\nEOF', ['a', 'b']],
    ['$( ) inside quoted heredoc is text', "a <<'EOF'\n$(b)\nEOF", ['a']],
    ['command after heredoc', 'a <<EOF\nx\nEOF\nb', ['a', 'b']],
    ['two heredocs on one line', 'a <<X; b <<Y\n1\nX\n2\nY\nc', ['a', 'b', 'c']],
    ['comment hides nothing after newline', 'a # b\nc', ['a', 'c']],
    ['quoted program name', '"curl" u', ['curl']],
    ['$() in assignment', 'X=$(a) b', ['b', 'a']],
    ['$() in redirect target', 'a > "$(b)"', ['a', 'b']],
  ];
  for (const [name, input, expected] of cases) {
    it(name, () => assert.deepEqual(progs(input).sort(), [...expected].sort()));
  }

  it('records redirections with fd and target', () => {
    const c = lex('a 2>&1 >out.txt <in 3>>log').commands[0];
    assert.deepEqual(
      c.redirects.map((r) => [r.fd, r.op, r.target?.text]),
      [['2', '>&', '1'], [null, '>', 'out.txt'], [null, '<', 'in'], ['3', '>>', 'log']],
    );
  });
  it('&> is a redirect, not a separator', () => {
    const c = lex('a &> f').commands;
    assert.equal(c.length, 1);
    assert.equal(c[0].redirects[0].op, '&>');
  });
  it('redirect after a subshell attaches to a pseudo-command', () => {
    const cs = lex('(a) > f').commands;
    assert.ok(cs.some((c: SimpleCommand) => c.keyword === ')' && c.redirects[0]?.target?.text === 'f'));
  });
  it('redirect after done attaches to a pseudo-command', () => {
    const cs = lex('for i in 1; do a; done > f').commands;
    assert.ok(cs.some((c) => c.keyword === 'done' && c.redirects[0]?.op === '>'));
  });
  it('words with $ are not static', () => {
    const w = lex('$X a').commands[0].words[0];
    assert.equal(w.static, false);
  });
  it('quote removal', () => {
    assert.equal(lex(`a "b c"'d'\\ e`).commands[0].words[1].text, 'b cd e');
  });

  const unsupported: [string, string][] = [
    ['case', 'case x in a) b;; esac'],
    ['function keyword', 'function f { a; }'],
    ['function parens', 'f() { a; }'],
    ['array assignment', 'a=(1 2)'],
    ['[[ ]]', '[[ -n x ]] && a'],
    ['$() in ${}', 'a ${X:-$(b)}'],
    ['$() in arithmetic', 'a $(( $(b) + 1 ))'],
    ['unterminated quote', 'a "b'],
    ['unterminated $(', 'a $(b'],
    ['unbalanced )', 'a )'],
    ['select', 'select x in a; do b; done'],
    ['arithmetic expansion', 'a $((1+2))'],
    ['arithmetic command', '((x=1)); a'],
    ['old $[ ] arithmetic', 'a $[1+2]'],
    ['array subscript', 'a "${arr[x]}"'],
    ['substring offset', 'a "${s:x}"'],
    ['prompt-expansion transform', 'a "${x@P}"'],
    ['brace expansion list', 'a {b,c}'],
    ['brace expansion range', 'a {1..3}'],
  ];
  for (const [name, input] of unsupported) {
    it(`flags unsupported: ${name}`, () => assert.ok(problems(input).length > 0, `no problem for ${input}`));
  }
  it('default-value expansions are fine', () => assert.deepEqual(problems('a "${X:-d}" ${Y:=e} ${#Z} ${W%.*}'), []));
  it('quoted braces are not brace expansion', () => assert.deepEqual(problems(`curl -w '%{a,b}' "{x,y}" u`), []));
  it('no problems for a typical curl', () =>
    assert.deepEqual(problems('curl -sS -H "Authorization: Bearer {{secret:A}}" https://api.example.com/v1 | jq .'), []));
});

describe('programBase', () => {
  it('strips path and .exe, lower-cases', () => {
    assert.equal(programBase('C:/Program Files/Git/usr/bin/CURL.EXE'), 'curl');
    assert.equal(programBase('/usr/bin/env'), 'env');
    assert.equal(programBase('curl'), 'curl');
  });
});

// The real proof: run the substituted script in Git Bash and compare with what bash would print if
// the value had been typed literally (computed by substituting the value textually where that is
// unambiguous).
const bash = gitBashPath();
describe('substitution executes correctly in Git Bash', { skip: !bash }, () => {
  const VALUE = "DUMMY-SECRET-a1b2c3d4e5f60718 $HOME `x` 'q' \"d\" \\ *";
  const run = (cmd: string) => {
    const { script } = substitute(cmd);
    const r = spawnSync(bash!, ['-c', '__c=$__SR_CMD; unset __SR_CMD; eval "$__c"'], {
      env: { ...process.env, __SR_0: VALUE, __SR_CMD: script },
      encoding: 'utf8',
    });
    return r.stdout;
  };
  const cases: [string, string, string][] = [
    ['unquoted keeps the value as one word', 'printf "[%s]" {{secret:A}}', `[${VALUE}]`],
    ['double quotes', 'printf "%s" "v={{secret:A}}!"', `v=${VALUE}!`],
    ['single quotes', "printf '%s' 'v={{secret:A}}!'", `v=${VALUE}!`],
    ['ANSI-C', "printf '%s' $'a\\tb{{secret:A}}c'", `a\tb${VALUE}c`],
    ['unquoted heredoc', 'cat <<EOF\nv={{secret:A}}\nEOF', `v=${VALUE}\n`],
    ['env prefix', 'X={{secret:A}} bash -c \'printf %s "$X"\'', VALUE],
    ['inside $()', 'printf "%s" "$(printf %s {{secret:A}})"', VALUE],
    ['no glob or expansion of the value', 'printf "%s|" {{secret:A}}', `${VALUE}|`],
  ];
  for (const [name, cmd, expected] of cases) {
    it(name, () => assert.equal(run(cmd), expected));
  }
});
