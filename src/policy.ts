// Command-shape policy (design §5). The primary control: a secret command may only run programs
// its secrets allow, may not write to files, and may only talk to allowed hosts where the host is
// visible. Every reason returned here is shown to the model — names and program names only,
// never a value.
import { programBase, type ParseResult, type SimpleCommand, type Word } from './lex.js';
import type { Grant, SecretMeta, SecretPolicy } from './types.js';

/** Never implicitly allowed alongside a secret (design §5). */
export const HARD_DENY = new Set([
  'echo', 'printf', 'printenv', 'env', 'set', 'export', 'declare', 'cat', 'tee', 'base64', 'xxd',
  'od', 'hexdump', 'tr', 'rev', 'sed', 'awk', 'python', 'python3', 'node', 'perl', 'ruby', 'sh', 'bash',
]);

/** Redirect targets that are not files. */
const SAFE_OUTPUT_TARGETS = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', '/dev/fd/1', '/dev/fd/2', 'nul']);

const DANGEROUS_ASSIGN = new RegExp(
  '^(' +
    ['PATH', 'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'PS4', 'BASH_XTRACEFD', 'PROMPT_COMMAND', 'IFS',
      'LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS', 'BASH_LOADABLES_PATH', 'CDPATH', 'GLOBIGNORE',
      // proxies and client config can send the request elsewhere; SSLKEYLOGFILE writes TLS keys to disk
      'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'FTP_PROXY', 'CURL_HOME', 'HOME', 'WGETRC',
      // curl also looks for .curlrc under these (Windows + XDG)
      'XDG_CONFIG_HOME', 'APPDATA', 'USERPROFILE',
      'SSLKEYLOGFILE'].join('|') +
    ')$',
  'i',
);

export type PolicyDecision = { ok: true } | { ok: false; reason: string };

export interface PolicyInput {
  parse: ParseResult;
  names: string[];
  metas: SecretMeta[];
  /** Live grants for the session (only consulted for grant-tier secrets). */
  grants: Grant[];
  sessionId: string;
  now?: number;
}

function deny(reason: string): PolicyDecision {
  return { ok: false, reason };
}

function allowedBy(policy: SecretPolicy, prog: string): boolean {
  const base = programBase(prog);
  return (policy.commands ?? []).some((entry) => {
    if (/[\\/]/.test(entry)) return entry === prog;
    return !/[\\/]/.test(prog) && programBase(entry) === base;
  });
}

function wordDesc(w: Word): string {
  return w.raw.length > 60 ? `${w.raw.slice(0, 57)}...` : w.raw;
}

export function checkPolicy(input: PolicyInput): PolicyDecision {
  const { parse, names } = input;
  if (names.length === 0) return { ok: true };
  const policies = new Map<string, SecretPolicy>();
  for (const name of names) {
    const meta = input.metas.find((m) => m.name === name);
    if (!meta) return deny(`There is no secret named ${name}. Run \`secretrun list\` to see the names you can use.`);
    if (!meta.policy) return deny(`Secret ${name} has no usage policy, so it cannot be used. Ask the operator to add one.`);
    policies.set(name, meta.policy);
  }

  if (parse.problems.length) {
    return deny(
      `This command is too complex to verify for secret use (${parse.problems.join('; ')}). ` +
        'Use a simple command or a pipeline/list of allowed programs.',
    );
  }

  const describeAllowed = () =>
    names.map((n) => `${n}: ${(policies.get(n)!.commands ?? []).join(', ') || '(nothing)'}`).join('; ');

  for (const cmd of parse.commands) {
    const r = checkCommand(cmd, names, policies, describeAllowed);
    if (!r.ok) return r;
  }

  // Grant tier: the session needs a live grant for every grant-tier secret (design §4).
  const now = input.now ?? Date.now();
  for (const name of names) {
    if (policies.get(name)!.tier !== 'grant') continue;
    const live = input.grants.some(
      (g) => g.secret === name && g.sessionId === input.sessionId && Date.parse(g.expiresAt) > now,
    );
    if (!live) {
      return deny(
        `${name} is a grant-tier secret and this session has no live grant. ` +
          `Ask the operator to grant ${name} to session ${input.sessionId}.`,
      );
    }
  }
  return { ok: true };
}

function checkCommand(
  cmd: SimpleCommand,
  names: string[],
  policies: Map<string, SecretPolicy>,
  describeAllowed: () => string,
): PolicyDecision {
  // Redirections to files would put output (possibly the value) beyond the redactor's reach.
  for (const r of cmd.redirects) {
    const out = /^(>|>>|>\||&>|&>>|<>)$/.test(r.op) || (r.op === '>&' && !isFdTarget(r.target));
    if (!out) continue;
    const t = r.target;
    if (t && t.static && !t.hasSentinel && SAFE_OUTPUT_TARGETS.has(t.text.toLowerCase())) continue;
    return deny(
      `Output redirection (${r.op}${t ? ` ${wordDesc(t)}` : ''}) is not allowed in a command that uses a secret: ` +
        'the file would hold unredacted output. Let the output go to stdout.',
    );
  }

  // Assignments that change what runs, or make a shell trace or source code.
  for (const a of cmd.assigns) {
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(a.raw)?.[0] ?? '';
    if (DANGEROUS_ASSIGN.test(name)) {
      return deny(`Setting ${name} is not allowed in a command that uses a secret.`);
    }
  }

  if (cmd.keyword) return { ok: true }; // `for` header, `((…))`, closers: no program of their own
  if (cmd.words.length === 0) return { ok: true }; // assignment- or redirect-only

  const prog = cmd.words[0];
  if (!prog.static || prog.hasSentinel) {
    return deny(`The program name ${wordDesc(prog)} must be a literal word in a command that uses a secret.`);
  }
  for (const name of names) {
    if (!allowedBy(policies.get(name)!, prog.text)) {
      return deny(
        `\`${prog.text}\` is not an allowed program for ${name}. Every command in the line must be allowed ` +
          `for every secret it uses (${describeAllowed()}).`,
      );
    }
  }

  // Hard-deny programs anywhere in the argv (catches `npx bash -c …`, `find -exec cat …`).
  for (const w of cmd.words) {
    if (!w.static || w.hasSentinel) continue;
    const base = programBase(w.text);
    if (!HARD_DENY.has(base)) continue;
    if (names.every((n) => allowedBy(policies.get(n)!, w.text) || allowedBy(policies.get(n)!, base))) continue;
    return deny(
      `\`${base}\` cannot appear in a command that uses a secret — it could print or transform the value. ` +
        'Pass the secret straight to the program that needs it.',
    );
  }

  const base = programBase(prog.text);
  const hostSets = names.map((n) => policies.get(n)!.hosts).filter((h): h is string[] => !!h && h.length > 0);
  if (hostSets.length && (base === 'curl' || base === 'wget')) {
    const r = base === 'curl' ? checkCurl(cmd.words.slice(1), hostSets) : checkWget(cmd.words.slice(1), hostSets);
    if (!r.ok) return r;
  }
  if (base === 'curl') {
    const r = curlNoFileOutput(cmd.words.slice(1));
    if (!r.ok) return r;
  }
  return { ok: true };
}

function isFdTarget(t: Word | null): boolean {
  return !!t && t.static && /^(\d+|-)$/.test(t.text);
}

// ---------------------------------------------------------------- hosts

/**
 * Host of a URL (with or without scheme, as curl accepts), lower-cased; null if not static or if
 * the authority is ambiguous. curl ends the authority at a backslash as well as at / ? #, so
 * `https://evil.com\@api.example.com` goes to evil.com; rather than model every parser quirk,
 * anything unusual in the authority (a backslash, more than one @, a % escape) is refused —
 * when in doubt, deny.
 */
export function urlHost(text: string): string | null {
  let rest = text;
  const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(rest);
  if (m) rest = rest.slice(m[0].length);
  let authority = rest.split(/[/?#]/)[0];
  if (/[\\%]/.test(authority)) return null;
  const ats = authority.split('@').length - 1;
  if (ats > 1) return null;
  if (ats === 1) authority = authority.slice(authority.indexOf('@') + 1);
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    return close === -1 ? null : authority.slice(1, close).toLowerCase();
  }
  const host = authority.split(':')[0].toLowerCase();
  if (!host || /[{}\[\]*\s]/.test(host)) return null;
  return host.replace(/\.$/, '');
}

function hostAllowed(host: string, allowed: string[]): boolean {
  return allowed.some((a) => {
    const e = a.toLowerCase();
    return e.startsWith('*.') ? host.endsWith(e.slice(1)) && host.length > e.length - 1 : host === e;
  });
}

function checkUrls(urls: Word[], hostSets: string[][], prog: string): PolicyDecision {
  if (urls.length === 0) {
    return deny(`Could not find the URL in this ${prog} command; give it as a literal https:// URL.`);
  }
  for (const u of urls) {
    const host = u.static ? urlHost(u.text) : null;
    if (!host || host.includes('{{secret')) {
      return deny(`The ${prog} URL ${wordDesc(u)} must be a literal URL so its host can be checked.`);
    }
    for (const hs of hostSets) {
      if (!hostAllowed(host, hs)) {
        return deny(`Host ${host} is not allowed for this secret (allowed: ${hs.join(', ')}).`);
      }
    }
  }
  return { ok: true };
}

// curl options that take a separate value argument. An option missing here is treated as a flag,
// so its value is then checked as a URL and the command is denied — the safe direction. An option
// wrongly listed here would swallow a URL; only list options that certainly take a value.
const CURL_SHORT_VALUE = new Set('AbcCdDeEFHKmoPQrtTuUwxXyYz'.split(''));
const CURL_LONG_VALUE = new Set([
  'abstract-unix-socket', 'alt-svc', 'aws-sigv4', 'cacert', 'capath', 'cert', 'cert-type', 'ciphers',
  'config', 'connect-timeout', 'connect-to', 'continue-at', 'cookie', 'cookie-jar', 'create-file-mode',
  'curves', 'data', 'data-ascii', 'data-binary', 'data-raw', 'data-urlencode', 'delegation',
  'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'dns-servers', 'doh-url', 'dump-header', 'egd-file',
  'engine', 'etag-compare', 'etag-save', 'expect100-timeout', 'form', 'form-string', 'ftp-account',
  'ftp-alternative-to-user', 'ftp-method', 'ftp-port', 'ftp-ssl-ccc-mode', 'happy-eyeballs-timeout-ms',
  'haproxy-clientip', 'header', 'hostpubmd5', 'hostpubsha256', 'hsts', 'interface', 'ip-tos',
  'ipfs-gateway', 'json', 'keepalive-time', 'keepalive-cnt', 'key', 'key-type', 'krb', 'libcurl',
  'limit-rate', 'local-port', 'login-options', 'mail-auth', 'mail-from', 'mail-rcpt', 'max-filesize',
  'max-redirs', 'max-time', 'netrc-file', 'noproxy', 'oauth2-bearer', 'output', 'output-dir',
  'parallel-max', 'pass', 'pinnedpubkey', 'preproxy', 'proto', 'proto-default', 'proto-redir', 'proxy',
  'proxy-cacert', 'proxy-capath', 'proxy-cert', 'proxy-cert-type', 'proxy-ciphers', 'proxy-crlfile',
  'proxy-header', 'proxy-key', 'proxy-key-type', 'proxy-pass', 'proxy-pinnedpubkey',
  'proxy-service-name', 'proxy-tls13-ciphers', 'proxy-tlsauthtype', 'proxy-tlspassword',
  'proxy-tlsuser', 'proxy-user', 'proxy1.0', 'pubkey', 'quote', 'random-file', 'range', 'rate', 'referer',
  'request', 'request-target', 'resolve', 'retry', 'retry-delay', 'retry-max-time', 'sasl-authzid',
  'service-name', 'socks4', 'socks4a', 'socks5', 'socks5-gssapi-service', 'socks5-hostname',
  'speed-limit', 'speed-time', 'stderr', 'tls-max', 'tls13-ciphers', 'tlsauthtype', 'tlspassword',
  'tlsuser', 'trace', 'trace-ascii', 'trace-config', 'unix-socket', 'upload-file', 'url', 'url-query',
  'user', 'user-agent', 'variable', 'write-out',
]);
/** Options that can send the request (and its headers) somewhere other than the visible URL. */
const CURL_REROUTE_LONG = new Set([
  'proxy', 'preproxy', 'proxy1.0', 'socks4', 'socks4a', 'socks5', 'socks5-hostname', 'connect-to',
  'resolve', 'doh-url', 'dns-servers', 'config', 'location', 'location-trusted', 'next', 'variable', 'unix-socket',
  'abstract-unix-socket',
]);
const CURL_REROUTE_SHORT = new Set(['x', 'K', 'L', ':']);
/** Options that write request or response data to a file (a value of `-` means stdout). */
const CURL_FILE_LONG = new Set([
  'output', 'dump-header', 'trace', 'trace-ascii', 'stderr', 'cookie-jar', 'libcurl', 'etag-save',
  'hsts', 'alt-svc', 'output-dir', 'remote-name', 'remote-name-all', 'remote-header-name',
]);
const CURL_FILE_SHORT = new Set(['o', 'D', 'c', 'O', 'J']);
/**
 * Denied whatever their value: the trace dump breaks a header value across hex/text lines (and
 * wraps it at 64 columns), so even `--trace -` to stdout defeats the redactor.
 */
const CURL_ALWAYS_DENY = new Set(['trace', 'trace-ascii', 'trace-config']);

interface CurlArgs {
  urls: Word[];
  opts: { name: string; long: boolean; value: Word | null }[];
}

function parseCurlArgs(args: Word[]): CurlArgs {
  const urls: Word[] = [];
  const opts: CurlArgs['opts'] = [];
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    const t = w.text;
    if (w.static && t.startsWith('--') && t.length > 2) {
      const name = t.slice(2).replace(/^no-/, '');
      if (name === 'expand-url' || name.startsWith('expand-')) {
        opts.push({ name: 'expand', long: true, value: args[i + 1] ?? null });
        i++;
        continue;
      }
      if (CURL_LONG_VALUE.has(name)) {
        const value = args[i + 1] ?? null;
        opts.push({ name, long: true, value });
        if (name === 'url' && value) urls.push(value);
        i++;
      } else {
        opts.push({ name, long: true, value: null });
      }
      continue;
    }
    if (w.static && t.startsWith('-') && t.length > 1) {
      for (let k = 1; k < t.length; k++) {
        const ch = t[k];
        if (CURL_SHORT_VALUE.has(ch)) {
          const inline = t.slice(k + 1);
          let value: Word | null;
          if (inline) value = { ...w, raw: inline, text: inline };
          else {
            value = args[i + 1] ?? null;
            i++;
          }
          opts.push({ name: ch, long: false, value });
          break;
        }
        opts.push({ name: ch, long: false, value: null });
      }
      continue;
    }
    urls.push(w);
  }
  return { urls, opts };
}

function checkCurl(args: Word[], hostSets: string[][]): PolicyDecision {
  const { urls, opts } = parseCurlArgs(args);
  for (const o of opts) {
    if (o.long ? CURL_REROUTE_LONG.has(o.name) || o.name === 'expand' : CURL_REROUTE_SHORT.has(o.name)) {
      return deny(
        `curl ${o.long ? '--' : '-'}${o.name} is not allowed with a host-restricted secret: it can send the ` +
          'request (and the secret) to a host other than the URL shown. Call the allowed host directly.',
      );
    }
  }
  return checkUrls(urls, hostSets, 'curl');
}

function curlNoFileOutput(args: Word[]): PolicyDecision {
  const { opts } = parseCurlArgs(args);
  for (const o of opts) {
    if (o.long && CURL_ALWAYS_DENY.has(o.name)) {
      return deny(
        `curl --${o.name} is not allowed in a command that uses a secret: its dump splits the value across ` +
          'lines where redaction cannot see it. Use -v if you need to see headers.',
      );
    }
    const hit = o.long ? CURL_FILE_LONG.has(o.name) : CURL_FILE_SHORT.has(o.name);
    if (!hit) continue;
    if (o.value && o.value.static && (o.value.text === '-' || SAFE_OUTPUT_TARGETS.has(o.value.text.toLowerCase()))) continue;
    return deny(
      `curl ${o.long ? '--' : '-'}${o.name} writes to a file, which is not allowed in a command that uses a ` +
        'secret (the file would hold unredacted data). Let the output go to stdout.',
    );
  }
  return { ok: true };
}

const WGET_SHORT_VALUE = new Set('OoaeiBtTwQPUlARDIX'.split(''));
const WGET_LONG_VALUE = new Set([
  'output-document', 'output-file', 'append-output', 'execute', 'input-file', 'base', 'tries', 'timeout',
  'wait', 'quota', 'directory-prefix', 'user-agent', 'level', 'accept', 'reject', 'domains',
  'include-directories', 'exclude-directories', 'header', 'user', 'password', 'post-data', 'post-file',
  'method', 'body-data', 'body-file', 'referer', 'http-user', 'http-password', 'proxy-user',
  'proxy-password', 'load-cookies', 'save-cookies', 'ca-certificate', 'certificate', 'private-key',
]);
const WGET_DENY = new Set(['execute', 'input-file', 'e', 'i', 'output-file', 'append-output', 'o', 'a', 'save-headers']);

function checkWget(args: Word[], hostSets: string[][]): PolicyDecision {
  const urls: Word[] = [];
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    const t = w.text;
    if (w.static && t.startsWith('--') && t.length > 2) {
      const [name] = t.slice(2).split('=');
      if (WGET_DENY.has(name)) return deny(`wget --${name} is not allowed in a command that uses a secret.`);
      if (!t.includes('=') && WGET_LONG_VALUE.has(name)) i++;
      continue;
    }
    if (w.static && t.startsWith('-') && t.length > 1) {
      for (let k = 1; k < t.length; k++) {
        const ch = t[k];
        if (WGET_DENY.has(ch)) return deny(`wget -${ch} is not allowed in a command that uses a secret.`);
        if (WGET_SHORT_VALUE.has(ch)) {
          if (k === t.length - 1) i++;
          break;
        }
      }
      continue;
    }
    urls.push(w);
  }
  return checkUrls(urls, hostSets, 'wget');
}
