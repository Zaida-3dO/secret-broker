// Minimal Infisical HTTP client shared by InfisicalBackend and `secretrun grant`.
//
// Client rules (design §5): hard timeout (default 5 s) on every request,
// because a Redis outage or an unreachable host HANGS rather than failing. A network error, a
// timeout or any 5xx is "vault unhealthy" — never "secret missing". `/api/status` is not a health
// check (it says OK with the DB down), so nothing here calls it.
//
// Errors never carry a request body (it can hold a client secret or a password) and never a
// response's secret value; only the server's short `message` field is quoted.

export const DEFAULT_TIMEOUT_MS = 5000;

export class VaultUnhealthyError extends Error {
  constructor(detail: string) {
    super(`vault unhealthy (${detail}) — the secret store did not answer properly; this is not a missing secret. Try again shortly, or run \`secretrun doctor\`.`);
  }
}

export interface VaultResponse {
  status: number;
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

export interface RequestOptions {
  token?: string;
  body?: unknown;
  query?: Record<string, string | undefined>;
  timeoutMs?: number;
}

/** Plain http is accepted only for loopback (tests, an ssh tunnel); anything else must be https. */
export function checkVaultUrl(url: string): string {
  const u = url.replace(/\/+$/, '');
  let parsed: URL;
  try {
    parsed = new URL(u);
  } catch {
    throw new Error(`vault url ${JSON.stringify(url)} is not a URL`);
  }
  const loopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new Error(`vault url must be https:// (got ${parsed.protocol}//${parsed.host})`);
  }
  return u;
}

export async function vaultRequest(base: string, method: string, path: string, opts: RequestOptions = {}): Promise<VaultResponse> {
  const qs = opts.query
    ? new URLSearchParams(Object.entries(opts.query).filter((e): e is [string, string] => e[1] !== undefined)).toString()
    : '';
  const url = base + path + (qs ? `?${qs}` : '');
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let res: Response;
  let text: string;
  try {
    res = await fetch(url, {
      method,
      headers: {
        ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    text = await res.text();
  } catch (e) {
    const err = e as Error & { cause?: { code?: string } };
    const what = err.name === 'TimeoutError' || err.name === 'AbortError' ? `no answer within ${timeoutMs} ms` : (err.cause?.code ?? 'connection failed');
    throw new VaultUnhealthyError(`${method} ${path}: ${what}`);
  }
  if (res.status >= 500) throw new VaultUnhealthyError(`${method} ${path}: HTTP ${res.status}`);
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

/** Short, value-free description of a 4xx for an error message. */
export function describeFailure(method: string, path: string, r: VaultResponse): string {
  const m = r.json && typeof r.json === 'object' && typeof r.json.message === 'string' ? `: ${String(r.json.message).slice(0, 200)}` : '';
  return `${method} ${path} -> HTTP ${r.status}${m}`;
}
