import { request } from "node:https";
import { rootCertificates } from "node:tls";
import { OpsError, normalizeEndpoint } from "@ops/contracts";
import type { TargetPin } from "@ops/contracts";
import { caFingerprintOf } from "@ops/broker";
import type { TokenCredential } from "@ops/broker";

export interface GhResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** Yanıt `maxBytes` üstünde kesildi. */
  readonly truncated: boolean;
}

export interface GhClientOptions {
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  /** POST/PUT/DELETE'e izin (savunma derinliği): YALNIZ yazma araçları için `true`. */
  readonly allowWrite?: boolean;
}

type Query = Readonly<Record<string, string | number | undefined>>;

function once(opts: {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: string;
  host: string;
  port: number;
  path: string;
  headers: Record<string, string>;
  ca?: string[];
  servername?: string;
  maxBytes: number;
  timeoutMs: number;
  signal?: AbortSignal;
}): Promise<GhResponse> {
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) return reject(new OpsError("aborted", "çağrı iptal edildi"));
    const req = request(
      {
        method: opts.method ?? "GET",
        host: opts.host,
        port: opts.port,
        path: opts.path,
        headers: opts.body !== undefined ? { ...opts.headers, "content-type": "application/json", "content-length": String(Buffer.byteLength(opts.body)) } : opts.headers,
        agent: false,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ...(opts.ca ? { ca: opts.ca } : {}),
        ...(opts.servername ? { servername: opts.servername } : {}),
        timeout: opts.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on("data", (c: Buffer) => {
          if (truncated) return;
          size += c.length;
          if (size > opts.maxBytes) {
            truncated = true;
            chunks.push(c.subarray(0, Math.max(0, c.length - (size - opts.maxBytes))));
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        const done = (): void => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
          resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString("utf8"), truncated });
        };
        res.on("end", done);
        res.on("close", () => {
          if (truncated) done();
        });
        res.on("error", (e) => (truncated ? done() : reject(e)));
      },
    );
    req.on("timeout", () => req.destroy(new OpsError("timeout", "GitHub isteği zaman aşımına uğradı")));
    req.on("error", reject);
    opts.signal?.addEventListener("abort", () => req.destroy(new OpsError("aborted", "çağrı iptal edildi")), { once: true });
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

/**
 * GitHub REST istemcisi (varsayılan yalnız GET; POST/PUT/DELETE yalnız `allowWrite` ile). Belirteç YALNIZ pinli adrese ve doğrulanmış TLS ile gider:
 * adres/CA pini kimlik kullanılmadan ÖNCE denetlenir; yönlendirmeler İZLENMEZ (günlük indirmesi
 * hariç, bkz. `fetchSigned`: Authorization OLMADAN ve izinli host'a).
 */
export class GithubClient {
  private readonly url: URL;
  private readonly cred: TokenCredential;
  private readonly opts: GhClientOptions;

  constructor(cred: TokenCredential, pin: TargetPin, opts: GhClientOptions) {
    if (normalizeEndpoint(cred.apiBase) !== normalizeEndpoint(pin.endpoint)) {
      throw new OpsError("target_pin_mismatch", "API adresi profilin pinli uç noktasıyla eşleşmiyor");
    }
    if (pin.caFingerprint && (!cred.caPem || caFingerprintOf(cred.caPem) !== pin.caFingerprint)) {
      throw new OpsError("target_pin_mismatch", "CA parmak izi profilin pinine uymuyor");
    }
    this.url = new URL(cred.apiBase);
    if (this.url.protocol !== "https:") throw new OpsError("api_base_insecure", "API adresi https olmalı");
    this.cred = cred;
    this.opts = opts;
  }

  get host(): string {
    return this.url.host.toLowerCase();
  }

  async get(path: string, query: Query = {}): Promise<GhResponse> {
    return this.send("GET", path, query);
  }

  private requireWrite(): void {
    if (this.opts.allowWrite !== true) throw new OpsError("write_not_allowed", "bu istemci salt okunur (yazma araçları dışında POST/PUT/DELETE yapılamaz)");
  }

  post(path: string, body: unknown): Promise<GhResponse> {
    this.requireWrite();
    return this.send("POST", path, {}, JSON.stringify(body));
  }

  put(path: string, body: unknown): Promise<GhResponse> {
    this.requireWrite();
    return this.send("PUT", path, {}, JSON.stringify(body));
  }

  del(path: string): Promise<GhResponse> {
    this.requireWrite();
    return this.send("DELETE", path, {});
  }

  private async send(method: "GET" | "POST" | "PUT" | "DELETE", path: string, query: Query, body?: string): Promise<GhResponse> {
    if (!path.startsWith("/")) throw new OpsError("path_refused", "yol / ile başlamalı");
    const qs = Object.entries(query)
      .filter((e): e is [string, string | number] => e[1] !== undefined)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join("&");
    const base = this.url.pathname.replace(/\/+$/, "");
    return once({
      method,
      ...(body !== undefined ? { body } : {}),
      host: this.url.hostname.replace(/^\[|\]$/g, ""),
      port: this.url.port ? Number(this.url.port) : 443,
      path: `${base}${path}${qs ? `?${qs}` : ""}`,
      headers: {
        authorization: `Bearer ${this.cred.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "ops-assistant",
      },
      ...(this.cred.caPem ? { ca: [this.cred.caPem] } : {}),
      maxBytes: this.opts.maxBytes,
      timeoutMs: this.opts.timeoutMs,
      ...(this.opts.signal ? { signal: this.opts.signal } : {}),
    });
  }

  /**
   * İmzalı günlük URL'sini Authorization OLMADAN getirir. URL'nin host'u çağıran tarafından
   * izinli listeye karşı doğrulanmış olmalıdır (`isAllowedLogHost`).
   */
  async fetchSigned(u: URL): Promise<GhResponse> {
    const sameHost = u.host.toLowerCase() === this.host;
    return once({
      host: u.hostname.replace(/^\[|\]$/g, ""),
      port: u.port ? Number(u.port) : 443,
      path: `${u.pathname}${u.search}`,
      headers: { accept: "*/*", "user-agent": "ops-assistant" },
      ...(this.cred.caPem ? { ca: sameHost ? [this.cred.caPem] : [...rootCertificates, this.cred.caPem] } : {}),
      maxBytes: this.opts.maxBytes,
      timeoutMs: this.opts.timeoutMs,
      ...(this.opts.signal ? { signal: this.opts.signal } : {}),
    });
  }
}

/** Günlük indirme yönlendirmesi için izinli host: aynı sunucu, profilde beyan edilenler veya (api.github.com için) bilinen blob alan adları. */
export function isAllowedLogHost(apiHost: string, location: URL, extra: readonly string[]): boolean {
  if (location.protocol !== "https:" || location.username || location.password) return false;
  const hostport = location.host.toLowerCase();
  const host = location.hostname.toLowerCase();
  if (hostport === apiHost.toLowerCase()) return true;
  if (extra.some((e) => e.toLowerCase() === hostport || e.toLowerCase() === host)) return true;
  if (apiHost.toLowerCase() === "api.github.com") {
    return /(^|\.)githubusercontent\.com$/.test(host) || /(^|\.)blob\.core\.windows\.net$/.test(host);
  }
  return false;
}

export function ghError(resp: GhResponse, what: string): OpsError {
  let msg = "";
  try {
    const j = JSON.parse(resp.body) as { message?: unknown };
    if (typeof j.message === "string") msg = j.message.replace(/[^\w .,:;()'/-]/g, "?").slice(0, 100);
  } catch {
    /* gövde JSON değil */
  }
  if (resp.status === 401) return new OpsError("github_unauthorized", `${what}: kimlik doğrulanamadı (belirteç geçersiz veya süresi dolmuş)`);
  if ((resp.status === 403 || resp.status === 429) && resp.headers["x-ratelimit-remaining"] === "0") {
    return new OpsError("github_rate_limited", `${what}: GitHub oran sınırı aşıldı${resp.headers["x-ratelimit-reset"] ? ` (sıfırlanma ${resp.headers["x-ratelimit-reset"]})` : ""}`);
  }
  if (resp.status === 403) return new OpsError("github_forbidden", `${what}: erişim yok (belirtecin izni eksik)${msg ? ` — ${msg}` : ""}`);
  if (resp.status === 404) return new OpsError("github_not_found", `${what}: bulunamadı veya erişim yok`);
  return new OpsError("github_error", `${what}: HTTP ${resp.status}${msg ? ` — ${msg}` : ""}`);
}
