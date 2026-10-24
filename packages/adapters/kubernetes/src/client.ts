import { X509Certificate } from "node:crypto";
import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { OpsError, normalizeEndpoint } from "@ops/contracts";
import type { TargetPin } from "@ops/contracts";
import type { KubeCredential } from "@ops/broker";

/** İzin verilen inceleme (review) uç noktaları: POST yalnız bunlara gider, gövde araç tarafından kurulur. */
export const REVIEW_PATHS = {
  selfSubject: "/apis/authentication.k8s.io/v1/selfsubjectreviews",
  selfRules: "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
} as const;
export type ReviewKind = keyof typeof REVIEW_PATHS;

export interface ClientOptions {
  /** Yanıt gövdesi üst sınırı (bayt); aşılırsa bağlantı kesilir. */
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface ApiResponse {
  readonly status: number;
  readonly body: string;
  readonly contentType: string;
}

function firstPem(pem: string): string {
  const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
  return m ? m[0] : "";
}

/** Profil pini ile kimlik materyalinin uyuşması: kimlik pin dışı bir hosta ASLA gönderilmez (T10). */
export function assertPinned(cred: KubeCredential, pin: TargetPin): void {
  if (normalizeEndpoint(cred.server) !== normalizeEndpoint(pin.endpoint)) {
    throw new OpsError("target_pin_mismatch", "kasadaki kimliğin sunucusu profilin pinli uç noktasıyla eşleşmiyor; kimlik gönderilmedi");
  }
  if (pin.caFingerprint !== undefined) {
    if (!cred.caPem) throw new OpsError("target_pin_mismatch", "profil CA parmak izi pinli ama kimlikte CA verisi yok; kimlik gönderilmedi");
    let fp: string;
    try {
      fp = new X509Certificate(firstPem(cred.caPem)).fingerprint256.replace(/:/g, "").toLowerCase();
    } catch {
      throw new OpsError("target_pin_mismatch", "kimlikteki CA sertifikası okunamadı; kimlik gönderilmedi");
    }
    if (fp !== pin.caFingerprint) {
      throw new OpsError("target_pin_mismatch", "kimlikteki CA parmak izi profilin pinli parmak iziyle eşleşmiyor; kimlik gönderilmedi");
    }
  }
}

/**
 * Asgari Kubernetes API istemcisi. Bilerek dar:
 *  - yalnız GET (+ izinli inceleme uç noktalarına POST): mutasyon fiili YAPISAL olarak yok;
 *  - yalnız https, TLS doğrulaması kapatılamaz; yalnız kimlikteki CA güvenilir sayılır;
 *  - yönlendirme izlenmez (kimlik başka hosta gitmesin); ortam proxy'si kullanılmaz;
 *  - yanıt boyutu ve süre sınırlı; iptal sinyali bağlanır.
 */
export class K8sClient {
  private readonly url: URL;
  private readonly agent: Agent;
  private readonly cred: KubeCredential;
  private readonly opts: ClientOptions;

  constructor(cred: KubeCredential, pin: TargetPin, opts: ClientOptions) {
    assertPinned(cred, pin);
    const url = new URL(cred.server);
    if (url.protocol !== "https:") throw new OpsError("target_pin_mismatch", "yalnız https sunucuları desteklenir");
    this.url = url;
    this.cred = cred;
    this.opts = opts;
    this.agent = new Agent({ keepAlive: false, maxSockets: 4 });
  }

  close(): void {
    this.agent.destroy();
  }

  get(path: string, query: Record<string, string | number | boolean | undefined> = {}, accept = "application/json"): Promise<ApiResponse> {
    return this.exec("GET", path, query, accept);
  }

  /** İzinli inceleme uç noktalarına POST (SelfSubject*Review). Başka yola POST yoktur. */
  review(kind: ReviewKind, body: unknown): Promise<ApiResponse> {
    return this.exec("POST", REVIEW_PATHS[kind], {}, "application/json", JSON.stringify(body));
  }

  private exec(
    method: "GET" | "POST",
    path: string,
    query: Record<string, string | number | boolean | undefined>,
    accept: string,
    body?: string,
  ): Promise<ApiResponse> {
    if (!path.startsWith("/api") && !path.startsWith("/version")) {
      return Promise.reject(new OpsError("path_refused", "yalnız /api, /apis ve /version yolları"));
    }
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined) qs.set(k, String(v));
    const fullPath = qs.size > 0 ? `${path}?${qs.toString()}` : path;
    const host = this.url.hostname.replace(/^\[|\]$/g, "");
    const headers: Record<string, string> = { accept, "user-agent": "ops-assistant", ...(body !== undefined ? { "content-type": "application/json" } : {}) };
    if (this.cred.token) headers["authorization"] = `Bearer ${this.cred.token}`;

    return new Promise<ApiResponse>((resolve, reject) => {
      const servername = this.cred.tlsServerName ?? (isIP(host) ? undefined : host);
      const req = request(
        {
          host,
          port: this.url.port ? Number(this.url.port) : 443,
          path: fullPath,
          method,
          headers,
          agent: this.agent,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          ...(servername ? { servername } : {}),
          ...(this.cred.caPem ? { ca: this.cred.caPem } : {}),
          ...(this.cred.clientCertPem && this.cred.clientKeyPem ? { cert: this.cred.clientCertPem, key: this.cred.clientKeyPem } : {}),
          timeout: this.opts.timeoutMs,
          ...(this.opts.signal ? { signal: this.opts.signal } : {}),
        },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) {
            res.resume();
            reject(new OpsError("redirect_refused", "sunucu yönlendirme istedi; yönlendirmeler izlenmez"));
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > this.opts.maxBytes) {
              req.destroy(new OpsError("response_too_large", `yanıt ${this.opts.maxBytes} bayt sınırını aştı; seçici/limit ile daraltın`));
              return;
            }
            chunks.push(c);
          });
          res.on("end", () =>
            resolve({ status, body: Buffer.concat(chunks).toString("utf8"), contentType: String(res.headers["content-type"] ?? "") }),
          );
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new OpsError("timeout", "API isteği zaman aşımına uğradı")));
      req.on("error", (e) => reject(e instanceof OpsError ? e : new OpsError("k8s_connect_error", e.message)));
      if (body !== undefined) req.write(body);
      req.end();
    });
  }
}

/** API hata gövdesini (Status) kullanıcıya anlamlı, secret içermeyen kısa mesaja çevirir. */
export function apiErrorMessage(resp: ApiResponse, what: string): string {
  let reason = "";
  let message = "";
  try {
    const j = JSON.parse(resp.body) as { reason?: string; message?: string };
    reason = j.reason ?? "";
    message = (j.message ?? "").slice(0, 200);
  } catch {
    message = resp.body.slice(0, 120);
  }
  if (resp.status === 401) return `kimlik doğrulanamadı (401) — ${what}`;
  if (resp.status === 403) return `yetki yok (403, RBAC) — ${what}${message ? `: ${message}` : ""}`;
  if (resp.status === 404) return `bulunamadı (404) — ${what}`;
  return `API hatası ${resp.status}${reason ? ` ${reason}` : ""} — ${what}${message ? `: ${message}` : ""}`;
}
