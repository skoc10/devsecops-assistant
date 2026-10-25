import { readFile } from "node:fs/promises";
import { Agent, request } from "node:https";
import { parse } from "yaml";
import { buildKubeconfig } from "./kubeconfig.ts";

/**
 * Gerçek Kubernetes kümesi (CI'da `kind`) için YÖNETİCİ istemcisi: yalnız test kurulumu/doğrulaması içindir
 * (namespace, RBAC, tohum nesneleri, ServiceAccount token'ı). Ürün kodu bunu KULLANMAZ; ürün kimliği
 * `ops profile add k8s` ile içe aktarılan kubeconfig'ten gelir.
 *
 * Küme `OPS_TEST_KUBECONFIG` (yönetici kubeconfig yolu; `kind get kubeconfig`) ile verilir. Değişken yoksa
 * `null` döner ve testler atlanır; değişken VARSA ama küme erişilemiyorsa hata fırlatılır (CI'da sessiz
 * atlama olmasın — ayrıca atlanan test kapısı işi düşürür).
 */

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

export interface KindResponse {
  readonly status: number;
  readonly body: string;
  /** Gövde JSON ise ayrıştırılmış hali; değilse `undefined`. */
  readonly json: any;
}

/** Test kurulumunun bildiği türler (yol kurmak için). Ürünün kapalı tür listesiyle ilgisi yoktur. */
const KINDS: Readonly<Record<string, { plural: string; namespaced: boolean }>> = {
  Namespace: { plural: "namespaces", namespaced: false },
  ServiceAccount: { plural: "serviceaccounts", namespaced: true },
  ConfigMap: { plural: "configmaps", namespaced: true },
  Secret: { plural: "secrets", namespaced: true },
  Pod: { plural: "pods", namespaced: true },
  Deployment: { plural: "deployments", namespaced: true },
  ReplicaSet: { plural: "replicasets", namespaced: true },
  Role: { plural: "roles", namespaced: true },
  RoleBinding: { plural: "rolebindings", namespaced: true },
  ClusterRole: { plural: "clusterroles", namespaced: false },
  ClusterRoleBinding: { plural: "clusterrolebindings", namespaced: false },
};

/** `apiVersion` + `kind` (+ namespace/ad) → API yolu. */
export function kindPath(apiVersion: string, kind: string, namespace?: string, name?: string): string {
  const k = KINDS[kind];
  if (!k) throw new Error(`kind yardımcısı bu türü bilmiyor: ${kind}`);
  const base = apiVersion === "v1" ? "/api/v1" : `/apis/${apiVersion}`;
  const ns = k.namespaced ? `/namespaces/${encodeURIComponent(namespace ?? "")}` : "";
  return `${base}${ns}/${k.plural}${name ? `/${encodeURIComponent(name)}` : ""}`;
}

function pathOfObject(o: Obj): string {
  const meta = isObj(o["metadata"]) ? o["metadata"] : {};
  return kindPath(String(o["apiVersion"]), String(o["kind"]), typeof meta["namespace"] === "string" ? meta["namespace"] : undefined, String(meta["name"]));
}

export interface KindCluster {
  /** API sunucusu (ör. `https://127.0.0.1:34567`). */
  readonly server: string;
  /** Küme CA'sı (PEM). */
  readonly caPem: string;
  /** Yönetici kimliğiyle ham istek. */
  api(method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown, contentType?: string): Promise<KindResponse>;
  /** Nesneyi server-side apply ile uygular (`force=true`; verilen alan yöneticisiyle). 2xx değilse hata. */
  apply(obj: Obj, fieldManager?: string): Promise<any>;
  /** Çok belgeli YAML'ı (ör. `generateReadOnlyRbac` çıktısı) belge belge uygular. */
  applyYaml(text: string, fieldManager?: string): Promise<any[]>;
  get(apiVersion: string, kind: string, namespace: string | undefined, name: string): Promise<any | null>;
  remove(apiVersion: string, kind: string, namespace: string | undefined, name: string): Promise<void>;
  /** ServiceAccount için kısa ömürlü token (TokenRequest). */
  token(namespace: string, serviceAccount: string, seconds?: number): Promise<string>;
  /** Yalnız token taşıyan (yönetici sertifikası İÇERMEYEN) tek bağlamlı kubeconfig metni. */
  kubeconfigFor(token: string, opts?: { namespace?: string; contextName?: string }): string;
  /** `fn` değer döndürene (falsy olmayan) kadar yoklar; süre dolarsa son durumu içeren hata. */
  waitFor<T>(what: string, fn: () => Promise<T | null | undefined | false>, timeoutMs?: number): Promise<T>;
  close(): void;
}

const b64d = (s: string): string => Buffer.from(s, "base64").toString("utf8");

/** `OPS_TEST_KUBECONFIG` ile verilen kümeye bağlanır; değişken yoksa `null` (testler atlanır). */
export async function connectKindCluster(env: Readonly<Record<string, string | undefined>> = process.env): Promise<KindCluster | null> {
  const file = env["OPS_TEST_KUBECONFIG"];
  if (!file) return null;
  const doc = parse(await readFile(file, "utf8")) as Obj;
  const ctxName = String(doc["current-context"] ?? "");
  const ctx = (Array.isArray(doc["contexts"]) ? doc["contexts"] : []).filter(isObj).find((c) => c["name"] === ctxName);
  if (!ctx || !isObj(ctx["context"])) throw new Error(`OPS_TEST_KUBECONFIG: current-context bulunamadı (${ctxName})`);
  const cx = ctx["context"];
  const cluster = (Array.isArray(doc["clusters"]) ? doc["clusters"] : []).filter(isObj).find((c) => c["name"] === cx["cluster"]);
  const user = (Array.isArray(doc["users"]) ? doc["users"] : []).filter(isObj).find((u) => u["name"] === cx["user"]);
  if (!cluster || !isObj(cluster["cluster"]) || !user || !isObj(user["user"])) throw new Error("OPS_TEST_KUBECONFIG: küme/kullanıcı girdisi eksik");
  const cl = cluster["cluster"];
  const us = user["user"];
  const server = String(cl["server"] ?? "");
  const caPem = typeof cl["certificate-authority-data"] === "string" ? b64d(cl["certificate-authority-data"]) : "";
  const cert = typeof us["client-certificate-data"] === "string" ? b64d(us["client-certificate-data"]) : undefined;
  const key = typeof us["client-key-data"] === "string" ? b64d(us["client-key-data"]) : undefined;
  const bearer = typeof us["token"] === "string" ? us["token"] : undefined;
  if (!server.startsWith("https://") || !caPem) throw new Error("OPS_TEST_KUBECONFIG: https sunucusu ve certificate-authority-data gerekli");
  if (!(cert && key) && !bearer) throw new Error("OPS_TEST_KUBECONFIG: yönetici kimliği (istemci sertifikası veya token) yok");

  const url = new URL(server);
  const agent = new Agent({ keepAlive: true, maxSockets: 8, ca: caPem, ...(cert && key ? { cert, key } : {}) });

  const api: KindCluster["api"] = (method, path, body, contentType = "application/json") =>
    new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
      const req = request(
        {
          host: url.hostname.replace(/^\[|\]$/g, ""),
          port: url.port ? Number(url.port) : 443,
          method,
          path,
          agent,
          timeout: 30_000,
          headers: {
            accept: "application/json",
            ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
            ...(payload !== undefined ? { "content-type": contentType, "content-length": String(Buffer.byteLength(payload)) } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let json: unknown;
            try {
              json = JSON.parse(text);
            } catch {
              json = undefined;
            }
            resolve({ status: res.statusCode ?? 0, body: text, json });
          });
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new Error(`kind API zaman aşımı: ${method} ${path}`)));
      req.on("error", reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });

  const must = (r: KindResponse, what: string): any => {
    if (r.status < 200 || r.status >= 300) throw new Error(`${what}: HTTP ${r.status} ${r.body.slice(0, 400)}`);
    return r.json;
  };

  const version = await api("GET", "/version");
  must(version, "kind kümesine bağlanılamadı (/version)");

  const apply: KindCluster["apply"] = async (o, fieldManager = "ops-it-admin") =>
    must(await api("PATCH", `${pathOfObject(o)}?fieldManager=${encodeURIComponent(fieldManager)}&force=true`, o, "application/apply-patch+yaml"), `uygula ${String(o["kind"])}`);

  const handle: KindCluster = {
    server,
    caPem,
    api,
    apply,
    async applyYaml(text, fieldManager) {
      const out: any[] = [];
      for (const part of text.split(/^---\s*$/m)) {
        const o = parse(part) as unknown;
        if (isObj(o)) out.push(await apply(o, fieldManager));
      }
      return out;
    },
    async get(apiVersion, kind, namespace, name) {
      const r = await api("GET", kindPath(apiVersion, kind, namespace, name));
      if (r.status === 404) return null;
      return must(r, `getir ${kind}/${name}`);
    },
    async remove(apiVersion, kind, namespace, name) {
      const r = await api("DELETE", kindPath(apiVersion, kind, namespace, name), { kind: "DeleteOptions", apiVersion: "v1", propagationPolicy: "Background" });
      if (r.status !== 404) must(r, `sil ${kind}/${name}`);
    },
    async token(namespace, serviceAccount, seconds = 3600) {
      const j = must(
        await api("POST", `${kindPath("v1", "ServiceAccount", namespace, serviceAccount)}/token`, { apiVersion: "authentication.k8s.io/v1", kind: "TokenRequest", spec: { expirationSeconds: seconds } }),
        `token ${namespace}/${serviceAccount}`,
      );
      const t = j?.status?.token;
      if (typeof t !== "string" || t.length < 20) throw new Error("TokenRequest token döndürmedi");
      return t;
    },
    kubeconfigFor(token, opts = {}) {
      return buildKubeconfig({ server, caPem, token, ...(opts.namespace ? { namespace: opts.namespace } : {}), ...(opts.contextName ? { contextName: opts.contextName } : {}) });
    },
    async waitFor(what, fn, timeoutMs = 120_000) {
      const end = Date.now() + timeoutMs;
      let last: unknown;
      for (;;) {
        try {
          const v = await fn();
          if (v) return v as never;
          last = v;
        } catch (e) {
          last = e;
        }
        if (Date.now() > end) throw new Error(`zaman aşımı (${timeoutMs} ms): ${what}; son durum: ${last instanceof Error ? last.message : JSON.stringify(last)}`);
        await new Promise((r) => setTimeout(r, 1_000));
      }
    },
    close() {
      agent.destroy();
    },
  };
  return handle;
}
