import { createServer } from "node:https";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { TestPki } from "./pki.ts";

/** Sahte API sunucusunun bildiği kaynak türleri (gerçek tablodan bağımsız: adapter hatasını yakalar). */
interface Res {
  readonly kind: string;
  readonly plural: string;
  readonly apiVersion: string;
  readonly namespaced: boolean;
}
const RESOURCES: readonly Res[] = [
  { kind: "Pod", plural: "pods", apiVersion: "v1", namespaced: true },
  { kind: "Service", plural: "services", apiVersion: "v1", namespaced: true },
  { kind: "Endpoints", plural: "endpoints", apiVersion: "v1", namespaced: true },
  { kind: "ConfigMap", plural: "configmaps", apiVersion: "v1", namespaced: true },
  { kind: "Secret", plural: "secrets", apiVersion: "v1", namespaced: true },
  { kind: "ServiceAccount", plural: "serviceaccounts", apiVersion: "v1", namespaced: true },
  { kind: "PersistentVolumeClaim", plural: "persistentvolumeclaims", apiVersion: "v1", namespaced: true },
  { kind: "ResourceQuota", plural: "resourcequotas", apiVersion: "v1", namespaced: true },
  { kind: "LimitRange", plural: "limitranges", apiVersion: "v1", namespaced: true },
  { kind: "Event", plural: "events", apiVersion: "v1", namespaced: true },
  { kind: "Node", plural: "nodes", apiVersion: "v1", namespaced: false },
  { kind: "Namespace", plural: "namespaces", apiVersion: "v1", namespaced: false },
  { kind: "PersistentVolume", plural: "persistentvolumes", apiVersion: "v1", namespaced: false },
  { kind: "Deployment", plural: "deployments", apiVersion: "apps/v1", namespaced: true },
  { kind: "ReplicaSet", plural: "replicasets", apiVersion: "apps/v1", namespaced: true },
  { kind: "StatefulSet", plural: "statefulsets", apiVersion: "apps/v1", namespaced: true },
  { kind: "DaemonSet", plural: "daemonsets", apiVersion: "apps/v1", namespaced: true },
  { kind: "Job", plural: "jobs", apiVersion: "batch/v1", namespaced: true },
  { kind: "CronJob", plural: "cronjobs", apiVersion: "batch/v1", namespaced: true },
  { kind: "Ingress", plural: "ingresses", apiVersion: "networking.k8s.io/v1", namespaced: true },
  { kind: "NetworkPolicy", plural: "networkpolicies", apiVersion: "networking.k8s.io/v1", namespaced: true },
  { kind: "HorizontalPodAutoscaler", plural: "horizontalpodautoscalers", apiVersion: "autoscaling/v2", namespaced: true },
  { kind: "PodDisruptionBudget", plural: "poddisruptionbudgets", apiVersion: "policy/v1", namespaced: true },
  { kind: "StorageClass", plural: "storageclasses", apiVersion: "storage.k8s.io/v1", namespaced: false },
];

export type K8sObject = Record<string, unknown> & {
  kind: string;
  apiVersion?: string;
  metadata: Record<string, unknown> & { name: string; namespace?: string };
};

export interface RecordedRequest {
  readonly method: string;
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  readonly accept: string;
  /** Bearer değeri YAKALANIR: testler "doğru kimlik doğru hosta gitti" der. */
  readonly bearer: string | null;
  readonly clientCertVerified: boolean;
  readonly body: string;
}

export interface FakeK8sOptions {
  readonly pki: TestPki;
  /** Verilirse `Authorization: Bearer <token>` zorunlu. */
  readonly token?: string;
  /** İstemci sertifikası zorunlu (CA ile doğrulanmış). */
  readonly requireClientCert?: boolean;
  readonly now?: () => Date;
  /** Kimliği doğrulanan kullanıcı adı (selfsubjectreviews yanıtı). */
  readonly username?: string;
  /** Yazma fiilleri (PATCH/DELETE) 403 Forbidden döner (salt okunur RBAC simülasyonu). */
  readonly readOnly?: boolean;
}

export interface FakeRule {
  verbs: string[];
  apiGroups: string[];
  resources: string[];
  resourceNames?: string[];
}
export interface FakeRulesStatus {
  resourceRules: FakeRule[];
  incomplete?: boolean;
  evaluationError?: string;
}

/** Varsayılan: salt okunur kimlik (Secret yok, yazma yok, exec yok). */
export const READONLY_RULES: FakeRulesStatus = {
  resourceRules: [
    { verbs: ["get", "list", "watch"], apiGroups: [""], resources: ["pods", "pods/log", "services", "endpoints", "configmaps", "events", "nodes", "namespaces"] },
    { verbs: ["get", "list", "watch"], apiGroups: ["apps"], resources: ["deployments", "replicasets", "statefulsets", "daemonsets"] },
    { verbs: ["get", "list", "watch"], apiGroups: ["batch", "autoscaling", "policy"], resources: ["jobs", "cronjobs", "horizontalpodautoscalers", "poddisruptionbudgets"] },
  ],
};

/**
 * Gerçek kümede `system:basic-user` (system:authenticated grubuna bağlı) her kimliğe öz-inceleme `create`
 * yetkisi verir; SelfSubjectRulesReview bunları her zaman döndürür. Sahte API de döndürür (kind testinde bulundu).
 */
export const BASIC_USER_RULES: readonly FakeRule[] = [
  { verbs: ["create"], apiGroups: ["authorization.k8s.io"], resources: ["selfsubjectaccessreviews", "selfsubjectrulesreviews"] },
  { verbs: ["create"], apiGroups: ["authentication.k8s.io"], resources: ["selfsubjectreviews"] },
];

interface LogEntry {
  readonly ts: Date;
  readonly text: string;
}

const statusBody = (code: number, reason: string, message: string): string =>
  JSON.stringify({ kind: "Status", apiVersion: "v1", status: "Failure", message, reason, code, metadata: {} });

function lookup(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function matchesSelectors(obj: K8sObject, labelSelector: string | undefined, fieldSelector: string | undefined): boolean {
  const labels = (obj.metadata["labels"] ?? {}) as Record<string, string>;
  for (const part of (labelSelector ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const ne = part.match(/^([^!=]+)!=(.*)$/);
    const eq = part.match(/^([^!=]+)==?(.*)$/);
    if (ne) {
      if (labels[ne[1] as string] === ne[2]) return false;
    } else if (eq) {
      if (labels[eq[1] as string] !== eq[2]) return false;
    } else if (!(part in labels)) {
      return false;
    }
  }
  for (const part of (fieldSelector ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const ne = part.match(/^([^!=]+)!=(.*)$/);
    const eq = part.match(/^([^!=]+)==?(.*)$/);
    const m = ne ?? eq;
    if (!m) return false;
    const v = lookup(obj, m[1] as string);
    const same = String(v ?? "") === m[2];
    if (ne ? same : !same) return false;
  }
  return true;
}

export class FakeK8sApi {
  readonly requests: RecordedRequest[] = [];
  readonly url: string;
  private readonly store = new Map<string, K8sObject>();
  private readonly logs = new Map<string, LogEntry[]>();
  private readonly faults = new Map<string, (res: ServerResponse) => void>();
  private readonly rules = new Map<string, FakeRulesStatus>();
  private readonly sockets = new Set<Socket>();
  private readonly now: () => Date;

  private readonly server: Server;
  private readonly opts: FakeK8sOptions;

  private constructor(server: Server, opts: FakeK8sOptions, port: number) {
    this.server = server;
    this.opts = opts;
    this.url = `https://127.0.0.1:${port}`;
    this.now = opts.now ?? (() => new Date());
  }

  static async start(opts: FakeK8sOptions): Promise<FakeK8sApi> {
    let self: FakeK8sApi | undefined;
    const server = createServer(
      {
        key: opts.pki.serverKeyPem,
        cert: opts.pki.serverCertPem,
        ca: opts.pki.caPem,
        requestCert: opts.requireClientCert === true,
        rejectUnauthorized: false,
        minVersion: "TLSv1.2",
      },
      (req, res) => void self?.handle(req, res),
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    self = new FakeK8sApi(server, opts, port);
    server.on("connection", (s) => {
      self?.sockets.add(s);
      s.on("close", () => self?.sockets.delete(s));
    });
    return self;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  // ---- kurulum -----------------------------------------------------------------------------

  private key(kind: string, ns: string | undefined, name: string): string {
    return `${kind}/${ns ?? ""}/${name}`;
  }

  add(obj: K8sObject): this {
    const res = RESOURCES.find((r) => r.kind === obj.kind);
    if (!res) throw new Error(`sahte API bu türü bilmiyor: ${obj.kind}`);
    // gerçek API sunucusu her nesneye uid ve resourceVersion verir (TOCTOU/ön koşul testleri bunlara dayanır)
    const meta = { ...obj.metadata, uid: obj.metadata["uid"] ?? `uid-${obj.metadata.name}`, resourceVersion: obj.metadata["resourceVersion"] ?? "1" };
    const full: K8sObject = { ...obj, apiVersion: obj.apiVersion ?? res.apiVersion, metadata: meta };
    this.store.set(this.key(obj.kind, obj.metadata.namespace, obj.metadata.name), full);
    return this;
  }

  setLog(ns: string, pod: string, entries: readonly (string | LogEntry)[], opts: { container?: string; previous?: boolean } = {}): this {
    const base = this.now().getTime();
    const list = entries.map((e, i) =>
      typeof e === "string" ? { ts: new Date(base - (entries.length - i) * 1000), text: e } : e,
    );
    this.logs.set(`${ns}/${pod}/${opts.container ?? ""}/${opts.previous ? "prev" : "cur"}`, list);
    return this;
  }

  /** Yol önekine uyan isteklere belirli bir yanıt verir (ör. 403 RBAC, yönlendirme, dev gövde). */
  fault(pathPrefix: string, responder: (res: ServerResponse) => void): this {
    this.faults.set(pathPrefix, responder);
    return this;
  }

  /** SelfSubjectRulesReview yanıtı: namespace'e özel veya `*` (varsayılan). */
  setRules(namespace: string, status: FakeRulesStatus): this {
    this.rules.set(namespace, status);
    return this;
  }

  clearRequests(): void {
    this.requests.length = 0;
  }

  // ---- işleyici ----------------------------------------------------------------------------

  private send(res: ServerResponse, code: number, body: string, type = "application/json"): void {
    res.writeHead(code, { "content-type": type });
    res.end(body);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", this.url);
    const query = Object.fromEntries(url.searchParams.entries());
    const auth = req.headers.authorization;
    const bearer = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : null;
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    const verified = (req.socket as TLSSocket).authorized === true;
    this.requests.push({
      method: req.method ?? "GET",
      path: url.pathname,
      query,
      accept: String(req.headers.accept ?? ""),
      bearer,
      clientCertVerified: verified,
      body,
    });

    for (const [prefix, responder] of this.faults) {
      if (url.pathname.startsWith(prefix)) return responder(res);
    }

    if (this.opts.token !== undefined && bearer !== this.opts.token) {
      return this.send(res, 401, statusBody(401, "Unauthorized", "Unauthorized"));
    }
    if (this.opts.requireClientCert && !verified) {
      return this.send(res, 401, statusBody(401, "Unauthorized", "client certificate required"));
    }

    const method = req.method ?? "GET";
    if (method === "POST") return this.handlePost(url.pathname, body, res, query);
    if (method === "PATCH" || method === "DELETE") {
      if (this.opts.readOnly) return this.send(res, 403, statusBody(403, "Forbidden", `${method === "PATCH" ? "patch" : "delete"} is forbidden for this user`));
      return method === "PATCH"
        ? this.handlePatch(url.pathname, query, body, String(req.headers["content-type"] ?? ""), res)
        : this.handleDelete(url.pathname, query, body, res);
    }
    if (method !== "GET") return this.send(res, 405, statusBody(405, "MethodNotAllowed", "method not allowed"));

    if (url.pathname === "/version") return this.send(res, 200, JSON.stringify({ major: "1", minor: "31", gitVersion: "v1.31.0-fake" }));

    // /api/v1/... veya /apis/<group>/<version>/...
    const segs = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    let rest: string[];
    let apiVersion: string;
    if (segs[0] === "api" && segs[1] === "v1") {
      apiVersion = "v1";
      rest = segs.slice(2);
    } else if (segs[0] === "apis" && segs.length >= 3) {
      apiVersion = `${segs[1]}/${segs[2]}`;
      rest = segs.slice(3);
    } else {
      return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
    }

    let ns: string | undefined;
    if (rest[0] === "namespaces" && rest.length >= 3) {
      ns = rest[1];
      rest = rest.slice(2);
    }
    const plural = rest[0];
    const name = rest[1];
    const sub = rest[2];
    const resource = RESOURCES.find((r) => r.plural === plural && r.apiVersion === apiVersion);
    if (!resource) return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
    if (resource.namespaced && ns === undefined && name !== undefined) {
      return this.send(res, 404, statusBody(404, "NotFound", "namespace required"));
    }

    const asTable = /as=Table/.test(String(req.headers.accept ?? ""));

    // log alt kaynağı
    if (name && sub === "log" && resource.kind === "Pod") {
      const pod = this.store.get(this.key("Pod", ns, name));
      if (!pod) return this.send(res, 404, statusBody(404, "NotFound", `pods "${name}" not found`));
      const container = query["container"] ?? "";
      const prev = query["previous"] === "true";
      const entries = this.logs.get(`${ns}/${name}/${container}/${prev ? "prev" : "cur"}`) ?? this.logs.get(`${ns}/${name}//${prev ? "prev" : "cur"}`) ?? [];
      let sel = entries;
      if (query["sinceSeconds"]) {
        const from = this.now().getTime() - Number(query["sinceSeconds"]) * 1000;
        sel = sel.filter((e) => e.ts.getTime() >= from);
      }
      if (query["tailLines"]) sel = sel.slice(-Number(query["tailLines"]));
      let text = sel.map((e) => (query["timestamps"] === "true" ? `${e.ts.toISOString()} ${e.text}` : e.text)).join("\n");
      if (text) text += "\n";
      if (query["limitBytes"]) text = Buffer.from(text, "utf8").subarray(0, Number(query["limitBytes"])).toString("utf8");
      return this.send(res, 200, text, "text/plain");
    }

    if (name) {
      const obj = this.store.get(this.key(resource.kind, resource.namespaced ? ns : undefined, name));
      if (!obj) return this.send(res, 404, statusBody(404, "NotFound", `${resource.plural} "${name}" not found`));
      if (sub === "scale") return this.send(res, 200, JSON.stringify(this.scaleOf(obj)));
      if (asTable) return this.send(res, 200, JSON.stringify(this.table(resource, [obj])));
      return this.send(res, 200, JSON.stringify(obj));
    }

    // liste
    let items = [...this.store.values()].filter(
      (o) => o.kind === resource.kind && (!resource.namespaced || ns === undefined || o.metadata.namespace === ns),
    );
    items = items.filter((o) => matchesSelectors(o, query["labelSelector"], query["fieldSelector"]));
    items.sort((a, b) => a.metadata.name.localeCompare(b.metadata.name));
    const limit = query["limit"] ? Number(query["limit"]) : items.length;
    const offset = query["continue"] ? Number(Buffer.from(query["continue"], "base64").toString("utf8")) : 0;
    const page = items.slice(offset, offset + limit);
    const more = offset + limit < items.length;
    const meta: Record<string, unknown> = { resourceVersion: "1" };
    if (more) {
      meta["continue"] = Buffer.from(String(offset + limit)).toString("base64");
      meta["remainingItemCount"] = items.length - offset - limit;
    }
    if (asTable) return this.send(res, 200, JSON.stringify({ ...(this.table(resource, page) as object), metadata: meta }));
    // gerçek API liste öğelerinde kind/apiVersion taşımaz
    const stripped = page.map(({ kind: _k, apiVersion: _a, ...o }) => o);
    return this.send(res, 200, JSON.stringify({ kind: `${resource.kind}List`, apiVersion, metadata: meta, items: stripped }));
  }

  /** Sunucu tarafı tablo: Secret için YALNIZ ad/tür/veri SAYISI (değer asla). */
  private table(resource: Res, objs: readonly K8sObject[]): unknown {
    const isSecret = resource.kind === "Secret";
    const columnDefinitions = isSecret
      ? [{ name: "Name", type: "string" }, { name: "Type", type: "string" }, { name: "Data", type: "integer" }, { name: "Age", type: "string" }]
      : [{ name: "Name", type: "string" }, { name: "Age", type: "string" }];
    const rows = objs.map((o) => ({
      cells: isSecret
        ? [o.metadata.name, String(o["type"] ?? "Opaque"), Object.keys((o["data"] ?? {}) as object).length, "1d"]
        : [o.metadata.name, "1d"],
      object: { kind: "PartialObjectMetadata", apiVersion: "meta.k8s.io/v1", metadata: { ...o.metadata } },
    }));
    return { kind: "Table", apiVersion: "meta.k8s.io/v1", columnDefinitions, rows };
  }

  // ---- yazma (Faz 2b): iyimser eşzamanlılık (resourceVersion), dryRun, silme ön koşulları -------

  private route(pathname: string): { res: Res; ns: string | undefined; name: string | undefined; sub: string | undefined } | null {
    const segs = pathname.split("/").filter(Boolean).map(decodeURIComponent);
    let rest: string[];
    let apiVersion: string;
    if (segs[0] === "api" && segs[1] === "v1") {
      apiVersion = "v1";
      rest = segs.slice(2);
    } else if (segs[0] === "apis" && segs.length >= 3) {
      apiVersion = `${segs[1]}/${segs[2]}`;
      rest = segs.slice(3);
    } else return null;
    let ns: string | undefined;
    if (rest[0] === "namespaces" && rest.length >= 3) {
      ns = rest[1];
      rest = rest.slice(2);
    }
    const res = RESOURCES.find((r) => r.plural === rest[0] && r.apiVersion === apiVersion);
    return res ? { res, ns, name: rest[1], sub: rest[2] } : null;
  }

  private rvOf(o: K8sObject): number {
    return Number(o.metadata["resourceVersion"] ?? 1);
  }

  private scaleOf(o: K8sObject): unknown {
    const spec = (o["spec"] ?? {}) as Record<string, unknown>;
    return {
      kind: "Scale",
      apiVersion: "autoscaling/v1",
      metadata: { name: o.metadata.name, namespace: o.metadata.namespace, resourceVersion: String(this.rvOf(o)), uid: o.metadata["uid"] },
      spec: { replicas: spec["replicas"] ?? 1 },
      status: { replicas: spec["replicas"] ?? 1 },
    };
  }

  private merge(a: unknown, b: unknown): unknown {
    if (b === null) return undefined;
    if (b === undefined) return a;
    if (Array.isArray(b) || typeof b !== "object") return b;
    const out: Record<string, unknown> = a && typeof a === "object" && !Array.isArray(a) ? { ...(a as Record<string, unknown>) } : {};
    for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
      const m = this.merge(out[k], v);
      if (m === undefined) delete out[k];
      else out[k] = m;
    }
    return out;
  }

  private handlePatch(path: string, query: Record<string, string>, body: string, contentType: string, res: ServerResponse): void {
    const r = this.route(path);
    if (!r || !r.name) return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
    if (contentType.startsWith("application/json-patch+json")) {
      const cur0 = this.store.get(this.key(r.res.kind, r.res.namespaced ? r.ns : undefined, r.name));
      if (!cur0) return this.send(res, 404, statusBody(404, "NotFound", `${r.res.plural} "${r.name}" not found`));
      let ops: unknown;
      try {
        ops = JSON.parse(body);
      } catch {
        return this.send(res, 400, statusBody(400, "BadRequest", "invalid patch body"));
      }
      const out = this.applyJsonPatch(cur0, ops);
      if (!out.ok) return this.send(res, out.code, statusBody(out.code, "Invalid", out.msg));
      out.obj.metadata = { ...out.obj.metadata, resourceVersion: String(this.rvOf(cur0) + 1) };
      if (query["dryRun"] !== "All") this.store.set(this.key(r.res.kind, r.res.namespaced ? r.ns : undefined, r.name), out.obj);
      return this.send(res, 200, JSON.stringify(out.obj));
    }
    let patch: Record<string, unknown>;
    try {
      patch = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return this.send(res, 400, statusBody(400, "BadRequest", "invalid patch body"));
    }
    const isApply = contentType.startsWith("application/apply-patch+yaml");
    if (!isApply && !contentType.startsWith("application/merge-patch+json") && !contentType.startsWith("application/strategic-merge-patch+json")) {
      return this.send(res, 415, statusBody(415, "UnsupportedMediaType", `unsupported patch type ${contentType.slice(0, 60)}`));
    }
    if (isApply && !query["fieldManager"]) return this.send(res, 400, statusBody(400, "BadRequest", "fieldManager is required for apply"));
    const key = this.key(r.res.kind, r.res.namespaced ? r.ns : undefined, r.name);
    const cur = this.store.get(key);
    const dry = query["dryRun"] === "All";

    const wantedRv = (patch["metadata"] as Record<string, unknown> | undefined)?.["resourceVersion"];
    if (wantedRv !== undefined && cur && String(wantedRv) !== String(this.rvOf(cur))) {
      return this.send(res, 409, statusBody(409, "Conflict", `Operation cannot be fulfilled on ${r.res.plural} "${r.name}": the object has been modified; please apply your changes to the latest version and try again`));
    }
    if (!cur && !isApply) return this.send(res, 404, statusBody(404, "NotFound", `${r.res.plural} "${r.name}" not found`));

    let next: K8sObject;
    if (r.sub === "scale") {
      if (!cur) return this.send(res, 404, statusBody(404, "NotFound", `${r.res.plural} "${r.name}" not found`));
      const replicas = (patch["spec"] as Record<string, unknown> | undefined)?.["replicas"];
      if (typeof replicas !== "number") return this.send(res, 422, statusBody(422, "Invalid", "spec.replicas required"));
      next = this.merge(cur, { spec: { replicas } }) as K8sObject;
    } else if (r.sub !== undefined) {
      return this.send(res, 404, statusBody(404, "NotFound", "unknown subresource"));
    } else {
      const { resourceVersion: _rv, ...metaRest } = (patch["metadata"] ?? {}) as Record<string, unknown>;
      next = this.merge(cur ?? { kind: r.res.kind, apiVersion: r.res.apiVersion, metadata: { name: r.name, ...(r.res.namespaced ? { namespace: r.ns } : {}), uid: `uid-${r.name}` } }, { ...patch, metadata: metaRest }) as K8sObject;
    }
    next.metadata = { ...next.metadata, resourceVersion: String((cur ? this.rvOf(cur) : 0) + 1), uid: cur?.metadata["uid"] ?? next.metadata["uid"] ?? `uid-${r.name}` };
    if (!dry) this.store.set(key, next);
    return this.send(res, cur ? 200 : 201, JSON.stringify(r.sub === "scale" ? this.scaleOf(next) : next));
  }

  private handleDelete(path: string, query: Record<string, string>, body: string, res: ServerResponse): void {
    const r = this.route(path);
    if (!r || !r.name || r.sub) return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
    const key = this.key(r.res.kind, r.res.namespaced ? r.ns : undefined, r.name);
    const cur = this.store.get(key);
    if (!cur) return this.send(res, 404, statusBody(404, "NotFound", `${r.res.plural} "${r.name}" not found`));
    let opts: { preconditions?: { uid?: string; resourceVersion?: string } } = {};
    if (body.trim() !== "") {
      try {
        opts = JSON.parse(body) as typeof opts;
      } catch {
        return this.send(res, 400, statusBody(400, "BadRequest", "invalid delete options"));
      }
    }
    const pre = opts.preconditions;
    if (pre?.uid !== undefined && pre.uid !== cur.metadata["uid"]) return this.send(res, 409, statusBody(409, "Conflict", "Precondition failed: UID in precondition does not match UID in record"));
    if (pre?.resourceVersion !== undefined && pre.resourceVersion !== String(this.rvOf(cur))) return this.send(res, 409, statusBody(409, "Conflict", "Precondition failed: ResourceVersion in precondition does not match"));
    if (query["dryRun"] !== "All") this.store.delete(key);
    return this.send(res, 200, JSON.stringify({ kind: "Status", apiVersion: "v1", status: "Success", details: { name: r.name, kind: r.res.plural, uid: cur.metadata["uid"] } }));
  }

  /** Testler için: depodaki nesnenin anlık görüntüsü (yazma sonrası doğrulama). */
  peek(kind: string, ns: string | undefined, name: string): K8sObject | undefined {
    const o = this.store.get(this.key(kind, ns, name));
    return o ? (JSON.parse(JSON.stringify(o)) as K8sObject) : undefined;
  }

  /** Testler için: nesneyi dışarıdan değiştirir (TOCTOU simülasyonu); resourceVersion artar. */
  mutate(kind: string, ns: string | undefined, name: string, fn: (o: K8sObject) => void): void {
    const o = this.store.get(this.key(kind, ns, name));
    if (!o) throw new Error("nesne yok");
    fn(o);
    o.metadata["resourceVersion"] = String(this.rvOf(o) + 1);
  }

  private handleCreate(path: string, query: Record<string, string>, body: string, res: ServerResponse): void {
    const r = this.route(path);
    if (!r || r.name) return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
    if (this.opts.readOnly) return this.send(res, 403, statusBody(403, "Forbidden", "create is forbidden for this user"));
    let obj: K8sObject;
    try {
      obj = JSON.parse(body) as K8sObject;
    } catch {
      return this.send(res, 400, statusBody(400, "BadRequest", "invalid body"));
    }
    if (obj.kind !== r.res.kind || !obj.metadata?.name) return this.send(res, 400, statusBody(400, "BadRequest", "kind/name mismatch"));
    const key = this.key(r.res.kind, r.res.namespaced ? r.ns : undefined, obj.metadata.name);
    if (this.store.has(key)) return this.send(res, 409, statusBody(409, "AlreadyExists", `${r.res.plural} "${obj.metadata.name}" already exists`));
    const created: K8sObject = { ...obj, metadata: { ...obj.metadata, ...(r.res.namespaced ? { namespace: r.ns } : {}), uid: `uid-${obj.metadata.name}`, resourceVersion: "1" } };
    if (query["dryRun"] !== "All") this.store.set(key, created);
    return this.send(res, 201, JSON.stringify(created));
  }

  private applyJsonPatch(target: K8sObject, ops: unknown): { ok: true; obj: K8sObject } | { ok: false; code: number; msg: string } {
    if (!Array.isArray(ops)) return { ok: false, code: 400, msg: "json-patch must be an array" };
    const obj = JSON.parse(JSON.stringify(target)) as K8sObject;
    for (const raw of ops) {
      const op = raw as { op?: string; path?: string; value?: unknown };
      const segs = (op.path ?? "").split("/").slice(1).map((x) => x.replace(/~1/g, "/").replace(/~0/g, "~"));
      let parent: Record<string, unknown> = obj as Record<string, unknown>;
      for (const sg of segs.slice(0, -1)) {
        const nx = parent[sg];
        if (nx === null || typeof nx !== "object") return { ok: false, code: 422, msg: `path not found: ${op.path}` };
        parent = nx as Record<string, unknown>;
      }
      const last = segs[segs.length - 1] ?? "";
      if (op.op === "test") {
        if (JSON.stringify(parent[last]) !== JSON.stringify(op.value)) return { ok: false, code: 422, msg: `test failed: ${op.path}` };
      } else if (op.op === "replace" || op.op === "add") {
        parent[last] = op.value;
      } else if (op.op === "remove") {
        delete parent[last];
      } else return { ok: false, code: 400, msg: `unsupported op ${String(op.op)}` };
    }
    return { ok: true, obj };
  }

  private handlePost(path: string, body: string, res: ServerResponse, query: Record<string, string> = {}): void {
    if (!path.startsWith("/apis/authentication.k8s.io") && !path.startsWith("/apis/authorization.k8s.io") && this.route(path)) return this.handleCreate(path, query, body, res);
    if (path === "/apis/authentication.k8s.io/v1/selfsubjectreviews") {
      return this.send(
        res,
        201,
        JSON.stringify({
          kind: "SelfSubjectReview",
          apiVersion: "authentication.k8s.io/v1",
          status: { userInfo: { username: this.opts.username ?? "ops-test-user", groups: ["system:authenticated"] } },
        }),
      );
    }
    if (path === "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews") {
      let ns = "default";
      try {
        ns = String((JSON.parse(body) as { spec?: { namespace?: string } }).spec?.namespace ?? "default");
      } catch {
        return this.send(res, 400, statusBody(400, "BadRequest", "invalid body"));
      }
      const st = this.rules.get(ns) ?? this.rules.get("*") ?? READONLY_RULES;
      return this.send(
        res,
        201,
        JSON.stringify({
          kind: "SelfSubjectRulesReview",
          apiVersion: "authorization.k8s.io/v1",
          status: { resourceRules: [...BASIC_USER_RULES, ...st.resourceRules], nonResourceRules: [{ verbs: ["get"], nonResourceURLs: ["/healthz", "/version"] }], incomplete: st.incomplete ?? false, ...(st.evaluationError ? { evaluationError: st.evaluationError } : {}) },
        }),
      );
    }
    return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
  }
}
