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
}

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
    const full: K8sObject = { ...obj, apiVersion: obj.apiVersion ?? res.apiVersion };
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
    if (method === "POST") return this.handlePost(url.pathname, body, res);
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

  private handlePost(path: string, body: string, res: ServerResponse): void {
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
    void body;
    return this.send(res, 404, statusBody(404, "NotFound", "the server could not find the requested resource"));
  }
}
