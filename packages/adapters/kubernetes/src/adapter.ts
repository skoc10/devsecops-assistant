import { X509Certificate } from "node:crypto";
import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError } from "@ops/contracts";
import type {
  ActionPreview,
  Adapter,
  AdapterCall,
  AdapterManifest,
  CredentialHandle,
  DoctorReport,
  Profile,
  RawToolOutput,
  Sensitivity,
  Target,
} from "@ops/contracts";
import type { CredentialResolver, KubeCredential } from "@ops/broker";
import { K8sClient, apiErrorMessage } from "./client.ts";
import type { ApiResponse } from "./client.ts";
import { parseSince } from "./duration.ts";
import { CLUSTER_SCOPE, resolveKind, resourcePath } from "./kinds.ts";
import type { KindInfo } from "./kinds.ts";
import { registerK8sRedactionProfile, sanitizeObject } from "./sanitize.ts";
import { diagnose } from "./doctor.ts";
import { analyzeRules, ruleAllows } from "./rbac.ts";
import type { RbacRule } from "./rbac.ts";
import { summarizeHpa, summarizeNode, summarizePdb, summarizePods, summarizeWorkload } from "./health.ts";
import { K8S_READ_TOOLS, K8S_WRITE_TOOLS } from "./tools.ts";
import { applyDiff, doApply, doDelete, doRestart, doScale, doUndo, parseManifest, previewApply, previewDelete, previewRestart, previewScale, previewUndo } from "./change.ts";

const ALL_TOOLS = [...K8S_READ_TOOLS, ...K8S_WRITE_TOOLS] as const;
/** `pods/log` için Accept (client-go varsayılanıyla aynı). */
export const LOG_ACCEPT = "application/json, */*";
const WRITE_TOOL_NAMES: ReadonlySet<string> = new Set(K8S_WRITE_TOOLS.map((t) => t.descriptor.name));

type Args = Record<string, unknown>;
const str = (a: Args, k: string): string | undefined => (typeof a[k] === "string" ? (a[k] as string) : undefined);

export interface KubernetesAdapterOptions {
  /** Zaman penceresi hesapları için saat (testlerde sabitlenir). */
  readonly now?: () => Date;
}

function jsonOf(resp: ApiResponse, what: string): unknown {
  if (resp.status < 200 || resp.status >= 300) throw new OpsError("k8s_api_error", apiErrorMessage(resp, what));
  try {
    return JSON.parse(resp.body);
  } catch {
    throw new OpsError("k8s_api_error", `API yanıtı JSON değil — ${what}`);
  }
}

const obj = (v: unknown): Record<string, unknown> => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

function refOf(k: KindInfo, namespace: string | undefined, name: string): string {
  return k.namespaced ? `${k.kind}/${namespace}/${name}` : `${k.kind}/${name}`;
}

function eventTime(e: Record<string, unknown>): string {
  const series = obj(e["series"]);
  const cands = [e["lastTimestamp"], e["eventTime"], series["lastObservedTime"], e["firstTimestamp"], obj(e["metadata"])["creationTimestamp"]];
  const times = cands.filter((c): c is string => typeof c === "string").map((c) => Date.parse(c)).filter((n) => !Number.isNaN(n));
  return times.length ? new Date(Math.max(...times)).toISOString() : "";
}

function slimEvent(e: Record<string, unknown>): Record<string, unknown> {
  const inv = obj(e["involvedObject"]);
  return {
    type: e["type"],
    reason: e["reason"],
    message: e["message"],
    count: e["count"] ?? obj(e["series"])["count"] ?? 1,
    first: e["firstTimestamp"] ?? e["eventTime"],
    last: eventTime(e),
    object: inv["kind"] && inv["name"] ? `${String(inv["kind"])}/${String(inv["name"])}` : undefined,
  };
}

/**
 * Kubernetes okuma adapter'ı. Doğrudan API (kubectl yok, kabuk yok). Kimlik yalnız
 * `CredentialResolver` capability'si ile, lease etkinken ve pin doğrulandıktan sonra okunur.
 */
export class KubernetesAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  private readonly resolver: CredentialResolver;
  private readonly now: () => Date;

  constructor(resolver: CredentialResolver, opts: KubernetesAdapterOptions = {}) {
    registerK8sRedactionProfile();
    this.resolver = resolver;
    this.now = opts.now ?? (() => new Date());
    this.manifest = AdapterManifestSchema.parse({
      id: "kubernetes",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "kubernetes",
      profileKinds: ["k8s"],
      credentialKinds: ["static", "exec"],
      capabilities: ["pagination", "table-secrets"],
      tools: ALL_TOOLS.map((t) => t.descriptor),
    });
  }

  get definitions(): readonly (typeof ALL_TOOLS)[number][] {
    return ALL_TOOLS;
  }

  validateProfile(profile: Profile): string[] {
    const problems: string[] = [];
    if (profile.kind !== "k8s") problems.push(`profil türü 'k8s' olmalı: ${profile.kind}`);
    if (!profile.targetPin.endpoint.startsWith("https://")) problems.push("pin uç noktası https olmalı");
    if (profile.credentialSource.kind !== "static" && profile.credentialSource.kind !== "exec") problems.push(`kimlik kaynağı henüz desteklenmiyor: ${profile.credentialSource.kind}`);
    return problems;
  }

  /** `Secret` türü (ad/tür/anahtar sayısı bile) secret-adjacent: bağlam yalnız yerel sağlayıcıya gidebilir. */
  sensitivityOf(tool: string, args: unknown): Sensitivity | undefined {
    if (tool !== "k8s.resources.list" && tool !== "k8s.resources.get" && tool !== "k8s.resources.describe") return undefined;
    try {
      return resolveKind(str((args ?? {}) as Args, "kind") ?? "").kind === "Secret" ? "secret-adjacent" : undefined;
    } catch {
      return undefined;
    }
  }

  // ---- hedef -------------------------------------------------------------------------------

  resolveTarget(tool: string, args: unknown, profile: Profile): Target {
    const a = (args ?? {}) as Args;
    const t = (scopes: string[], refs: string[] = []): Target => ({
      profileId: profile.id,
      kind: profile.kind,
      endpoint: profile.targetPin.endpoint,
      scopes,
      refs,
    });
    switch (tool) {
      case "k8s.profile.describe":
        return t([...profile.allowedScopes]);
      case "k8s.resources.list":
      case "k8s.resources.get":
      case "k8s.resources.describe": {
        const k = resolveKind(str(a, "kind") ?? "");
        const namespace = str(a, "namespace");
        if (k.namespaced && !namespace) throw new OpsError("namespace_required", `${k.kind} isim alanlıdır: namespace verin`);
        if (!k.namespaced && namespace) throw new OpsError("namespace_unexpected", `${k.kind} küme kapsamlıdır: namespace verilmemeli`);
        const name = str(a, "name");
        return t([k.namespaced ? (namespace as string) : CLUSTER_SCOPE], name ? [refOf(k, namespace, name)] : []);
      }
      case "k8s.events.list": {
        const namespace = str(a, "namespace") as string;
        parseSince(str(a, "since") ?? "");
        const ik = str(a, "involvedKind");
        const iname = str(a, "involvedName");
        const refs = ik && iname ? [refOf(resolveKind(ik), namespace, iname)] : [];
        return t([namespace], refs);
      }
      case "k8s.pods.logs": {
        parseSince(str(a, "since") ?? "");
        const namespace = str(a, "namespace") as string;
        return t([namespace], [`Pod/${namespace}/${str(a, "pod")}`]);
      }
      case "k8s.auth.can_i":
        return t([str(a, "namespace") as string]);
      case "k8s.workload.health": {
        const namespace = str(a, "namespace") as string;
        return t([namespace], [`${str(a, "kind")}/${namespace}/${str(a, "name")}`]);
      }
      case "k8s.apply.diff":
      case "k8s.apply": {
        const m = parseManifest(str(a, "manifest") ?? "");
        return t([m.namespace as string], [m.ref]);
      }
      case "k8s.scale":
      case "k8s.rollout.restart":
      case "k8s.resources.delete": {
        const k = resolveKind(str(a, "kind") ?? "");
        const namespace = str(a, "namespace") as string;
        return t([namespace], [refOf(k, namespace, str(a, "name") as string)]);
      }
      case "k8s.rollout.undo": {
        const namespace = str(a, "namespace") as string;
        return t([namespace], [`Deployment/${namespace}/${str(a, "name")}`]);
      }
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${tool}`);
    }
  }

  // ---- bağlantı ----------------------------------------------------------------------------

  private client(handle: CredentialHandle | null, profile: Profile, call: { maxBytes: number; timeoutMs: number; signal?: AbortSignal; allowWrite?: boolean }): K8sClient {
    if (!handle) throw new OpsError("lease_inactive", "kimlik tutamacı yok");
    const cred = this.resolver.k8s(handle);
    return new K8sClient(cred, profile.targetPin, {
      maxBytes: call.maxBytes,
      timeoutMs: call.timeoutMs,
      ...(call.signal ? { signal: call.signal } : {}),
      ...(call.allowWrite ? { allowWrite: true } : {}),
    });
  }

  /** Mutasyon önizlemesi (diff/etki/geri alma/hedef sürümü): salt OKUMA, istemci yazma yetkisiz. */
  async preview(call: AdapterCall): Promise<ActionPreview> {
    const a = (call.args ?? {}) as Args;
    const client = this.client(call.handle, call.profile, { maxBytes: 2_000_000, timeoutMs: Math.min(call.limits.timeoutMs, 20_000), signal: call.signal });
    try {
      switch (call.tool) {
        case "k8s.apply":
          return await previewApply(client, str(a, "manifest") ?? "");
        case "k8s.scale":
          return await previewScale(client, a as { kind: string; namespace: string; name: string; replicas: number });
        case "k8s.rollout.restart":
          return await previewRestart(client, a as { kind: string; namespace: string; name: string });
        case "k8s.rollout.undo":
          return await previewUndo(client, a as { namespace: string; name: string; toRevision?: number });
        case "k8s.resources.delete":
          return await previewDelete(client, a as { kind: string; namespace: string; name: string });
        default:
          throw new OpsError("no_preview", `araç önizleme desteklemiyor: ${call.tool}`);
      }
    } finally {
      client.close();
    }
  }

  /** Sunucuya erişip kimliği doğrular (`whoami`) ve CA parmak izini döner. Kimlik yalnız pin doğrulanınca gönderilir. */
  async connectCheck(handle: CredentialHandle, profile: Profile): Promise<{ identity: string; targetFingerprint: string }> {
    const cred: KubeCredential = this.resolver.k8s(handle);
    const client = new K8sClient(cred, profile.targetPin, { maxBytes: 64_000, timeoutMs: 10_000 });
    try {
      let identity = "bilinmiyor";
      const r = await client.review("selfSubject", { apiVersion: "authentication.k8s.io/v1", kind: "SelfSubjectReview" });
      if (r.status === 200 || r.status === 201) {
        const user = obj(obj(obj(JSON.parse(r.body))["status"])["userInfo"]);
        identity = typeof user["username"] === "string" ? (user["username"] as string) : identity;
      } else if (r.status === 401) {
        throw new OpsError("k8s_api_error", apiErrorMessage(r, "kimlik doğrulama"));
      } else {
        const v = await client.get("/version");
        if (v.status !== 200) throw new OpsError("k8s_api_error", apiErrorMessage(v, "sunucu sürümü"));
      }
      let fp = profile.targetPin.caFingerprint ?? "system-roots";
      if (!profile.targetPin.caFingerprint && cred.caPem) {
        const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(cred.caPem);
        if (m) fp = new X509Certificate(m[0]).fingerprint256.replace(/:/g, "").toLowerCase();
      }
      return { identity, targetFingerprint: fp };
    } finally {
      client.close();
    }
  }

  /** Beyan edilen tavan ↔ fiili RBAC; oturum başında ve `profile add`'de çalışır. */
  async doctor(handle: CredentialHandle, profile: Profile): Promise<DoctorReport> {
    const cred = this.resolver.k8s(handle);
    let client: K8sClient | undefined;
    try {
      client = new K8sClient(cred, profile.targetPin, { maxBytes: 1_000_000, timeoutMs: 15_000 });
    } catch (e) {
      return diagnose(profile, {
        connect: () => Promise.reject(e),
        rulesFor: () => Promise.reject(e),
        now: this.now,
      });
    }
    const c = client;
    try {
      return await diagnose(profile, {
        connect: () => this.connectCheck(handle, profile),
        rulesFor: (ns) => this.rulesFor(c, ns),
        now: this.now,
      });
    } finally {
      c.close();
    }
  }

  // ---- araçlar -----------------------------------------------------------------------------

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const a = (call.args ?? {}) as Args;
    if (call.tool === "k8s.profile.describe") return this.profileDescribe(call.profile);
    const client = this.client(call.handle, call.profile, {
      maxBytes: Math.min(call.limits.maxBytes * 4, 4_000_000),
      timeoutMs: call.limits.timeoutMs,
      signal: call.signal,
      allowWrite: WRITE_TOOL_NAMES.has(call.tool),
    });
    try {
      switch (call.tool) {
        case "k8s.apply.diff":
          return await applyDiff(client, str(a, "manifest") ?? "");
        case "k8s.apply":
          return await doApply(client, str(a, "manifest") ?? "", call.approvedVersion);
        case "k8s.scale":
          return await doScale(client, a as { kind: string; namespace: string; name: string; replicas: number }, call.approvedVersion);
        case "k8s.rollout.restart":
          return await doRestart(client, a as { kind: string; namespace: string; name: string }, call.approvedVersion, this.now());
        case "k8s.rollout.undo":
          return await doUndo(client, a as { namespace: string; name: string; toRevision?: number }, call.approvedVersion);
        case "k8s.resources.delete":
          return await doDelete(client, a as { kind: string; namespace: string; name: string }, call.approvedVersion);
        case "k8s.resources.list":
          return await this.list(client, a, call);
        case "k8s.resources.get":
          return await this.get(client, a);
        case "k8s.resources.describe":
          return await this.describe(client, a);
        case "k8s.events.list":
          return await this.events(client, a, call);
        case "k8s.pods.logs":
          return await this.logs(client, a, call);
        case "k8s.auth.can_i":
          return await this.canI(client, a);
        case "k8s.workload.health":
          return await this.health(client, a, call.profile);
        default:
          throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
      }
    } finally {
      client.close();
    }
  }

  private profileDescribe(p: Profile): RawToolOutput {
    let host = p.targetPin.endpoint;
    try {
      host = new URL(p.targetPin.endpoint).host;
    } catch {
      /* ham değer */
    }
    return {
      data: {
        id: p.id,
        displayName: p.displayName,
        kind: p.kind,
        environment: p.environment,
        server: host,
        caPinned: p.targetPin.caFingerprint !== undefined,
        classCeiling: p.classCeiling,
        allowedScopes: p.allowedScopes,
        egressClass: p.egressClass,
        credentialSource: p.credentialSource.kind,
      },
      summary: `profil ${p.id} (${p.environment}), tavan ${p.classCeiling}`,
    };
  }

  /** Secret: değerler sunucudan HİÇ çekilmez; Table biçimi yalnız ad/tür/veri sayısı verir. */
  private async secretTable(client: K8sClient, k: KindInfo, namespace: string, name?: string, query: Record<string, string | number | undefined> = {}): Promise<{ items: Record<string, unknown>[]; more: number | undefined; hasMore: boolean }> {
    const resp = await client.get(resourcePath(k, namespace, name), { ...query, includeObject: "Metadata" }, "application/json;as=Table;g=meta.k8s.io;v=v1");
    const j = obj(jsonOf(resp, `${k.kind} ${namespace}${name ? `/${name}` : ""}`));
    const cols = (Array.isArray(j["columnDefinitions"]) ? j["columnDefinitions"] : []).map((c) => String(obj(c)["name"]).toLowerCase());
    const typeIdx = cols.indexOf("type");
    const dataIdx = cols.indexOf("data");
    const rows = Array.isArray(j["rows"]) ? j["rows"] : [];
    const items = rows.map((r) => {
      const row = obj(r);
      const meta = obj(obj(row["object"])["metadata"]);
      const cells = Array.isArray(row["cells"]) ? row["cells"] : [];
      return {
        metadata: { name: meta["name"], namespace: meta["namespace"] ?? namespace, creationTimestamp: meta["creationTimestamp"] },
        type: typeIdx >= 0 ? String(cells[typeIdx] ?? "") : undefined,
        dataKeyCount: dataIdx >= 0 ? Number(cells[dataIdx] ?? 0) : undefined,
      };
    });
    const meta = obj(j["metadata"]);
    return { items, hasMore: typeof meta["continue"] === "string" && meta["continue"] !== "", more: typeof meta["remainingItemCount"] === "number" ? (meta["remainingItemCount"] as number) : undefined };
  }

  private subjectsOf(k: KindInfo, items: Record<string, unknown>[], namespace: string | undefined): string[] {
    return items.slice(0, 50).flatMap((i) => {
      const n = obj(i["metadata"])["name"];
      return typeof n === "string" ? [refOf(k, namespace, n)] : [];
    });
  }

  private async list(client: K8sClient, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const k = resolveKind(str(a, "kind") ?? "");
    const namespace = str(a, "namespace");
    const limit = Math.min(typeof a["limit"] === "number" ? (a["limit"] as number) : 50, call.limits.maxItems);
    const query = { limit, labelSelector: str(a, "labelSelector"), fieldSelector: str(a, "fieldSelector") };

    if (k.kind === "Secret") {
      const t = await this.secretTable(client, k, namespace as string, undefined, query);
      return {
        data: { kind: "Secret", namespace, count: t.items.length, truncated: t.hasMore || undefined, remaining: t.more, note: "Secret değerleri ve anahtar adları okunmaz; yalnız ad/tür/anahtar sayısı", items: t.items },
        summary: `${t.items.length} Secret (${namespace})`,
        truncated: t.hasMore,
        subjects: this.subjectsOf(k, t.items, namespace),
        sensitivity: "secret-adjacent",
      };
    }

    const resp = await client.get(resourcePath(k, namespace), query);
    const j = obj(jsonOf(resp, `${k.kind} listesi${namespace ? ` (${namespace})` : ""}`));
    const raw = Array.isArray(j["items"]) ? (j["items"] as unknown[]) : [];
    const items = raw.map((i) => sanitizeObject(k.kind, i)) as Record<string, unknown>[];
    const meta = obj(j["metadata"]);
    const hasMore = typeof meta["continue"] === "string" && meta["continue"] !== "";
    const remaining = typeof meta["remainingItemCount"] === "number" ? (meta["remainingItemCount"] as number) : undefined;
    return {
      data: { kind: k.kind, namespace, count: items.length, truncated: hasMore || undefined, remaining, items },
      summary: `${items.length} ${k.kind}${namespace ? ` (${namespace})` : ""}${hasMore ? `, +${remaining ?? "?"} daha var` : ""}`,
      truncated: hasMore,
      subjects: this.subjectsOf(k, items, namespace),
      ...(k.kind === "ConfigMap" ? { taint: "untrusted" as const } : {}),
    };
  }

  private async get(client: K8sClient, a: Args): Promise<RawToolOutput> {
    const k = resolveKind(str(a, "kind") ?? "");
    const namespace = str(a, "namespace");
    const name = str(a, "name") as string;
    if (k.kind === "Secret") {
      const t = await this.secretTable(client, k, namespace as string, name);
      const first = t.items[0];
      if (!first) throw new OpsError("k8s_api_error", `bulunamadı — Secret ${namespace}/${name}`);
      return {
        data: { kind: "Secret", ...first, note: "Secret değerleri okunmaz" },
        summary: `Secret ${namespace}/${name}`,
        subjects: [refOf(k, namespace, name)],
        sensitivity: "secret-adjacent",
      };
    }
    const resp = await client.get(resourcePath(k, namespace, name));
    const o = sanitizeObject(k.kind, jsonOf(resp, `${k.kind} ${namespace ? `${namespace}/` : ""}${name}`));
    return {
      data: o,
      summary: `${k.kind} ${namespace ? `${namespace}/` : ""}${name}`,
      subjects: [refOf(k, namespace, name)],
      ...(k.kind === "ConfigMap" ? { taint: "untrusted" as const } : {}),
    };
  }

  private async describe(client: K8sClient, a: Args): Promise<RawToolOutput> {
    const k = resolveKind(str(a, "kind") ?? "");
    const namespace = str(a, "namespace");
    const name = str(a, "name") as string;
    const got = await this.get(client, a);
    let events: Record<string, unknown>[] = [];
    let note: string | undefined;
    if (k.namespaced && namespace) {
      const resp = await client.get(`/api/v1/namespaces/${encodeURIComponent(namespace)}/events`, {
        fieldSelector: `involvedObject.name=${name},involvedObject.kind=${k.kind}`,
        limit: 100,
      });
      const j = obj(jsonOf(resp, `olaylar (${namespace})`));
      events = (Array.isArray(j["items"]) ? (j["items"] as Record<string, unknown>[]) : [])
        .map((e) => slimEvent(obj(e)))
        .sort((x, y) => String(y["last"]).localeCompare(String(x["last"])))
        .slice(0, 15);
    } else {
      note = "küme kapsamlı kaynak: olaylar bu araçla gösterilmez";
    }
    return {
      data: { object: got.data, events, ...(note ? { note } : {}) },
      summary: `${k.kind} ${namespace ? `${namespace}/` : ""}${name}: ${events.length} olay`,
      subjects: got.subjects ?? [],
      ...(got.sensitivity ? { sensitivity: got.sensitivity } : {}),
    };
  }

  private async events(client: K8sClient, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const namespace = str(a, "namespace") as string;
    const sinceSec = parseSince(str(a, "since") ?? "");
    const limit = Math.min(typeof a["limit"] === "number" ? (a["limit"] as number) : 50, call.limits.maxItems);
    const fields: string[] = [];
    const ik = str(a, "involvedKind");
    const iname = str(a, "involvedName");
    if (ik) fields.push(`involvedObject.kind=${resolveKind(ik).kind}`);
    if (iname) fields.push(`involvedObject.name=${iname}`);
    const type = str(a, "type");
    if (type) fields.push(`type=${type}`);
    const SCAN = 500;
    const resp = await client.get(`/api/v1/namespaces/${encodeURIComponent(namespace)}/events`, {
      limit: SCAN,
      ...(fields.length ? { fieldSelector: fields.join(",") } : {}),
    });
    const j = obj(jsonOf(resp, `olaylar (${namespace})`));
    const meta = obj(j["metadata"]);
    const scannedAll = !(typeof meta["continue"] === "string" && meta["continue"] !== "");
    const from = this.now().getTime() - sinceSec * 1000;
    const all = (Array.isArray(j["items"]) ? (j["items"] as unknown[]) : [])
      .map((e) => obj(e))
      .filter((e) => {
        const t = Date.parse(eventTime(e));
        return !Number.isNaN(t) && t >= from;
      })
      .map(slimEvent)
      .sort((x, y) => String(y["last"]).localeCompare(String(x["last"])));
    const items = all.slice(0, limit);
    const truncated = all.length > limit || !scannedAll;
    return {
      data: {
        namespace,
        since: str(a, "since"),
        count: items.length,
        truncated: truncated || undefined,
        note: !scannedAll ? `yalnız ilk ${SCAN} olay tarandı; involvedKind/involvedName/type ile daraltın` : all.length > limit ? `${all.length - limit} olay daha var` : undefined,
        items,
      },
      summary: `${items.length} olay (${namespace}, son ${str(a, "since")})${truncated ? ", kısmi" : ""}`,
      truncated,
      subjects: [...new Set(items.map((i) => String(i["object"] ?? "")).filter(Boolean).map((o) => o.replace("/", `/${namespace}/`)))].slice(0, 50),
    };
  }

  private async logs(client: K8sClient, a: Args, call: AdapterCall): Promise<RawToolOutput> {
    const namespace = str(a, "namespace") as string;
    const pod = str(a, "pod") as string;
    const sinceSec = parseSince(str(a, "since") ?? "");
    const tail = Math.min(typeof a["tailLines"] === "number" ? (a["tailLines"] as number) : 200, call.limits.maxItems);
    const limitBytes = Math.min(call.limits.maxBytes, 256_000);
    const resp = await client.get(
      `/api/v1/namespaces/${encodeURIComponent(namespace)}/pods/${encodeURIComponent(pod)}/log`,
      {
        sinceSeconds: sinceSec,
        tailLines: tail,
        limitBytes,
        timestamps: true,
        container: str(a, "container"),
        previous: a["previous"] === true ? true : undefined,
      },
      // Gerçek API sunucusu Accept'i serileştiriciye (json/yaml/protobuf) göre müzakere eder; `text/plain` tek başına
      // 406 NotAcceptable alır (kind'da bulundu: pods.logs gerçek kümede HİÇ çalışmıyordu). kubectl/client-go gibi
      // `*/*` ile istenir; gövde yine düz metindir ve boyut sınırı akışta uygulanır.
      LOG_ACCEPT,
    );
    if (resp.status < 200 || resp.status >= 300) throw new OpsError("k8s_api_error", apiErrorMessage(resp, `log ${namespace}/${pod}`));
    const text = resp.body;
    const lines = text === "" ? 0 : text.replace(/\n$/, "").split("\n").length;
    const truncated = Buffer.byteLength(text, "utf8") >= limitBytes || lines >= tail;
    return {
      data: text,
      summary: `log ${namespace}/${pod}${str(a, "container") ? `:${str(a, "container")}` : ""}${a["previous"] === true ? " (önceki)" : ""}: ${lines} satır, son ${str(a, "since")}${truncated ? ", kesildi" : ""}`,
      truncated,
      subjects: [`Pod/${namespace}/${pod}`],
    };
  }

  // ---- yetki ve sağlık ---------------------------------------------------------------------

  /** SelfSubjectRulesReview: kimliğin namespace'teki fiili kuralları. */
  async rulesFor(client: K8sClient, namespace: string): Promise<{ rules: RbacRule[]; incomplete: boolean; evaluationError?: string }> {
    const resp = await client.review("selfRules", { apiVersion: "authorization.k8s.io/v1", kind: "SelfSubjectRulesReview", spec: { namespace } });
    if (resp.status !== 200 && resp.status !== 201) throw new OpsError("k8s_api_error", apiErrorMessage(resp, `yetki kuralları (${namespace})`));
    const st = obj(obj(JSON.parse(resp.body))["status"]);
    const rules = (Array.isArray(st["resourceRules"]) ? st["resourceRules"] : []).map((r) => {
      const o = obj(r);
      const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
      return { verbs: strs(o["verbs"]), apiGroups: strs(o["apiGroups"]), resources: strs(o["resources"]), resourceNames: strs(o["resourceNames"]) } satisfies RbacRule;
    });
    return {
      rules,
      incomplete: st["incomplete"] === true,
      ...(typeof st["evaluationError"] === "string" ? { evaluationError: (st["evaluationError"] as string).slice(0, 200) } : {}),
    };
  }

  private async canI(client: K8sClient, a: Args): Promise<RawToolOutput> {
    const namespace = str(a, "namespace") as string;
    const { rules, incomplete } = await this.rulesFor(client, namespace);
    const verb = str(a, "verb");
    const resource = str(a, "resource");
    if (verb && resource) {
      const group = str(a, "group");
      const allowed = ruleAllows(rules, { verb, resource, ...(group !== undefined ? { group } : {}) });
      return {
        data: { namespace, verb, resource, group: group ?? "", allowed, incomplete: incomplete || undefined },
        summary: `${verb} ${resource} (${namespace}): ${allowed ? "izinli" : "izinsiz"}`,
      };
    }
    const analysis = analyzeRules(rules);
    const compact = rules.map((r) => ({ verbs: r.verbs.join(","), groups: (r.apiGroups ?? []).join(",") || "core", resources: (r.resources ?? []).join(","), names: (r.resourceNames ?? []).length ? r.resourceNames : undefined }));
    return {
      data: { namespace, effectiveClass: analysis.effective, secretsReadable: analysis.secretsReadable, incomplete: incomplete || undefined, rules: compact },
      summary: `${rules.length} kural (${namespace}); fiili sınıf: ${analysis.effective}`,
      sensitivity: "internal",
    };
  }

  private async health(client: K8sClient, a: Args, profile: Profile): Promise<RawToolOutput> {
    const kind = str(a, "kind") as string;
    const name = str(a, "name") as string;
    const namespace = str(a, "namespace") as string;
    const k = resolveKind(kind);
    const wl = obj(jsonOf(await client.get(resourcePath(k, namespace, name)), `${kind} ${namespace}/${name}`));
    const { workload, findings } = summarizeWorkload(kind, wl);

    const spec = obj(wl["spec"]);
    const matchLabels = obj(obj(spec["selector"])["matchLabels"]);
    const selector = Object.entries(matchLabels).filter((e): e is [string, string] => typeof e[1] === "string").map(([k2, v]) => `${k2}=${v}`).join(",");
    const tmplLabels = Object.fromEntries(Object.entries(obj(obj(obj(spec["template"])["metadata"])["labels"])).filter((e): e is [string, string] => typeof e[1] === "string"));

    const listOf = async (kindName: string, query: Record<string, string | number | undefined>): Promise<Record<string, unknown>[]> => {
      const kk = resolveKind(kindName);
      const j = obj(jsonOf(await client.get(resourcePath(kk, namespace), { limit: 200, ...query }), `${kindName} (${namespace})`));
      return (Array.isArray(j["items"]) ? j["items"] : []).map(obj);
    };
    const [pods, hpas, pdbs] = await Promise.all([
      selector ? listOf("Pod", { labelSelector: selector }) : Promise.resolve([] as Record<string, unknown>[]),
      kind === "Job" ? Promise.resolve([] as Record<string, unknown>[]) : listOf("HorizontalPodAutoscaler", {}),
      kind === "Job" ? Promise.resolve([] as Record<string, unknown>[]) : listOf("PodDisruptionBudget", {}),
    ]);
    const ps = summarizePods(pods);
    const hs = summarizeHpa(hpas, kind, name);
    const pd = summarizePdb(pdbs, tmplLabels);

    let nodes: Record<string, unknown>[] | "kapsam-dışı" = "kapsam-dışı";
    const nodeFindings: ReturnType<typeof summarizeNode>["findings"] = [];
    if (profile.allowedScopes.includes("*") || profile.allowedScopes.includes(CLUSTER_SCOPE)) {
      const nk = resolveKind("Node");
      const got = await Promise.all(
        ps.nodeNames.map(async (n) => {
          const r = await client.get(resourcePath(nk, undefined, n));
          return r.status === 200 ? obj(JSON.parse(r.body)) : null;
        }),
      );
      const sums = got.filter((x): x is Record<string, unknown> => x !== null).map(summarizeNode);
      nodes = sums.map((x) => x.node);
      for (const s of sums) nodeFindings.push(...s.findings);
    }

    const all = [...findings, ...ps.findings, ...hs.findings, ...pd.findings, ...nodeFindings];
    const rank = { critical: 0, warning: 1, info: 2 } as const;
    all.sort((x, y) => rank[x.severity] - rank[y.severity]);
    const critical = all.filter((f) => f.severity === "critical").length;
    return {
      data: {
        workload,
        pods: ps.pods,
        images: ps.images,
        hpa: hs.hpa ?? undefined,
        pdb: pd.pdb ?? undefined,
        nodes,
        findings: all.slice(0, 30),
      },
      summary: `${kind} ${namespace}/${name}: ${String(workload["ready"])}/${String(workload["desired"])} hazır, ${critical} kritik bulgu`,
      subjects: [`${kind}/${namespace}/${name}`, ...pods.slice(0, 20).map((p) => `Pod/${namespace}/${String(obj(p["metadata"])["name"])}`)],
    };
  }
}
