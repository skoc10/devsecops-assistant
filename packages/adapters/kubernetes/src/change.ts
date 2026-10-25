import { parseAllDocuments, stringify } from "yaml";
import { OpsError } from "@ops/contracts";
import type { ActionPreview, RawToolOutput } from "@ops/contracts";
import { diffFile } from "@ops/diff";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { K8sClient, apiErrorMessage } from "./client.ts";
import type { ApiResponse } from "./client.ts";
import { DNS_LABEL, DNS_SUBDOMAIN, resolveKind, resourcePath } from "./kinds.ts";
import type { KindInfo } from "./kinds.ts";
import { sanitizeObject } from "./sanitize.ts";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const FIELD_MANAGER = "ops-assistant";

/** `k8s.apply` ile uygulanabilen türler (KAPALI liste). Secret/Pod/RBAC/küme-kapsamlı türler yok. */
export const APPLY_KINDS: readonly string[] = [
  "Service", "ConfigMap", "PersistentVolumeClaim", "ResourceQuota", "LimitRange", "Deployment", "StatefulSet", "DaemonSet",
  "Job", "CronJob", "Ingress", "NetworkPolicy", "HorizontalPodAutoscaler", "PodDisruptionBudget",
];
/** `k8s.resources.delete` ile silinebilen türler (uygulanabilenler + Pod/ReplicaSet). Secret, Namespace, Node, PV yok. */
export const DELETE_KINDS: readonly string[] = [...APPLY_KINDS, "Pod", "ReplicaSet"];
export const SCALE_KINDS = ["Deployment", "StatefulSet", "ReplicaSet"] as const;
export const RESTART_KINDS = ["Deployment", "StatefulSet", "DaemonSet"] as const;

const MAX_MANIFEST_BYTES = 60_000;
const MAX_NODES = 5_000;
const MAX_DEPTH = 30;
const TOP_KEYS = new Set(["apiVersion", "kind", "metadata", "spec", "data", "immutable"]);
const META_KEYS = new Set(["name", "namespace", "labels", "annotations"]);
const SECRETISH_KEY = /(token|password|passwd|secret|key|credential|cert|auth)/i;
const LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration";
const ENV_PLACEHOLDER = "‹redacted:env›";

/** Ortam değişkeni (`{name, value}`) girdilerinden secret benzeri adlı olanların DÜZ değerlerini maskeler (diff/önizleme için). */
function maskEnv<T>(v: T): T {
  if (Array.isArray(v)) return v.map((x) => maskEnv(x)) as unknown as T;
  if (isObj(v)) {
    const out: Obj = {};
    for (const [k, x] of Object.entries(v)) out[k] = maskEnv(x);
    if (typeof out["name"] === "string" && SECRETISH_KEY.test(out["name"]) && typeof out["value"] === "string" && out["value"] !== "") out["value"] = ENV_PLACEHOLDER;
    return out as T;
  }
  return v;
}

/** Manifestte secret benzeri adlı ortam değişkenine düz değer verilmiş mi? (yol döner) */
function findLiteralSecretEnv(v: unknown, path = ""): string | undefined {
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const r = findLiteralSecretEnv(v[i], `${path}[${i}]`);
      if (r) return r;
    }
  } else if (isObj(v)) {
    if (typeof v["name"] === "string" && SECRETISH_KEY.test(v["name"]) && typeof v["value"] === "string" && v["value"] !== "" && !("valueFrom" in v)) return `${path}.${v["name"].slice(0, 40)}`;
    for (const [k, x] of Object.entries(v)) {
      const r = findLiteralSecretEnv(x, `${path}.${k}`);
      if (r) return r;
    }
  }
  return undefined;
}

export interface ParsedManifest {
  readonly obj: Obj;
  readonly kind: KindInfo;
  readonly namespace: string | undefined;
  readonly name: string;
  readonly ref: string;
}

export const refOf = (k: KindInfo, namespace: string | undefined, name: string): string => (k.namespaced ? `${k.kind}/${namespace}/${name}` : `${k.kind}/${name}`);

function countNodes(v: unknown, depth = 0): number {
  if (depth > MAX_DEPTH) throw new OpsError("manifest_invalid", `manifest çok derin (> ${MAX_DEPTH})`);
  if (Array.isArray(v)) return 1 + v.reduce((n: number, x) => n + countNodes(x, depth + 1), 0);
  if (isObj(v)) return 1 + Object.values(v).reduce((n: number, x) => n + countNodes(x, depth + 1), 0);
  return 1;
}

/**
 * Modelin yazdığı manifesti KATI doğrular. Tek belge; takma ad (alias) yok; kapalı tür listesi; yalnız
 * izinli üst-düzey/metadata alanları (`status`, `finalizers`, `ownerReferences`, `managedFields`,
 * `generateName`, `resourceVersion`, `uid` yok); secret benzeri içerik (M2 desenleri, ConfigMap'te secret
 * adlı anahtar) REDDEDİLİR — manifestte secret taşınmaz, `secretKeyRef` kullanılır.
 */
export function parseManifest(text: string): ParsedManifest {
  if (Buffer.byteLength(text) > MAX_MANIFEST_BYTES) throw new OpsError("manifest_too_large", `manifest ${MAX_MANIFEST_BYTES} bayt sınırını aşıyor`);
  const docs = parseAllDocuments(text, { uniqueKeys: true });
  const real = docs.filter((d) => d.contents !== null);
  if (real.length !== 1) throw new OpsError("manifest_invalid", `manifest tam olarak bir belge içermeli (${real.length} bulundu)`);
  const doc = real[0];
  if (!doc || doc.errors.length > 0) throw new OpsError("manifest_invalid", `YAML hatası: ${(doc?.errors[0]?.message ?? "?").split("\n")[0]?.slice(0, 120)}`);
  let js: unknown;
  try {
    js = doc.toJS({ maxAliasCount: 0 });
  } catch {
    throw new OpsError("manifest_invalid", "manifestte YAML takma adı (alias) kullanılamaz");
  }
  if (!isObj(js)) throw new OpsError("manifest_invalid", "manifest bir nesne olmalı");
  if (countNodes(js) > MAX_NODES) throw new OpsError("manifest_too_large", `manifest ${MAX_NODES} düğümü aşıyor`);
  for (const k of Object.keys(js)) if (!TOP_KEYS.has(k)) throw new OpsError("manifest_invalid", `izin verilmeyen üst-düzey alan: ${k.slice(0, 40)} (izinli: ${[...TOP_KEYS].join(", ")})`);

  const kindName = js["kind"];
  if (typeof kindName !== "string") throw new OpsError("manifest_invalid", "kind zorunlu");
  const kind = resolveKind(kindName);
  if (kind.kind !== kindName) throw new OpsError("manifest_invalid", `kind tam adıyla yazılmalı: ${kind.kind}`);
  if (!APPLY_KINDS.includes(kind.kind)) throw new OpsError("kind_refused", `'${kind.kind}' k8s.apply ile uygulanamaz (uygulanabilir: ${APPLY_KINDS.join(", ")})`);
  if (js["apiVersion"] !== kind.apiVersion) throw new OpsError("manifest_invalid", `apiVersion '${kind.apiVersion}' olmalı`);

  const meta = js["metadata"];
  if (!isObj(meta)) throw new OpsError("manifest_invalid", "metadata zorunlu");
  for (const k of Object.keys(meta)) if (!META_KEYS.has(k)) throw new OpsError("manifest_invalid", `izin verilmeyen metadata alanı: ${k.slice(0, 40)} (izinli: ${[...META_KEYS].join(", ")})`);
  const name = meta["name"];
  if (typeof name !== "string" || !DNS_SUBDOMAIN.test(name) || name.length > 253) throw new OpsError("manifest_invalid", "metadata.name geçersiz");
  const namespace = meta["namespace"];
  if (kind.namespaced) {
    if (typeof namespace !== "string" || !DNS_LABEL.test(namespace)) throw new OpsError("manifest_invalid", "metadata.namespace zorunlu ve geçerli olmalı");
  } else if (namespace !== undefined) throw new OpsError("manifest_invalid", "küme kapsamlı türde namespace verilmez");
  for (const f of ["labels", "annotations"] as const) {
    const m = meta[f];
    if (m === undefined) continue;
    if (!isObj(m)) throw new OpsError("manifest_invalid", `metadata.${f} bir nesne olmalı`);
    for (const [k, v] of Object.entries(m)) {
      if (typeof v !== "string" || v.length > 1_000 || k.length > 253) throw new OpsError("manifest_invalid", `metadata.${f}: değerler ≤1000 karakterlik dizge olmalı`);
      if (k === LAST_APPLIED) throw new OpsError("manifest_invalid", "last-applied-configuration ek açıklaması yazılamaz");
    }
  }
  if (kind.kind === "ConfigMap" && isObj(js["data"])) {
    const bad = Object.keys(js["data"]).find((k) => SECRETISH_KEY.test(k));
    if (bad) throw new OpsError("secret_in_manifest", `ConfigMap anahtarı '${bad.slice(0, 40)}' secret benzeri: secret'lar ConfigMap'e yazılmaz (Secret/dış secret yöneticisi kullanın)`);
  }
  const literal = findLiteralSecretEnv(js);
  if (literal) throw new OpsError("secret_in_manifest", `secret benzeri adlı ortam değişkenine düz değer verilmiş (${literal}): \`valueFrom.secretKeyRef\` kullanın`);
  const flat = JSON.stringify(js);
  if (scrubText(flat, new KnownSecrets()) !== flat) throw new OpsError("secret_in_manifest", "manifest secret benzeri bir değer içeriyor: değeri `secretKeyRef`/dış yöneticiye taşıyın");
  return { obj: js, kind, namespace: kind.namespaced ? (namespace as string) : undefined, name, ref: refOf(kind, kind.namespaced ? (namespace as string) : undefined, name) };
}

// ---- yardımcılar ---------------------------------------------------------------------------------

const yaml = (v: unknown): string => stringify(v, { sortMapEntries: true, lineWidth: 0 });

/** `live`ın yalnız `want`ta bulunan anahtarlarını tutar (diziler/skalerler canlı değerleriyle). */
function project(live: unknown, want: unknown): unknown {
  if (isObj(want)) {
    if (!isObj(live)) return undefined;
    const out: Obj = {};
    for (const k of Object.keys(want)) if (k in live) out[k] = project(live[k], want[k]);
    return out;
  }
  return live;
}

function jsonOf(resp: ApiResponse, what: string): Obj {
  if (resp.status < 200 || resp.status >= 300) throw new OpsError("k8s_api_error", apiErrorMessage(resp, what));
  try {
    const j: unknown = JSON.parse(resp.body);
    if (!isObj(j)) throw new Error("nesne değil");
    return j;
  } catch {
    throw new OpsError("k8s_api_error", `API yanıtı JSON nesnesi değil — ${what}`);
  }
}

async function getLive(client: K8sClient, k: KindInfo, namespace: string | undefined, name: string): Promise<Obj | null> {
  const resp = await client.get(resourcePath(k, namespace, name));
  if (resp.status === 404) return null;
  return jsonOf(resp, `${refOf(k, namespace, name)}`);
}

function rvOf(o: Obj): string {
  const rv = isObj(o["metadata"]) ? o["metadata"]["resourceVersion"] : undefined;
  if (typeof rv !== "string" || rv === "") throw new OpsError("version_missing", "nesnenin resourceVersion değeri yok: TOCTOU koruması sağlanamaz, işlem reddedildi");
  return rv;
}

const unified = (path: string, before: string | null, after: string): string => diffFile(path, before, after).patch;

/** Pod şablonlarındaki riskli ayarları işaretler (karar yine insanda; yalnız görünür kılar). */
export function lintManifest(obj: Obj): string[] {
  const out: string[] = [];
  const spec = isObj(obj["spec"]) ? obj["spec"] : {};
  const podSpec = ((): Obj | undefined => {
    const t = (x: unknown): Obj | undefined => (isObj(x) && isObj(x["spec"]) ? (x["spec"] as Obj) : undefined);
    if (isObj(spec["template"])) return t(spec["template"]);
    if (isObj(spec["jobTemplate"]) && isObj((spec["jobTemplate"] as Obj)["spec"])) return t(((spec["jobTemplate"] as Obj)["spec"] as Obj)["template"]);
    return undefined;
  })();
  if (!podSpec) return out;
  for (const f of ["hostNetwork", "hostPID", "hostIPC"]) if (podSpec[f] === true) out.push(`⚠ ${f}: true (düğüm ad alanı paylaşımı)`);
  const vols = Array.isArray(podSpec["volumes"]) ? podSpec["volumes"] : [];
  for (const v of vols) if (isObj(v) && isObj(v["hostPath"])) out.push(`⚠ hostPath birimi: ${String((v["hostPath"] as Obj)["path"] ?? "?").slice(0, 60)}`);
  const containers = [...(Array.isArray(podSpec["containers"]) ? podSpec["containers"] : []), ...(Array.isArray(podSpec["initContainers"]) ? podSpec["initContainers"] : [])];
  for (const c of containers) {
    if (!isObj(c)) continue;
    const nm = String(c["name"] ?? "?").slice(0, 40);
    const sc = isObj(c["securityContext"]) ? c["securityContext"] : {};
    if (sc["privileged"] === true) out.push(`⚠ ${nm}: privileged`);
    if (sc["allowPrivilegeEscalation"] === true) out.push(`⚠ ${nm}: allowPrivilegeEscalation`);
    if (sc["runAsUser"] === 0) out.push(`⚠ ${nm}: root (runAsUser 0)`);
    const adds = isObj(sc["capabilities"]) && Array.isArray(sc["capabilities"]["add"]) ? (sc["capabilities"]["add"] as unknown[]) : [];
    if (adds.length) out.push(`⚠ ${nm}: capabilities.add ${adds.map(String).join(",").slice(0, 60)}`);
    const image = typeof c["image"] === "string" ? c["image"] : "";
    if (image && (!/[:@]/.test(image.split("/").pop() ?? "") || /:latest$/.test(image))) out.push(`⚠ ${nm}: imaj etiketi yok/latest (${image.slice(0, 60)})`);
  }
  return out;
}

// ---- apply / apply.diff ---------------------------------------------------------------------------

interface ApplyPlan {
  readonly parsed: ParsedManifest;
  readonly live: Obj | null;
  readonly diff: string;
  readonly impact: string[];
  readonly version: string;
}

async function planApply(client: K8sClient, parsed: ParsedManifest): Promise<ApplyPlan> {
  const live = await getLive(client, parsed.kind, parsed.namespace, parsed.name);
  const desired = parsed.obj;
  const liveSub = live ? maskEnv(project(sanitizeObject(parsed.kind.kind, live), desired)) : undefined;
  const before = live ? yaml(liveSub) : null;
  const diff = unified(parsed.ref, before, yaml(desired));
  const impact: string[] = [live ? `mevcut ${parsed.ref} güncellenecek` : `yeni ${parsed.ref} oluşturulacak`];
  if (live && diff === "") impact[0] = `${parsed.ref}: değişiklik yok (istenen durum zaten uygulanmış)`;
  const wantReplicas = isObj(desired["spec"]) ? (desired["spec"] as Obj)["replicas"] : undefined;
  const liveReplicas = live && isObj(live["spec"]) ? (live["spec"] as Obj)["replicas"] : undefined;
  if (typeof wantReplicas === "number" && wantReplicas !== liveReplicas) impact.push(`replika ${liveReplicas ?? "(yok)"} → ${wantReplicas}`);
  impact.push(...lintManifest(desired));
  return { parsed, live, diff, impact, version: live ? rvOf(live) : "yok" };
}

export async function applyDiff(client: K8sClient, manifest: string): Promise<RawToolOutput> {
  const parsed = parseManifest(manifest);
  const plan = await planApply(client, parsed);
  return {
    data: { ref: parsed.ref, exists: plan.live !== null, version: plan.version, changed: plan.diff !== "", diff: plan.diff, impact: plan.impact },
    summary: `${parsed.ref}: ${plan.live ? (plan.diff === "" ? "değişiklik yok" : "güncellenecek") : "oluşturulacak"}`,
    subjects: [parsed.ref],
  };
}

export async function previewApply(client: K8sClient, manifest: string): Promise<ActionPreview> {
  const plan = await planApply(client, parseManifest(manifest));
  return {
    targetVersion: plan.version,
    diff: plan.diff,
    impact: plan.impact,
    rollback: plan.live ? "önceki değerler diff'teki '-' satırlarıdır; eski manifesti k8s.apply ile geri uygulayın (kaynak depodaki sürümü tercih edin)" : `k8s.resources.delete ${plan.parsed.ref}`,
  };
}

/** Sunucu kaynaklı alan yolu / yönetici adı: yalnız kısa, boşluksuz tanımlayıcı biçimi geçer (serbest metin değil). */
const SAFE_FIELD = /^[A-Za-z0-9_.\-[\]="/:{}]{1,160}$/;
const SAFE_MANAGER = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * Server-side apply 409'u: `reason: Conflict` + `details.causes[].reason: FieldManagerConflict` ise alan sahipliği
 * çakışmasıdır (başka bir alan yöneticisi — ör. GitOps denetleyicisi, kubectl — bu alanları farklı değerle yönetiyor).
 * Gerçek kümede (kind) doğrulandı; sahte API bu ayrımı yapmıyordu. `force` hiçbir zaman kullanılmaz.
 */
export function fieldManagerConflicts(resp: ApiResponse): { field: string; manager: string }[] {
  let j: unknown;
  try {
    j = JSON.parse(resp.body);
  } catch {
    return [];
  }
  if (!isObj(j) || j["reason"] !== "Conflict" || !isObj(j["details"]) || !Array.isArray(j["details"]["causes"])) return [];
  return (j["details"]["causes"] as unknown[])
    .filter(isObj)
    .filter((c) => c["reason"] === "FieldManagerConflict")
    .slice(0, 10)
    .map((c) => {
      const field = typeof c["field"] === "string" && SAFE_FIELD.test(c["field"]) ? c["field"] : "?";
      const m = /conflict with "([^"]{1,128})"/.exec(typeof c["message"] === "string" ? c["message"] : "")?.[1] ?? "";
      return { field, manager: SAFE_MANAGER.test(m) ? m : "?" };
    });
}

/**
 * "Yalnız yoksa oluştur" ön koşulu için resourceVersion: etcd revizyonu 1 kümenin ilk yazımıdır, bir kullanıcı nesnesinin
 * güncel sürümü olamaz. Var olan nesnede uyuşmazlık = 409; nesne yokken sunucu oluşturur ve kendi sürümünü atar.
 */
export const CREATE_ONLY_RV = "1";

/** Status yanıtındaki `reason` (yalnız kısa tanımlayıcı; sunucu metni taşınmaz). */
function statusReason(resp: ApiResponse): string {
  try {
    const r = (JSON.parse(resp.body) as { reason?: unknown }).reason;
    return typeof r === "string" && /^[A-Za-z]{1,40}$/.test(r) ? r : "?";
  } catch {
    return "?";
  }
}

export async function doApply(client: K8sClient, manifest: string, approvedVersion: string | undefined): Promise<RawToolOutput> {
  const parsed = parseManifest(manifest);
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const { kind, namespace, name, obj, ref } = parsed;
  let resp: ApiResponse;
  if (approvedVersion === "yok") {
    // Oluşturma da server-side apply ile: POST ile oluşturulan alanlar (operation Update) aynı yöneticinin sonraki
    // Apply'ıyla ÇAKIŞIYORDU (yönetici kimliği ad + işlemdir; kind'da bulundu). "Yalnız yoksa oluştur" koşulu
    // resourceVersion ön koşuluyla: hiçbir canlı nesnenin sahip olamayacağı sürüm (`CREATE_ONLY_RV`) — nesne onaydan sonra
    // başkasınca oluşturulduysa sürüm uyuşmaz (409), var olan nesne DEĞİŞMEZ; oluşturmada sunucu sürümü kendisi atar.
    // (uid bu iş için KULLANILAMAZ: gerçek sunucu SSA'da uid'i ön koşul sayar ve nesne yokken "uid mismatch … no existing
    // object was found" ile her oluşturmayı 409'la reddeder — kind'da bulundu.)
    const body = { ...obj, metadata: { ...(obj["metadata"] as Obj), resourceVersion: CREATE_ONLY_RV } };
    resp = await client.patch(resourcePath(kind, namespace, name), body, "application/apply-patch+yaml", { fieldManager: FIELD_MANAGER, force: false });
    if (resp.status === 409) {
      throw new OpsError("target_changed", `${ref} onaydan sonra başkası tarafından oluşturuldu (409 ${statusReason(resp)}); hiçbir şey uygulanmadı, yeniden inceleyin`);
    }
    if (resp.status === 200) {
      // 201 beklenir; 200 = nesne vardı ve güncellendi (uid koşulu sunucuda uygulanmadı). Sessiz geçilmez.
      throw new OpsError("target_changed", `${ref} beklenmedik biçimde zaten vardı ve bu çağrıyla GÜNCELLENDİ (onaylanan: yeni nesne); nesneyi inceleyin`);
    }
  } else {
    const body = { ...obj, metadata: { ...(obj["metadata"] as Obj), resourceVersion: approvedVersion } };
    resp = await client.patch(resourcePath(kind, namespace, name), body, "application/apply-patch+yaml", { fieldManager: FIELD_MANAGER, force: false });
    if (resp.status === 409) {
      const conflicts = fieldManagerConflicts(resp);
      if (conflicts.length > 0) {
        throw new OpsError(
          "field_manager_conflict",
          `${ref}: alan sahipliği çakışması (server-side apply, 409): ${conflicts.map((c) => `${c.field} → '${c.manager}'`).join(", ")}. ` +
            "Bu alanları başka bir yönetici farklı değerle yönetiyor; hiçbir şey uygulanmadı (zorla devralma yapılmaz). Değişikliği o yöneticinin kaynağında (ör. GitOps deposu) yapın veya alanı manifestten çıkarın",
        );
      }
      throw new OpsError("target_changed", `${ref} onaydan sonra değişti (resourceVersion ön koşulu, 409); hiçbir şey uygulanmadı`);
    }
  }
  const j = jsonOf(resp, `${ref} uygulama`);
  return {
    data: { applied: true, ref, created: approvedVersion === "yok", resourceVersion: isObj(j["metadata"]) ? j["metadata"]["resourceVersion"] : undefined },
    summary: `${ref} ${approvedVersion === "yok" ? "oluşturuldu" : "uygulandı"}`,
    subjects: [ref],
  };
}

// ---- scale ------------------------------------------------------------------------------------------

interface ScaleArgs { kind: string; namespace: string; name: string; replicas: number }

export async function previewScale(client: K8sClient, a: ScaleArgs): Promise<ActionPreview> {
  const k = resolveKind(a.kind);
  const live = await getLive(client, k, a.namespace, a.name);
  if (!live) throw new OpsError("not_found", `${refOf(k, a.namespace, a.name)} bulunamadı`);
  const cur = isObj(live["spec"]) && typeof (live["spec"] as Obj)["replicas"] === "number" ? ((live["spec"] as Obj)["replicas"] as number) : 1;
  const ref = refOf(k, a.namespace, a.name);
  const impact = [`replika ${cur} → ${a.replicas}`];
  if (a.replicas === 0) impact.push("⚠ 0 replika: iş yükü hizmet vermeyi durdurur");
  if (cur > 0 && a.replicas > cur * 5) impact.push(`⚠ ${Math.round(a.replicas / cur)} kat büyütme`);
  return {
    targetVersion: rvOf(live),
    diff: unified(ref, yaml({ spec: { replicas: cur } }), yaml({ spec: { replicas: a.replicas } })),
    impact,
    rollback: `k8s.scale ${ref} replicas=${cur}`,
  };
}

export async function doScale(client: K8sClient, a: ScaleArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const k = resolveKind(a.kind);
  const ref = refOf(k, a.namespace, a.name);
  const resp = await client.patch(`${resourcePath(k, a.namespace, a.name)}/scale`, { metadata: { resourceVersion: approvedVersion }, spec: { replicas: a.replicas } }, "application/merge-patch+json");
  if (resp.status === 409) throw new OpsError("target_changed", `${ref} onaydan sonra değişti (409); hiçbir şey uygulanmadı`);
  jsonOf(resp, `${ref} ölçekleme`);
  return { data: { scaled: true, ref, replicas: a.replicas }, summary: `${ref} → ${a.replicas} replika`, subjects: [ref] };
}

// ---- rollout restart / undo -------------------------------------------------------------------------

interface WorkloadArgs { kind: string; namespace: string; name: string }
const RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt";

export async function previewRestart(client: K8sClient, a: WorkloadArgs): Promise<ActionPreview> {
  const k = resolveKind(a.kind);
  const live = await getLive(client, k, a.namespace, a.name);
  if (!live) throw new OpsError("not_found", `${refOf(k, a.namespace, a.name)} bulunamadı`);
  const ref = refOf(k, a.namespace, a.name);
  const spec = isObj(live["spec"]) ? live["spec"] : {};
  const tmpl = isObj(spec["template"]) ? spec["template"] : {};
  const ann = isObj(tmpl["metadata"]) && isObj((tmpl["metadata"] as Obj)["annotations"]) ? (((tmpl["metadata"] as Obj)["annotations"]) as Obj) : {};
  const before = { spec: { template: { metadata: { annotations: { [RESTART_ANNOTATION]: ann[RESTART_ANNOTATION] ?? null } } } } };
  // zaman damgası ÇALIŞTIRMA anında üretilir; önizleme zamandan bağımsızdır (TOCTOU özeti kararlı kalmalı)
  const after = { spec: { template: { metadata: { annotations: { [RESTART_ANNOTATION]: "<çalıştırma anındaki zaman damgası>" } } } } };
  return {
    targetVersion: rvOf(live),
    diff: unified(ref, yaml(before), yaml(after)),
    impact: [`${ref} pod'ları kademeli olarak yeniden oluşturulur (rolling restart)`],
    rollback: "yeniden başlatma geri alınmaz; sorun çıkarsa k8s.rollout.undo ile önceki revizyona dönülebilir (Deployment)",
  };
}

export async function doRestart(client: K8sClient, a: WorkloadArgs, approvedVersion: string | undefined, now: Date): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const k = resolveKind(a.kind);
  const ref = refOf(k, a.namespace, a.name);
  const resp = await client.patch(
    resourcePath(k, a.namespace, a.name),
    { metadata: { resourceVersion: approvedVersion }, spec: { template: { metadata: { annotations: { [RESTART_ANNOTATION]: now.toISOString() } } } } },
    "application/merge-patch+json",
  );
  if (resp.status === 409) throw new OpsError("target_changed", `${ref} onaydan sonra değişti (409); hiçbir şey uygulanmadı`);
  jsonOf(resp, `${ref} yeniden başlatma`);
  return { data: { restarted: true, ref }, summary: `${ref} yeniden başlatılıyor`, subjects: [ref] };
}

interface UndoArgs { namespace: string; name: string; toRevision?: number }
const REVISION = "deployment.kubernetes.io/revision";

async function undoTarget(client: K8sClient, a: UndoArgs): Promise<{ live: Obj; currentRev: number; targetRev: number; template: Obj }> {
  const k = resolveKind("Deployment");
  const live = await getLive(client, k, a.namespace, a.name);
  if (!live) throw new OpsError("not_found", `${refOf(k, a.namespace, a.name)} bulunamadı`);
  const meta = isObj(live["metadata"]) ? live["metadata"] : {};
  const ann = isObj(meta["annotations"]) ? (meta["annotations"] as Obj) : {};
  const currentRev = Number(ann[REVISION] ?? 0);
  const sel = isObj(live["spec"]) && isObj((live["spec"] as Obj)["selector"]) ? (((live["spec"] as Obj)["selector"] as Obj)["matchLabels"] as Obj | undefined) : undefined;
  const labelSelector = sel ? Object.entries(sel).map(([k2, v]) => `${k2}=${String(v)}`).join(",") : undefined;
  const rsResp = await client.get(resourcePath(resolveKind("ReplicaSet"), a.namespace), { labelSelector, limit: 200 });
  const items = Array.isArray(jsonOf(rsResp, "ReplicaSet listesi")["items"]) ? (jsonOf(rsResp, "ReplicaSet listesi")["items"] as unknown[]) : [];
  const uid = meta["uid"];
  const owned = items.filter(isObj).filter((rs) => {
    const owners = isObj(rs["metadata"]) && Array.isArray((rs["metadata"] as Obj)["ownerReferences"]) ? (((rs["metadata"] as Obj)["ownerReferences"]) as unknown[]) : [];
    return owners.some((o) => isObj(o) && o["kind"] === "Deployment" && o["name"] === a.name && (uid === undefined || o["uid"] === uid));
  });
  const revs = owned
    .map((rs) => ({ rs, rev: Number(isObj(rs["metadata"]) && isObj((rs["metadata"] as Obj)["annotations"]) ? (((rs["metadata"] as Obj)["annotations"]) as Obj)[REVISION] : 0) }))
    .filter((x) => x.rev > 0)
    .sort((x, y) => y.rev - x.rev);
  const pick = a.toRevision !== undefined ? revs.find((x) => x.rev === a.toRevision) : revs.find((x) => x.rev < currentRev);
  if (!pick) throw new OpsError("no_previous_revision", a.toRevision !== undefined ? `revizyon ${a.toRevision} bulunamadı` : "geri dönülecek önceki revizyon yok");
  if (pick.rev === currentRev) throw new OpsError("no_previous_revision", "hedef revizyon zaten güncel");
  const tpl = isObj(pick.rs["spec"]) && isObj((pick.rs["spec"] as Obj)["template"]) ? (JSON.parse(JSON.stringify((pick.rs["spec"] as Obj)["template"])) as Obj) : null;
  if (!tpl) throw new OpsError("no_previous_revision", "revizyonun pod şablonu okunamadı");
  if (isObj(tpl["metadata"]) && isObj((tpl["metadata"] as Obj)["labels"])) delete ((tpl["metadata"] as Obj)["labels"] as Obj)["pod-template-hash"];
  return { live, currentRev, targetRev: pick.rev, template: tpl };
}

export async function previewUndo(client: K8sClient, a: UndoArgs): Promise<ActionPreview> {
  const t = await undoTarget(client, a);
  const ref = `Deployment/${a.namespace}/${a.name}`;
  const curTpl = isObj(t.live["spec"]) && isObj((t.live["spec"] as Obj)["template"]) ? (JSON.parse(JSON.stringify((t.live["spec"] as Obj)["template"])) as Obj) : {};
  const imgs = (tpl: Obj): Record<string, string> => {
    const cs = isObj(tpl["spec"]) && Array.isArray((tpl["spec"] as Obj)["containers"]) ? (((tpl["spec"] as Obj)["containers"]) as unknown[]) : [];
    return Object.fromEntries(cs.filter(isObj).map((c) => [String(c["name"]), String(c["image"] ?? "?")]));
  };
  const a1 = imgs(curTpl);
  const b1 = imgs(t.template);
  const impact = [`revizyon ${t.currentRev} → ${t.targetRev}`];
  for (const [n, img] of Object.entries(b1)) if (a1[n] !== img) impact.push(`kapsayıcı ${n}: ${a1[n] ?? "(yok)"} → ${img}`);
  return {
    targetVersion: rvOf(t.live),
    diff: unified(`${ref}#template`, yaml(maskEnv(sanitizeObject("Deployment", curTpl))), yaml(maskEnv(sanitizeObject("Deployment", t.template)))),
    impact,
    rollback: `k8s.rollout.undo ${ref} toRevision=${t.currentRev}`,
  };
}

export async function doUndo(client: K8sClient, a: UndoArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const t = await undoTarget(client, a);
  const k = resolveKind("Deployment");
  const ref = refOf(k, a.namespace, a.name);
  // kubectl rollout undo ile aynı: test(resourceVersion) + replace(/spec/template)
  const resp = await client.patch(
    resourcePath(k, a.namespace, a.name),
    [
      { op: "test", path: "/metadata/resourceVersion", value: approvedVersion },
      { op: "replace", path: "/spec/template", value: t.template },
    ],
    "application/json-patch+json",
  );
  if (resp.status === 409 || resp.status === 422) throw new OpsError("target_changed", `${ref} onaydan sonra değişti; hiçbir şey uygulanmadı`);
  jsonOf(resp, `${ref} geri alma`);
  return { data: { undone: true, ref, fromRevision: t.currentRev, toRevision: t.targetRev }, summary: `${ref} revizyon ${t.targetRev}'e döndürüldü`, subjects: [ref] };
}

// ---- delete -----------------------------------------------------------------------------------------

interface DeleteArgs { kind: string; namespace: string; name: string }

function compactSummary(kind: string, live: Obj): Obj {
  const meta = isObj(live["metadata"]) ? live["metadata"] : {};
  const spec = isObj(live["spec"]) ? live["spec"] : {};
  const tmplSpec = isObj(spec["template"]) && isObj((spec["template"] as Obj)["spec"]) ? ((spec["template"] as Obj)["spec"] as Obj) : isObj(spec["containers"]) || Array.isArray(spec["containers"]) ? spec : {};
  const containers = Array.isArray(tmplSpec["containers"]) ? (tmplSpec["containers"] as unknown[]).filter(isObj).map((c) => ({ name: c["name"], image: c["image"] })) : undefined;
  return sanitizeObject(kind, {
    kind,
    metadata: { name: meta["name"], namespace: meta["namespace"], labels: meta["labels"], ownerReferences: meta["ownerReferences"], creationTimestamp: meta["creationTimestamp"] },
    spec: { ...(typeof spec["replicas"] === "number" ? { replicas: spec["replicas"] } : {}), ...(containers ? { containers } : {}), ...(typeof spec["type"] === "string" ? { type: spec["type"] } : {}) },
  }) as Obj;
}

export async function previewDelete(client: K8sClient, a: DeleteArgs): Promise<ActionPreview> {
  const k = resolveKind(a.kind);
  const ref = refOf(k, a.namespace, a.name);
  const live = await getLive(client, k, a.namespace, a.name);
  if (!live) throw new OpsError("not_found", `${ref} bulunamadı`);
  const meta = isObj(live["metadata"]) ? live["metadata"] : {};
  const uid = typeof meta["uid"] === "string" ? meta["uid"] : "";
  if (uid === "") throw new OpsError("version_missing", "nesnenin uid değeri yok: silme ön koşulu kurulamaz, işlem reddedildi");
  const impact = [`${ref} KALICI olarak silinecek`];
  const owners = Array.isArray(meta["ownerReferences"]) ? (meta["ownerReferences"] as unknown[]).filter(isObj).map((o) => `${String(o["kind"])}/${String(o["name"])}`) : [];
  if (owners.length) impact.push(`sahip nesne(ler): ${owners.join(", ")} — denetleyici yeniden oluşturabilir`);
  if (a.kind === "PersistentVolumeClaim") impact.push("⚠ kalıcı veri kaybı olabilir (PV geri alma politikasına bağlı)");
  if (typeof (isObj(live["spec"]) ? (live["spec"] as Obj)["replicas"] : undefined) === "number") impact.push(`${String((live["spec"] as Obj)["replicas"])} replikalı iş yükü sonlanır`);
  return {
    targetVersion: `${uid}@${rvOf(live)}`,
    diff: unified(ref, yaml(compactSummary(a.kind, live)), ""),
    impact,
    rollback: "silme GERİ ALINAMAZ; yeniden oluşturmak için manifesti kaynak depodan (GitOps) uygulayın",
  };
}

export async function doDelete(client: K8sClient, a: DeleteArgs, approvedVersion: string | undefined): Promise<RawToolOutput> {
  if (approvedVersion === undefined) throw new OpsError("approval_version_missing", "onaylanan hedef sürümü yok; uygulama reddedildi");
  const [uid, rv] = approvedVersion.split("@");
  if (!uid || !rv) throw new OpsError("approval_version_missing", "onaylanan sürüm biçimi geçersiz");
  const k = resolveKind(a.kind);
  const ref = refOf(k, a.namespace, a.name);
  const resp = await client.remove(resourcePath(k, a.namespace, a.name), { kind: "DeleteOptions", apiVersion: "v1", preconditions: { uid, resourceVersion: rv }, propagationPolicy: "Background" });
  if (resp.status === 409) throw new OpsError("target_changed", `${ref} onaydan sonra değişti veya yeniden oluşturuldu (ön koşul 409); hiçbir şey silinmedi`);
  if (resp.status === 404) throw new OpsError("not_found", `${ref} bulunamadı (zaten silinmiş)`);
  jsonOf(resp, `${ref} silme`);
  return { data: { deleted: true, ref }, summary: `${ref} silindi`, subjects: [ref] };
}
