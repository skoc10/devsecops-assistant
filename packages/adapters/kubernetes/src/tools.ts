import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { ToolDefinition, ToolDescriptorMeta } from "@ops/contracts";
import { DELETE_KINDS, RESTART_KINDS, SCALE_KINDS } from "./change.ts";
import { DNS_LABEL, DNS_SUBDOMAIN, SELECTOR } from "./kinds.ts";

const base = {
  profileKind: "k8s",
  sensitivity: "internal",
  idempotent: true,
  scope: "target",
  network: "allowlisted",
  redactionProfile: "k8s",
} as const satisfies Partial<ToolDescriptorMeta>;

const ns = z.string().regex(DNS_LABEL).max(63);
const objName = z.string().regex(DNS_SUBDOMAIN).max(253);
const selector = z.string().regex(SELECTOR);
const select = z.array(z.string().min(1).max(80)).max(20);
const kind = z.string().min(1).max(40);
const since = z.string().regex(/^\d{1,6}[smhd]$/);

/** Liste araçlarının varsayılan kompakt alan kümesi (tür-bağımsız birleşim; boş alanlar atılır). */
const LIST_FIELDS = [
  "kind",
  "namespace",
  "count",
  "truncated",
  "remaining",
  "note",
  "items.metadata.name",
  "items.metadata.namespace",
  "items.metadata.creationTimestamp",
  "items.type",
  "items.dataKeyCount",
  "items.spec.type",
  "items.spec.replicas",
  "items.status.phase",
  "items.status.replicas",
  "items.status.readyReplicas",
  "items.status.availableReplicas",
  "items.status.containerStatuses.name",
  "items.status.containerStatuses.ready",
  "items.status.containerStatuses.restartCount",
  "items.status.containerStatuses.state",
] as const;

const GET_FIELDS = [
  "kind",
  "metadata.name",
  "metadata.namespace",
  "metadata.labels",
  "metadata.creationTimestamp",
  "metadata.deletionTimestamp",
  "metadata.ownerReferences",
  "type",
  "dataKeyCount",
  "spec.replicas",
  "spec.selector",
  "spec.type",
  "spec.nodeName",
  "spec.containers.name",
  "spec.containers.image",
  "spec.template.spec.containers.name",
  "spec.template.spec.containers.image",
  "status",
] as const;

export const profileDescribe = defineTool(
  {
    ...base,
    name: "k8s.profile.describe",
    description: "Bağlı küme profilinin secret içermeyen tanımı: ad, ortam, sunucu, izinli kapsamlar, sınıf tavanı.",
    class: "read",
    network: "none",
    toolset: "core",
    limits: { timeoutMs: 5_000, maxBytes: 8_000, maxItems: 50, maxOutputTokens: 600 },
    untrustedOutput: false,
    typicalOutputTokens: 120,
  },
  z.strictObject({}),
);

export const resourcesList = defineTool(
  {
    ...base,
    name: "k8s.resources.list",
    description: "Kaynakları listeler (en çok 200). Dar sonuç için labelSelector/fieldSelector; alan genişletmek için select ('items.' önekli).",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 15_000, maxBytes: 400_000, maxItems: 200, maxOutputTokens: 1_500 },
    untrustedOutput: false,
    projection: { defaultFields: [...LIST_FIELDS], selectable: true },
    typicalOutputTokens: 600,
  },
  z.strictObject({
    kind,
    namespace: ns.optional(),
    labelSelector: selector.optional(),
    fieldSelector: selector.optional(),
    limit: z.number().int().min(1).max(200).optional(),
    select: select.optional(),
  }),
);

export const resourcesGet = defineTool(
  {
    ...base,
    name: "k8s.resources.get",
    description: "Tek kaynağı getirir. Varsayılan görünüm kompakttır; ayrıntı için select (nokta yolları).",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 15_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_500 },
    untrustedOutput: false,
    projection: { defaultFields: [...GET_FIELDS], selectable: true },
    typicalOutputTokens: 500,
  },
  z.strictObject({ kind, name: objName, namespace: ns.optional(), select: select.optional() }),
);

export const resourcesDescribe = defineTool(
  {
    ...base,
    name: "k8s.resources.describe",
    description: "Kaynağın birleşik görünümü: nesne durumu ve ilgili son olaylar.",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 20_000, maxBytes: 300_000, maxItems: 100, maxOutputTokens: 1_500 },
    untrustedOutput: true,
    projection: { defaultFields: [...GET_FIELDS.map((f) => `object.${f}`).filter((f) => f !== "object.kind"), "object.kind", "events", "note"], selectable: true },
    typicalOutputTokens: 900,
  },
  z.strictObject({ kind, name: objName, namespace: ns.optional(), select: select.optional() }),
);

export const eventsList = defineTool(
  {
    ...base,
    name: "k8s.events.list",
    description: "Namespace olayları (son ilk). since zorunlu; involvedKind/involvedName/type ile daraltılır.",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 15_000, maxBytes: 200_000, maxItems: 200, maxOutputTokens: 1_500 },
    untrustedOutput: true,
    projection: { defaultFields: ["namespace", "since", "count", "truncated", "note", "items.type", "items.reason", "items.message", "items.count", "items.last", "items.object"], selectable: true },
    typicalOutputTokens: 500,
  },
  z.strictObject({
    namespace: ns,
    since,
    involvedKind: kind.optional(),
    involvedName: objName.optional(),
    type: z.enum(["Normal", "Warning"]).optional(),
    limit: z.number().int().min(1).max(200).optional(),
    select: select.optional(),
  }),
);

export const podsLogs = defineTool(
  {
    ...base,
    name: "k8s.pods.logs",
    description: "Pod logu. since zorunlu, tailLines ≤1000. Çok kapsayıcılı podda container verin; çöken için previous.",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 20_000, maxBytes: 256_000, maxItems: 1_000, maxOutputTokens: 1_500 },
    untrustedOutput: true,
    typicalOutputTokens: 700,
  },
  z.strictObject({
    namespace: ns,
    pod: objName,
    container: z.string().regex(DNS_LABEL).max(63).optional(),
    previous: z.boolean().optional(),
    since,
    tailLines: z.number().int().min(1).max(1_000).optional(),
  }),
);

export const authCanI = defineTool(
  {
    ...base,
    name: "k8s.auth.can_i",
    description: "Bu profilin kendi kimliğinin namespace'teki yetkileri (kural listesi). verb+resource verilirse tek evet/hayır.",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 10_000, maxBytes: 100_000, maxItems: 100, maxOutputTokens: 1_200 },
    untrustedOutput: false,
    typicalOutputTokens: 400,
  },
  z.strictObject({
    namespace: ns,
    verb: z.string().regex(/^[a-z*]{1,20}$/).optional(),
    resource: z.string().regex(/^[a-z0-9*./-]{1,60}$/).optional(),
    group: z.string().regex(/^[a-z0-9.-]{0,60}$/).optional(),
  }),
);

export const workloadHealth = defineTool(
  {
    ...base,
    name: "k8s.workload.health",
    description: "İş yükünün türetilmiş sağlığı: rollout, replikalar, sorunlu kapsayıcılar, HPA/PDB, düğüm baskısı, bulgu kodları. Önce bunu çağırın.",
    class: "read",
    toolset: "k8s",
    limits: { timeoutMs: 25_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_500 },
    untrustedOutput: false,
    typicalOutputTokens: 450,
  },
  z.strictObject({ kind: z.enum(["Deployment", "StatefulSet", "DaemonSet", "Job"]), name: objName, namespace: ns }),
);

export const K8S_READ_TOOLS: readonly ToolDefinition[] = [
  profileDescribe,
  resourcesList,
  resourcesGet,
  resourcesDescribe,
  eventsList,
  podsLogs,
  authCanI,
  workloadHealth,
];

// ---- değişiklik araçları (Faz 2b): ayrı toolset, ayrı sınıflar, hepsi önizleme + onay + TOCTOU -----------

const writeBase = {
  ...base,
  toolset: "k8s-change",
  idempotent: false,
  untrustedOutput: false,
  limits: { timeoutMs: 30_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_200 },
  typicalOutputTokens: 300,
} as const satisfies Partial<ToolDescriptorMeta>;

const manifest = z.string().min(10).max(60_000);

export const applyDiff = defineTool(
  {
    ...writeBase,
    name: "k8s.apply.diff",
    description: "Manifest tek nesneyi canlıyla karşılaştırır (yalnız okuma): birleşik diff, etki ve risk işaretleri. Uygulamadan önce HER ZAMAN çağırın.",
    class: "read",
    idempotent: true,
    typicalOutputTokens: 600,
  },
  z.strictObject({ manifest }),
);

export const apply = defineTool(
  {
    ...writeBase,
    name: "k8s.apply",
    description: "Manifesti uygular (server-side apply; yoksa oluşturur). Onay ekranı diff'i gösterir; hedef onaydan sonra değişirse uygulanmaz. Secret/Pod/RBAC/küme kapsamlı tür yok.",
    class: "deploy",
  },
  z.strictObject({ manifest }),
);

export const scale = defineTool(
  {
    ...writeBase,
    name: "k8s.scale",
    description: "Deployment/StatefulSet/ReplicaSet replika sayısını değiştirir (tek iş yükü).",
    class: "mutate",
  },
  z.strictObject({ kind: z.enum(SCALE_KINDS), namespace: ns, name: objName, replicas: z.number().int().min(0).max(1_000) }),
);

export const rolloutRestart = defineTool(
  {
    ...writeBase,
    name: "k8s.rollout.restart",
    description: "Deployment/StatefulSet/DaemonSet pod'larını kademeli yeniden başlatır (şablon ek açıklamasını günceller).",
    class: "mutate",
  },
  z.strictObject({ kind: z.enum(RESTART_KINDS), namespace: ns, name: objName }),
);

export const rolloutUndo = defineTool(
  {
    ...writeBase,
    name: "k8s.rollout.undo",
    description: "Deployment'ı önceki (veya toRevision) revizyonun pod şablonuna döndürür.",
    class: "deploy",
  },
  z.strictObject({ namespace: ns, name: objName, toRevision: z.number().int().min(1).optional() }),
);

export const resourcesDelete = defineTool(
  {
    ...writeBase,
    name: "k8s.resources.delete",
    description: "Tek nesneyi KALICI siler (uid + resourceVersion ön koşullu). Varsayılan kapalı: profil tavanı 'destroy' ve ortam/kaynak adı yazdırma gerekir.",
    class: "destroy",
  },
  z.strictObject({ kind: z.enum(DELETE_KINDS as [string, ...string[]]), namespace: ns, name: objName }),
);

export const K8S_WRITE_TOOLS: readonly ToolDefinition[] = [applyDiff, apply, scale, rolloutRestart, rolloutUndo, resourcesDelete];
