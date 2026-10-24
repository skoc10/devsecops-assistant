import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { ToolDefinition, ToolDescriptorMeta } from "@ops/contracts";
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

export const K8S_READ_TOOLS: readonly ToolDefinition[] = [profileDescribe, resourcesList, resourcesGet, resourcesDescribe, eventsList, podsLogs];
