import { OpsError } from "@ops/contracts";

export interface KindInfo {
  readonly kind: string;
  readonly plural: string;
  /** `v1` veya `<grup>/<sürüm>`. */
  readonly apiVersion: string;
  readonly namespaced: boolean;
  readonly aliases: readonly string[];
}

const K = (kind: string, plural: string, apiVersion: string, namespaced: boolean, aliases: string[] = []): KindInfo => ({
  kind,
  plural,
  apiVersion,
  namespaced,
  aliases,
});

/**
 * Okunabilen kaynak türleri: KAPALI liste. Rastgele grup/sürüm/çoğul kabul edilmez (yeni tür =
 * kod değişikliği + conformance). `Event` için `k8s.events.list` kullanılır.
 */
export const KINDS: readonly KindInfo[] = [
  K("Pod", "pods", "v1", true, ["po"]),
  K("Service", "services", "v1", true, ["svc"]),
  K("Endpoints", "endpoints", "v1", true, ["ep"]),
  K("ConfigMap", "configmaps", "v1", true, ["cm"]),
  K("Secret", "secrets", "v1", true),
  K("ServiceAccount", "serviceaccounts", "v1", true, ["sa"]),
  K("PersistentVolumeClaim", "persistentvolumeclaims", "v1", true, ["pvc"]),
  K("ResourceQuota", "resourcequotas", "v1", true, ["quota"]),
  K("LimitRange", "limitranges", "v1", true, ["limits"]),
  K("Node", "nodes", "v1", false, ["no"]),
  K("Namespace", "namespaces", "v1", false, ["ns"]),
  K("PersistentVolume", "persistentvolumes", "v1", false, ["pv"]),
  K("Deployment", "deployments", "apps/v1", true, ["deploy"]),
  K("ReplicaSet", "replicasets", "apps/v1", true, ["rs"]),
  K("StatefulSet", "statefulsets", "apps/v1", true, ["sts"]),
  K("DaemonSet", "daemonsets", "apps/v1", true, ["ds"]),
  K("Job", "jobs", "batch/v1", true),
  K("CronJob", "cronjobs", "batch/v1", true, ["cj"]),
  K("Ingress", "ingresses", "networking.k8s.io/v1", true, ["ing"]),
  K("NetworkPolicy", "networkpolicies", "networking.k8s.io/v1", true, ["netpol"]),
  K("HorizontalPodAutoscaler", "horizontalpodautoscalers", "autoscaling/v2", true, ["hpa"]),
  K("PodDisruptionBudget", "poddisruptionbudgets", "policy/v1", true, ["pdb"]),
  K("StorageClass", "storageclasses", "storage.k8s.io/v1", false, ["sc"]),
];

const byName = new Map<string, KindInfo>();
for (const k of KINDS) {
  for (const n of [k.kind, k.plural, ...k.aliases]) byName.set(n.toLowerCase(), k);
}

/** `Pod`, `pods`, `po` → KindInfo. Bilinmeyen tür açık hata verir (desteklenenleri sayar). */
export function resolveKind(name: string): KindInfo {
  const k = byName.get(name.toLowerCase());
  if (!k) {
    throw new OpsError("kind_unsupported", `desteklenmeyen kaynak türü '${name.slice(0, 40)}'. Desteklenenler: ${KINDS.map((x) => x.kind).join(", ")}`);
  }
  return k;
}

export const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
export const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/;
/** Seçici ifadeleri: sunucuya yalnız bu karakterlerle gider. */
export const SELECTOR = /^[A-Za-z0-9_.,=!()/ -]{0,256}$/;

/** Kümeye özgü (isim alanı olmayan) kaynaklar için PEP kapsamı. Profil `cluster` veya `*` izinli olmalı. */
export const CLUSTER_SCOPE = "cluster";

export function apiBase(k: KindInfo): string {
  return k.apiVersion === "v1" ? "/api/v1" : `/apis/${k.apiVersion}`;
}

export function resourcePath(k: KindInfo, namespace: string | undefined, name?: string): string {
  const ns = k.namespaced ? `/namespaces/${encodeURIComponent(namespace ?? "")}` : "";
  const nm = name ? `/${encodeURIComponent(name)}` : "";
  return `${apiBase(k)}${ns}/${k.plural}${nm}`;
}
