import { stringify } from "yaml";
import { riskRank } from "@ops/contracts";
import type { DoctorFinding, RiskClass } from "@ops/contracts";

export interface RbacRule {
  readonly verbs: readonly string[];
  readonly apiGroups?: readonly string[];
  readonly resources?: readonly string[];
  readonly resourceNames?: readonly string[];
  readonly nonResourceURLs?: readonly string[];
}

const READ_VERBS = new Set(["get", "list", "watch"]);
const WORKLOADS = new Set(["deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs", "pods", "replicationcontrollers"]);
const ESCALATION_VERBS = new Set(["impersonate", "escalate", "bind", "approve", "sign"]);
const EXEC_SUBRESOURCES = new Set(["pods/exec", "pods/attach", "pods/portforward", "pods/ephemeralcontainers"]);

const has = (xs: readonly string[] | undefined, v: string): boolean => !!xs && (xs.includes(v) || xs.includes("*"));

/**
 * Kimliğin YALNIZ kendi yetkisini/kimliğini soran inceleme kaynakları. Gerçek kümede `system:basic-user`
 * (her kimliği doğrulanmış kullanıcıya bağlı) bunlara `create` verir; nesne oluşturmaz, yazma sayılmaz.
 * Sahte API bu kuralları döndürmediği için kind testine kadar fark edilmedi: salt okunur SA bile `write_access`
 * alıp bağlanamıyordu.
 */
const SELF_REVIEW_RESOURCES = new Set(["selfsubjectaccessreviews", "selfsubjectrulesreviews", "selfsubjectreviews"]);
const REVIEW_GROUPS = new Set(["authorization.k8s.io", "authentication.k8s.io"]);

/** Kuralın kaynakları, yalnız inceleme gruplarına özgü kuralda öz-inceleme kaynakları atılarak (joker grup/kaynak atılmaz). */
function effectiveResources(r: RbacRule): readonly string[] {
  const resources = r.resources ?? [];
  const groups = r.apiGroups ?? [];
  if (groups.length === 0 || !groups.every((g) => REVIEW_GROUPS.has(g))) return resources;
  return resources.filter((x) => !SELF_REVIEW_RESOURCES.has(x));
}

export interface RuleAnalysis {
  readonly effective: RiskClass;
  readonly findings: DoctorFinding[];
  readonly secretsReadable: boolean;
}

/**
 * Fiili RBAC kurallarını risk sınıfına çevirir. Beyan ≠ gerçek yetki: `read` beyan edilmiş bir
 * profilin kimliği yazabiliyor, exec yapabiliyor ya da Secret okuyabiliyorsa bu burada yakalanır.
 */
export function analyzeRules(rules: readonly RbacRule[]): RuleAnalysis {
  let eff: RiskClass = "read";
  const findings = new Map<string, DoctorFinding>();
  const raise = (c: RiskClass): void => {
    if (riskRank(c) > riskRank(eff)) eff = c;
  };
  const note = (severity: DoctorFinding["severity"], code: string, message: string): void => {
    if (!findings.has(code)) findings.set(code, { severity, code, message });
  };
  let secretsReadable = false;

  for (const r of rules) {
    const resources = effectiveResources(r);
    const verbs = r.verbs;
    if (resources.length === 0) continue; // nonResourceURLs / yalnız öz-inceleme: sınıf etkisi yok
    const anyRead = verbs.some((v) => READ_VERBS.has(v) || v === "*");

    if (verbs.includes("*")) {
      raise("destroy");
      note("error", "wildcard_verbs", "kimlik her fiili (*) kullanabiliyor");
    }
    if (resources.includes("*")) {
      note("error", "wildcard_resources", "kimlik her kaynağa (*) erişebiliyor");
      if (anyRead) secretsReadable = true;
    }
    for (const v of verbs) {
      if (ESCALATION_VERBS.has(v)) {
        raise("destroy");
        note("error", "privilege_escalation_verb", `yetki yükseltme fiili: ${v}`);
      }
      if (v === "delete" || v === "deletecollection") {
        raise("destroy");
        note("error", "delete_access", "kimlik kaynak silebiliyor");
      }
      if (v === "create" || v === "update" || v === "patch") {
        const touchesWorkload = resources.some((x) => WORKLOADS.has(x) || x === "*");
        raise(touchesWorkload ? "deploy" : "mutate");
        note("error", "write_access", "kimlik kaynak oluşturabiliyor/değiştirebiliyor");
      }
    }
    for (const res of resources) {
      if (EXEC_SUBRESOURCES.has(res) && verbs.some((v) => v === "create" || v === "get" || v === "*")) {
        raise("mutate");
        note("error", "exec_access", `kimlik ${res} kullanabiliyor (kapsayıcıda komut/ağ erişimi)`);
      }
      if ((res === "nodes/proxy" || res.endsWith("/proxy")) && anyRead) {
        raise("mutate");
        note("error", "proxy_access", `kimlik ${res} üzerinden kubelet/hizmet vekil erişimine sahip`);
      }
      if (res === "serviceaccounts/token" && verbs.some((v) => v === "create" || v === "*")) {
        raise("mutate");
        note("error", "token_mint", "kimlik başka ServiceAccount için token üretebiliyor");
      }
      if (res === "secrets" && anyRead && has(r.apiGroups, "")) {
        secretsReadable = true;
      }
    }
  }
  if (secretsReadable) note("error", "secrets_readable", "kimlik Secret nesnelerini okuyabiliyor (get/list/watch)");
  return { effective: eff, findings: [...findings.values()], secretsReadable };
}

/** `verb` + `resource` (+ grup) bu kurallarca izinli mi? (Yerel, SSAR çağrısı yapmaz.) */
export function ruleAllows(rules: readonly RbacRule[], q: { verb: string; resource: string; group?: string }): boolean {
  const group = q.group ?? "";
  return rules.some((r) => {
    if (!has(r.verbs, q.verb)) return false;
    if (!has(r.apiGroups ?? [""], group)) return false;
    const res = r.resources ?? [];
    return res.includes("*") || res.includes(q.resource) || (q.resource.includes("/") ? false : res.includes(`${q.resource}/*`));
  });
}

// ---- salt okunur RBAC manifesti ------------------------------------------------------------

export interface ReadOnlyRbacOptions {
  /** ServiceAccount (ve ClusterRole) adı. */
  readonly name?: string;
  /** ServiceAccount'un bulunacağı namespace. */
  readonly serviceAccountNamespace: string;
  /** Okuma izni verilecek namespace'ler. */
  readonly namespaces: readonly string[];
  /** Düğüm/namespace/PV/StorageClass okuma (küme kapsamlı). */
  readonly clusterRead?: boolean;
}

export const READONLY_NAMESPACED_RULES: readonly RbacRule[] = [
  { apiGroups: [""], resources: ["pods", "pods/log", "services", "endpoints", "configmaps", "serviceaccounts", "persistentvolumeclaims", "resourcequotas", "limitranges", "events"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["apps"], resources: ["deployments", "replicasets", "statefulsets", "daemonsets"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["batch"], resources: ["jobs", "cronjobs"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["networking.k8s.io"], resources: ["ingresses", "networkpolicies"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["autoscaling"], resources: ["horizontalpodautoscalers"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["policy"], resources: ["poddisruptionbudgets"], verbs: ["get", "list", "watch"] },
];
export const READONLY_CLUSTER_RULES: readonly RbacRule[] = [
  { apiGroups: [""], resources: ["nodes", "namespaces", "persistentvolumes"], verbs: ["get", "list", "watch"] },
  { apiGroups: ["storage.k8s.io"], resources: ["storageclasses"], verbs: ["get", "list", "watch"] },
];

/**
 * Salt okunur kimlik için manifest ÜRETİR; UYGULAMAZ. Secret, exec, proxy, yazma yok.
 * Kullanıcı dosyayı gözden geçirip kendi sürecinde uygular. Uzun ömürlü token Secret'ı üretilmez:
 * kısa ömürlü token için `kubectl create token` önerilir.
 */
export function generateReadOnlyRbac(o: ReadOnlyRbacOptions): string {
  const name = o.name ?? "ops-assistant-reader";
  const labels = { "app.kubernetes.io/managed-by": "ops-assistant-manifest" };
  const docs: unknown[] = [
    { apiVersion: "v1", kind: "ServiceAccount", metadata: { name, namespace: o.serviceAccountNamespace, labels } },
    { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: { name, labels }, rules: READONLY_NAMESPACED_RULES },
  ];
  for (const ns of o.namespaces) {
    docs.push({
      apiVersion: "rbac.authorization.k8s.io/v1",
      kind: "RoleBinding",
      metadata: { name, namespace: ns, labels },
      roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name },
      subjects: [{ kind: "ServiceAccount", name, namespace: o.serviceAccountNamespace }],
    });
  }
  if (o.clusterRead) {
    docs.push(
      { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: { name: `${name}-cluster`, labels }, rules: READONLY_CLUSTER_RULES },
      {
        apiVersion: "rbac.authorization.k8s.io/v1",
        kind: "ClusterRoleBinding",
        metadata: { name: `${name}-cluster`, labels },
        roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: `${name}-cluster` },
        subjects: [{ kind: "ServiceAccount", name, namespace: o.serviceAccountNamespace }],
      },
    );
  }
  const header = [
    "# ops-assistant: salt okunur kimlik için ÖNERİLEN RBAC manifesti.",
    "# Bu dosya ürün tarafından UYGULANMAZ; gözden geçirip kendi sürecinizle uygulayın.",
    "# Secret, exec/portforward, proxy ve yazma izni YOKTUR. Kısa ömürlü token: kubectl create token <ad> -n <ns>",
    "",
  ].join("\n");
  return header + docs.map((d) => stringify(d)).join("---\n");
}
