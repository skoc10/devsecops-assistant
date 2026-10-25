/**
 * `terraform|tofu show -json <plan>` çıktısının GÜVENLİ özeti. Plan JSON'u hassas değerler taşıyabilir
 * (bayraklar yalnız gösterim katmanı içindir): bu yüzden özet YALNIZ adresleri, eylemleri, öznitelik
 * ADLARINI ve hassas OLMAYAN, bilinen, skaler değerlerin kısaltılmışını içerir. `prior_state`,
 * `configuration`, `variables`, çıktı değerleri, `after_unknown`/`*_sensitive` ağaçları ASLA kopyalanmaz.
 * Hassas bayraklı veya gizli-benzeri adlı öznitelik değeri hiçbir koşulda çıkmaz.
 */

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

export type PlanAction = "create" | "update" | "delete" | "replace" | "read" | "no-op";

export interface PlanAttr {
  readonly name: string;
  /** Hassas/gizli-benzeri/bilinmeyen için yok. */
  readonly value?: string;
  /** `before → after` (güncellemede). */
  readonly before?: string;
  readonly note?: "hassas" | "gizli-adlı" | "apply sonrası belli";
}

export interface PlanChange {
  readonly address: string;
  readonly type: string;
  readonly action: PlanAction;
  readonly attrs: readonly PlanAttr[];
  readonly risks: readonly string[];
}

export interface PlanSummary {
  readonly formatVersion: string | undefined;
  readonly counts: Readonly<Record<PlanAction, number>>;
  readonly changes: readonly PlanChange[];
  readonly omitted: number;
  readonly outputs: readonly { readonly name: string; readonly action: string; readonly sensitive: boolean }[];
  readonly risks: readonly { readonly label: string; readonly count: number; readonly examples: readonly string[] }[];
  readonly errored: boolean;
}

const SECRETISH = /(pass(word|wd)?|secret|token|api_?key|private|credential|cert(ificate)?|auth|signing|bearer|connection_string|conn_str)/i;
const NOISY = new Set(["tags", "tags_all", "id", "arn", "timeouts", "triggers_replace", "output"]);

/** Risk etiketleri: kaynak TÜRÜ ve eyleme göre kural tabanlı (model yorumu değil). */
const IDENTITY = /(^|_)(iam|role|policy|user|access_key|service_account|principal|permission|rbac|role_assignment|kms|key_vault|secret|credential)(_|$)/;
const NETWORK = /(security_group|firewall|network_acl|nsg|route|ingress|egress|vpc|subnet|load_balancer|(^|_)lb(_|$)|gateway|peering|dns|waf|cidr)/;
const DATA = /(^|_)(db|database|bucket|storage|volume|disk|snapshot|sql|dynamodb|table|cluster|redis|elasticache|rds|s3|blob)(_|$)/;

export function risksFor(type: string, action: PlanAction): string[] {
  const out: string[] = [];
  if (action === "delete") out.push("silme");
  if (action === "replace") out.push("yeniden-yaratma");
  if (IDENTITY.test(type) && action !== "no-op" && action !== "read") out.push("kimlik-yetki");
  if (NETWORK.test(type) && action !== "no-op" && action !== "read") out.push("ağ-kuralı");
  if (DATA.test(type) && (action === "delete" || action === "replace")) out.push("veri-kaybı-riski");
  return out;
}

function actionOf(actions: unknown): PlanAction {
  const a = arr(actions).filter((x): x is string => typeof x === "string");
  if (a.length === 2 && a.includes("delete") && a.includes("create")) return "replace";
  if (a.includes("delete")) return "delete";
  if (a.includes("create")) return "create";
  if (a.includes("update")) return "update";
  if (a.includes("read")) return "read";
  return "no-op";
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n)}…` : s);
const scalar = (v: unknown): string | undefined => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : v === null ? "null" : undefined);

/** `true` veya boş olmayan nesne/dizi → hassas ağacı. */
function isSensitive(tree: unknown, key: string): boolean {
  const t = obj(tree)[key];
  if (t === true) return true;
  if (Array.isArray(t)) return t.length > 0 && t.some((x) => x === true || Object.keys(obj(x)).length > 0);
  return Object.keys(obj(t)).length > 0;
}

function attrsOf(action: PlanAction, change: Obj, maxAttrs: number, valueMax: number): PlanAttr[] {
  const before = obj(change["before"]);
  const after = obj(change["after"]);
  const unknown = obj(change["after_unknown"]);
  const afterSens = change["after_sensitive"];
  const beforeSens = change["before_sensitive"];
  const names = [...new Set([...Object.keys(after), ...Object.keys(unknown)])].filter((k) => !NOISY.has(k));
  const out: PlanAttr[] = [];
  for (const name of names.sort()) {
    const sens = isSensitive(afterSens, name) || isSensitive(beforeSens, name);
    const isUnknown = unknown[name] === true;
    const a = after[name];
    const b = before[name];
    if (action === "update" && !isUnknown && JSON.stringify(a) === JSON.stringify(b)) continue; // değişmedi
    if (sens) {
      out.push({ name, note: "hassas" });
    } else if (SECRETISH.test(name)) {
      out.push({ name, note: "gizli-adlı" });
    } else if (isUnknown) {
      out.push({ name, note: "apply sonrası belli" });
    } else {
      const v = scalar(a);
      if (v === undefined) continue; // nesne/dizi: yalnız adı bile gerekmez (token ekonomisi)
      const bv = action === "update" || action === "replace" ? scalar(b) : undefined;
      out.push({ name, value: clip(v, valueMax), ...(bv !== undefined ? { before: clip(bv, valueMax) } : {}) });
    }
  }
  // değeri gösterilebilenler önce (daha bilgilendirici), sonra "hassas/gizli/bilinmiyor" notlular
  return [...out.filter((a) => a.value !== undefined), ...out.filter((a) => a.value === undefined)].slice(0, maxAttrs);
}

const ACTION_ORDER: Record<PlanAction, number> = { delete: 0, replace: 1, update: 2, create: 3, read: 4, "no-op": 5 };

export function summarizePlan(plan: unknown, opts: { maxChanges?: number; maxAttrs?: number; valueMax?: number } = {}): PlanSummary {
  const maxChanges = opts.maxChanges ?? 40;
  const maxAttrs = opts.maxAttrs ?? 6;
  const valueMax = opts.valueMax ?? 60;
  const p = obj(plan);
  const counts: Record<PlanAction, number> = { create: 0, update: 0, delete: 0, replace: 0, read: 0, "no-op": 0 };
  const all: PlanChange[] = [];
  for (const rcRaw of arr(p["resource_changes"])) {
    const rc = obj(rcRaw);
    const change = obj(rc["change"]);
    const action = actionOf(change["actions"]);
    counts[action] += 1;
    if (action === "no-op") continue;
    const address = typeof rc["address"] === "string" ? clip(rc["address"], 160) : "?";
    const type = typeof rc["type"] === "string" ? clip(rc["type"], 80) : "?";
    all.push({ address, type, action, attrs: attrsOf(action, change, maxAttrs, valueMax), risks: risksFor(type, action) });
  }
  all.sort((x, y) => ACTION_ORDER[x.action] - ACTION_ORDER[y.action] || x.address.localeCompare(y.address));
  const shown = all.slice(0, maxChanges);
  const byRisk = new Map<string, string[]>();
  for (const c of all) for (const r of c.risks) byRisk.set(r, [...(byRisk.get(r) ?? []), c.address]);
  const outputs = Object.entries(obj(p["output_changes"])).slice(0, 30).map(([name, v]) => {
    const o = obj(v);
    return { name: clip(name, 80), action: actionOf(o["actions"]), sensitive: o["after_sensitive"] === true || o["before_sensitive"] === true };
  });
  return {
    formatVersion: typeof p["format_version"] === "string" ? p["format_version"] : undefined,
    counts,
    changes: shown,
    omitted: all.length - shown.length,
    outputs,
    risks: [...byRisk].map(([label, a]) => ({ label, count: a.length, examples: a.slice(0, 3) })).sort((x, y) => y.count - x.count),
    errored: p["errored"] === true,
  };
}
