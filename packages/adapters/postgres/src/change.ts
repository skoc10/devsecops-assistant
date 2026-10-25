import { strongerLock } from "@ops/classifiers";
import type { ChangeAnalysis, ChangeKind, ChangeRelation, LockMode } from "@ops/classifiers";
import type { ActionPreview, RiskClass } from "@ops/contracts";

/** Onaylanabilen etkilenen-satır üst sınırı (toplam, tüm ifadeler): varsayılan ve tavan. */
export const DEFAULT_CHANGE_MAX_ROWS = 1_000;
export const MAX_APPROVED_ROWS = 100_000;

export interface PlanStatement {
  readonly index: number;
  readonly kind: ChangeKind;
  readonly risk: RiskClass;
  /** Sunucuya aynen gönderilecek tek ifade. */
  readonly text: string;
  /** Etkilenen satır sayısı sayılan (INSERT/UPDATE/DELETE) ifade mi? */
  readonly dml: boolean;
  readonly unbounded: boolean;
}

export interface PlanRelation {
  readonly schema: string;
  readonly name: string;
}

export interface PlanLock extends PlanRelation {
  readonly mode: LockMode;
}

/** Onaylanan ifade kümesinin yürütme planı: ifadeler, kilitler, parmak izi alınacak ilişkiler ve sınırlar. */
export interface ChangePlan {
  readonly digest: string;
  readonly statements: readonly PlanStatement[];
  readonly locks: readonly PlanLock[];
  readonly touched: readonly PlanRelation[];
  readonly maxRows: number;
  readonly timeoutMs: number;
  readonly hasDdl: boolean;
}

const DML_KINDS: ReadonlySet<ChangeKind> = new Set(["insert", "update", "delete"]);
const keyOf = (r: PlanRelation): string => `${r.schema}.${r.name}`;
const resolve = (r: ChangeRelation, defaultSchema: string): PlanRelation => ({ schema: r.schema ?? defaultSchema, name: r.name });

export function buildPlan(analysis: ChangeAnalysis, defaultSchema: string, maxRows: number, timeoutMs: number): ChangePlan {
  const locks = new Map<string, PlanLock>();
  const touched = new Map<string, PlanRelation>();
  const lock = (r: PlanRelation, mode: LockMode): void => {
    const k = keyOf(r);
    const had = locks.get(k);
    locks.set(k, { ...r, mode: had ? strongerLock(had.mode, mode) : mode });
    touched.set(k, r);
  };
  for (const s of analysis.statements) {
    for (const t of s.targets) lock(resolve(t, defaultSchema), s.lockMode);
    for (const r of s.reads) lock(resolve(r, defaultSchema), "ACCESS SHARE");
  }
  const sorted = <T extends PlanRelation>(m: Map<string, T>): T[] => [...m.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v);
  return {
    digest: analysis.digest,
    statements: analysis.statements.map((s) => ({ index: s.index, kind: s.kind, risk: s.risk, text: s.text, dml: DML_KINDS.has(s.kind), unbounded: s.unbounded })),
    locks: sorted(locks),
    touched: sorted(touched),
    maxRows,
    timeoutMs,
    hasDdl: analysis.statements.some((s) => !DML_KINDS.has(s.kind)),
  };
}

/** PEP kapsamı: hedef ve okunan ilişkilerin şemaları (nitelenmemiş = varsayılan şema). */
export function changeScopes(analysis: ChangeAnalysis, defaultSchema: string): string[] {
  const out = new Set<string>();
  for (const s of analysis.statements) for (const r of [...s.targets, ...s.reads]) out.add(r.schema ?? defaultSchema);
  return [...out];
}

/** Atıf başvuruları: var olan hedef tablolar `Table/…`; yeni yaratılan nesnenin şeması `Schema/…`. */
export function changeRefs(analysis: ChangeAnalysis, defaultSchema: string): string[] {
  const out = new Set<string>();
  for (const s of analysis.statements) {
    for (const t of s.targets) {
      const r = resolve(t, defaultSchema);
      out.add(s.creates ? `Schema/${r.schema}` : `Table/${keyOf(r)}`);
    }
  }
  return [...out];
}

const MAX_STMT_DISPLAY = 2_000;

/** Onay ekranı için önizleme: ifade kümesi, tahmini etki, kilitler ve geri alma notu. */
export function renderPreview(plan: ChangePlan, estimates: readonly (number | null)[], version: string): ActionPreview {
  const lines: string[] = [
    `# db.change — ${plan.statements.length} ifade, TEK işlem (hata ya da satır üst sınırı aşımında tamamı ROLLBACK)`,
    `# onaylı üst sınır: toplam ${plan.maxRows} etkilenen satır · ifade seti sha256:${plan.digest.slice(0, 16)}`,
  ];
  for (const s of plan.statements) {
    const est = estimates[s.index];
    const tag = [s.kind, s.risk, s.dml ? (est === null || est === undefined ? "satır tahmini yok" : `≈${est} satır`) : "şema değişikliği", s.unbounded ? "WHERE YOK/SINIRLAMIYOR" : ""].filter(Boolean).join(" · ");
    lines.push(`[${s.index + 1}/${plan.statements.length}] ${tag}`);
    lines.push(s.text.length > MAX_STMT_DISPLAY ? `${s.text.slice(0, MAX_STMT_DISPLAY)}… (kesildi; tam metin sha256 ile bağlıdır)` : s.text);
  }
  const known = estimates.filter((e): e is number => typeof e === "number");
  const total = known.reduce((a, b) => a + b, 0);
  const impact: string[] = [];
  const dml = plan.statements.filter((s) => s.dml);
  if (dml.length > 0) {
    const complete = known.length === dml.length;
    impact.push(`tahmini etkilenen satır: ${complete ? "" : "≥ "}${total} (planlayıcı tahmini; yürütmede gerçek sayı sayılır)${total > plan.maxRows ? ` — ÜST SINIRI (${plan.maxRows}) AŞIYOR: büyük olasılıkla ROLLBACK` : ""}`);
  }
  for (const s of plan.statements) if (s.unbounded) impact.push(`ifade ${s.index + 1}: WHERE yok ya da satırları sınırlamıyor (sütuna başvurmuyor) — tüm satırlar etkilenir`);
  const strong = plan.locks.filter((l) => l.mode === "ACCESS EXCLUSIVE" || l.mode === "SHARE");
  if (strong.length > 0) impact.push(`kilit (işlem boyunca): ${strong.map((l) => `${l.schema}.${l.name} ${l.mode}`).join(", ")}`);
  impact.push(`en yüksek sınıf: ${plan.statements.reduce<RiskClass>((m, s) => (rank(s.risk) > rank(m) ? s.risk : m), "mutate")}`);
  return {
    targetVersion: version,
    diff: lines.join("\n"),
    impact,
    rollback: "Tek işlemdir: hata ya da satır üst sınırı aşımında otomatik ROLLBACK. COMMIT sonrası otomatik geri alma yoktur: ters ifade veya yedek/PITR gerekir.",
  };
}

const RANK: Record<RiskClass, number> = { read: 0, mutate: 1, deploy: 2, destroy: 3 };
const rank = (c: RiskClass): number => RANK[c];
