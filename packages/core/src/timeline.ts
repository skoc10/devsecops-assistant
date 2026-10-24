import type { Sensitivity } from "@ops/contracts";
import type { EvidenceEntry } from "./evidence.ts";

/**
 * `timeline.build`: kanıt deposundaki farklı kaynaklı sonuçları DETERMİNİSTİK anahtarlarla (imaj
 * özeti, commit SHA, koşu/iş kimliği) tek zaman çizelgesinde birleştirir. LLM birleştirmez, yorumlar.
 *
 * Güvenlik: çıktıya YALNIZ şema-tipli alanlar girer (zaman, enum, sayı, kısa karakter kümesi sınırlı
 * adlar, kimlikler). Commit mesajı, PR başlığı, olay/günlük metni GİRMEZ; bu yüzden çıktı taint'siz
 * sayılır (tasarım §4.2 şema-tipli alan ilkesi). Her olay kaynak kanıt kimliğini (`ev`) taşır.
 */

export type TimelineSource = "k8s" | "pipeline" | "scm" | "db";

export interface TimelineEvent {
  readonly t: string;
  readonly source: TimelineSource;
  readonly kind: string;
  readonly summary: string;
  /** Kaynak kanıt kimliği (atıf için). */
  readonly ev: string;
  /** Zaman yaklaşık mı (gerçek değişiklik zamanı yerine gözlem zamanı kullanıldı)? */
  readonly approx?: boolean;
}

export interface TimelineLink {
  /** Bağı kuran anahtar türleri (digest | commit | run | job). */
  readonly via: string[];
  readonly keys: string[];
  /** `events` dizisindeki dizinler. */
  readonly events: number[];
  readonly sources: TimelineSource[];
}

export interface Timeline {
  readonly window: { readonly from: string | null; readonly to: string | null };
  readonly events: TimelineEvent[];
  readonly links: TimelineLink[];
  /** Bağ kurulamayan ama zamanca yakın (kural tabanlı) ipuçları; kesin değil. */
  readonly hints: string[];
  readonly sources: Readonly<Record<string, number>>;
  readonly skipped: { readonly ev: string; readonly reason: string }[];
  readonly truncated?: boolean;
  readonly note: string;
}

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
/** Kalıp-doğrulamalı kısa tanımlayıcı: boşluk yok (`_`), en çok `max` karakter, kalan karakterler `?`. */
const clean = (v: unknown, max = 48): string | undefined => {
  if (typeof v !== "string") return undefined;
  const c = v.trim().slice(0, max * 2).replace(/\s+/g, "_").slice(0, max).replace(/[^A-Za-z0-9._/@#+:,=-]/g, "?");
  return c === "" ? undefined : c;
};
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const iso = (v: unknown): string | undefined => {
  if (typeof v !== "string") return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
};
const sha40 = (v: unknown): string | undefined => (typeof v === "string" && /^[0-9a-f]{40}$/.test(v) ? v : undefined);
const DIGEST = /sha256:[0-9a-f]{64}/g;
const KEEP_JOB = /deploy|release|rollout|publish|promote|push/i;

interface Raw {
  readonly t: string;
  readonly source: TimelineSource;
  readonly kind: string;
  readonly summary: string;
  readonly ev: string;
  readonly approx?: boolean;
  readonly keys: string[];
}

const digestsIn = (text: string): string[] => [...new Set(text.match(DIGEST) ?? [])].map((d) => `digest:${d}`);

function imageKeys(images: unknown): string[] {
  const keys: string[] = [];
  for (const im of arr(images).map(obj)) {
    if (typeof im["digest"] === "string" && /^sha256:[0-9a-f]{64}$/.test(im["digest"])) keys.push(`digest:${im["digest"]}`);
    // imaj etiketi commit kısaltması olabilir (örn. app:9f2c1ab)
    const tag = typeof im["image"] === "string" ? /:([0-9a-f]{7,40})$/.exec(im["image"])?.[1] : undefined;
    if (tag) keys.push(tag.length === 40 ? `commit:${tag}` : `commit7:${tag}`);
  }
  return keys;
}

function fromEntry(e: EvidenceEntry): { events: Raw[]; bridge: string[] } | { skip: string } {
  let data: unknown;
  try {
    data = JSON.parse(e.text);
  } catch {
    return { skip: "kanıt JSON değil" };
  }
  const d = obj(data);
  const ev = e.id;
  const mk = (r: Omit<Raw, "ev" | "keys"> & { keys?: string[] }): Raw => ({ ...r, ev, keys: r.keys ?? [] });
  const events: Raw[] = [];
  const bridge: string[] = [];

  switch (e.tool) {
    case "pipeline.runs.list":
    case "pipeline.run.get": {
      const items = e.tool === "pipeline.run.get" ? [d] : arr(d["items"]).map(obj);
      for (const r of items) {
        const id = num(r["id"]);
        const done = r["status"] === "completed";
        const t = iso(done ? r["updatedAt"] : r["createdAt"]) ?? iso(r["createdAt"]);
        if (!t || id === undefined) continue;
        const sha = sha40(r["sha"]);
        events.push(
          mk({
            t,
            source: "pipeline",
            kind: done ? `run_${clean(r["conclusion"], 20) ?? "done"}` : "run_started",
            summary: `koşu #${id} ${clean(r["workflow"]) ?? "?"} ${done ? (clean(r["conclusion"], 20) ?? "bitti") : "başladı"}${r["branch"] ? ` (${clean(r["branch"])})` : ""}`,
            keys: [`run:${id}`, ...(sha ? [`commit:${sha}`] : [])],
          }),
        );
      }
      return { events, bridge };
    }
    case "pipeline.jobs.list": {
      const runId = num(d["runId"]);
      const ids = arr(d["items"]).map(obj).flatMap((j) => (num(j["id"]) !== undefined ? [`job:${num(j["id"])}`] : []));
      bridge.push(...(runId !== undefined ? [`run:${runId}`] : []), ...ids);
      for (const j of arr(d["items"]).map(obj)) {
        const t = iso(j["completedAt"]);
        const id = num(j["id"]);
        const name = clean(j["name"]);
        const bad = typeof j["conclusion"] === "string" && j["conclusion"] !== "success" && j["conclusion"] !== "skipped";
        if (!t || id === undefined || !name || !(bad || KEEP_JOB.test(name))) continue;
        const failed = arr(j["failedSteps"]).map((s) => clean(s, 40)).filter((x): x is string => !!x).slice(0, 3);
        events.push(mk({ t, source: "pipeline", kind: bad ? "job_failed" : "job_done", summary: `iş ${name} ${bad ? `başarısız (${clean(j["conclusion"], 20)})` : "bitti"}${failed.length ? ` — adım: ${failed.join(", ")}` : ""}`, keys: [`job:${id}`, ...(runId !== undefined ? [`run:${runId}`] : [])] }));
      }
      return { events, bridge };
    }
    case "pipeline.job.logs": {
      // günlükten yalnız imaj özetleri (anahtar) alınır; metin çizelgeye girmez
      const text = typeof data === "string" ? data : JSON.stringify(data);
      const job = e.subjects.find((s) => s.startsWith("Job/"))?.slice(4);
      const run = e.subjects.find((s) => s.startsWith("Run/"))?.slice(4);
      bridge.push(...digestsIn(text), ...(job ? [`job:${job}`] : []), ...(run ? [`run:${run}`] : []));
      return { events, bridge };
    }
    case "pipeline.artifacts.list": {
      const runId = num(d["runId"]);
      for (const a of arr(d["items"]).map(obj)) if (typeof a["digest"] === "string" && /^sha256:[0-9a-f]{64}$/.test(a["digest"])) bridge.push(`digest:${a["digest"]}`);
      if (runId !== undefined) bridge.push(`run:${runId}`);
      return { events, bridge };
    }
    case "scm.commit.list": {
      for (const c of arr(d["items"]).map(obj)) {
        const sha = sha40(c["sha"]);
        const t = iso(c["date"]);
        if (!sha || !t) continue;
        events.push(mk({ t, source: "scm", kind: "commit", summary: `commit ${sha.slice(0, 7)} — ${clean(c["author"]) ?? "?"}`, keys: [`commit:${sha}`] }));
      }
      return { events, bridge };
    }
    case "scm.pr.list": {
      for (const p of arr(d["items"]).map(obj)) {
        const t = iso(p["mergedAt"]);
        const n = num(p["number"]);
        if (!t || n === undefined) continue;
        const sha = sha40(p["headSha"]);
        events.push(mk({ t, source: "scm", kind: "pr_merged", summary: `PR #${n} birleşti (${clean(p["head"]) ?? "?"} → ${clean(p["base"]) ?? "?"})`, keys: [`pr:${n}`, ...(sha ? [`commit:${sha}`] : [])] }));
      }
      return { events, bridge };
    }
    case "k8s.events.list": {
      for (const x of arr(d["items"]).map(obj)) {
        const t = iso(x["last"]);
        const reason = clean(x["reason"], 40);
        if (!t || !reason) continue;
        const count = num(x["count"]);
        events.push(mk({ t, source: "k8s", kind: reason, summary: `${clean(x["type"], 10) ?? "?"} ${reason}${x["object"] ? ` ${clean(x["object"])}` : ""}${count && count > 1 ? ` ×${count}` : ""}` }));
      }
      return { events, bridge };
    }
    case "k8s.workload.health": {
      const w = obj(d["workload"]);
      const pods = obj(d["pods"]);
      const lastUpdate = iso(w["lastUpdate"]);
      const newestPod = iso(pods["newestCreatedAt"]);
      const t = lastUpdate ?? newestPod ?? iso(e.observedAt);
      if (!t) return { events, bridge };
      const findings = arr(d["findings"]).map(obj).map((f) => clean(f["code"], 40)).filter((x): x is string => !!x);
      const codes = [...new Set(findings)].slice(0, 3);
      const nm = `${clean(w["kind"], 20) ?? "?"} ${clean(w["namespace"]) ?? "?"}/${clean(w["name"]) ?? "?"}`;
      events.push(
        mk({
          t,
          source: "k8s",
          kind: "rollout",
          summary: `${nm} rollout=${clean(w["rollout"], 20) ?? "?"} hazır ${num(w["ready"]) ?? "?"}/${num(w["desired"]) ?? "?"}${codes.length ? ` [${codes.join(",")}]` : ""}`,
          keys: [...imageKeys(d["images"]), `workload:${nm.replace(/ /g, "")}`],
          ...(lastUpdate || newestPod ? {} : { approx: true }),
        }),
      );
      return { events, bridge };
    }
    case "db.stats.summary": {
      const waiting = num(d["waitingOnLocks"]) ?? 0;
      const blocked = num(d["blockedSessions"]) ?? 0;
      const longest = num(d["longestActiveSec"]) ?? 0;
      const lag = num(d["replayLagSec"]) ?? 0;
      if (waiting === 0 && blocked === 0 && longest < 30 && lag < 30) return { events, bridge };
      const t = iso(e.observedAt);
      if (!t) return { events, bridge };
      events.push(mk({ t, source: "db", kind: "db_contention", summary: `veritabanı: ${waiting} kilit beklemesi, ${blocked} bloklu oturum, en uzun aktif sorgu ${longest}sn${lag ? `, replika gecikmesi ${lag}sn` : ""}`, approx: true }));
      return { events, bridge };
    }
    default:
      return { skip: "bu araç zaman çizelgesi üretmiyor" };
  }
}

// ---- birleşik küme (union-find) -------------------------------------------------------------

class UnionFind {
  private readonly parent = new Map<string, string>();
  find(x: string): string {
    let root = x;
    for (;;) {
      const p = this.parent.get(root);
      if (p === undefined) {
        this.parent.set(root, root);
        return root;
      }
      if (p === root) break;
      root = p;
    }
    let cur = x;
    while (cur !== root) {
      const next = this.parent.get(cur) as string;
      this.parent.set(cur, root);
      cur = next;
    }
    return root;
  }
  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(ra, rb);
  }
}

const kindOfKey = (k: string): string => (k.startsWith("digest:") ? "digest" : k.startsWith("commit") ? "commit" : k.startsWith("run:") ? "run" : k.startsWith("job:") ? "job" : "other");
const shortKey = (k: string): string => (k.startsWith("digest:sha256:") ? `digest:sha256:${k.slice(14, 26)}…` : k.startsWith("commit:") ? `commit:${k.slice(7, 14)}` : k);

export interface TimelineOptions {
  readonly from?: string;
  readonly to?: string;
  readonly limit?: number;
  /** Bağ kurulamayan koşu↔yayılım yakınlık ipucu penceresi (dk). */
  readonly proximityMin?: number;
}

/** Kanıt girdilerinden çizelge kurar. Saf fonksiyon: aynı girdi → aynı çıktı. */
export function buildTimeline(entries: readonly EvidenceEntry[], opts: TimelineOptions = {}): { timeline: Timeline; sensitivity: Sensitivity } {
  const limit = Math.max(1, Math.min(opts.limit ?? 40, 100));
  const skipped: Timeline["skipped"][number][] = [];
  const raws: Raw[] = [];
  const bridges: string[][] = [];
  let sensitivity: Sensitivity = "none";
  const order: Sensitivity[] = ["none", "internal", "pii", "secret-adjacent"];
  for (const e of entries) {
    const r = fromEntry(e);
    if ("skip" in r) {
      skipped.push({ ev: e.id, reason: r.skip });
      continue;
    }
    if (order.indexOf(e.sensitivity) > order.indexOf(sensitivity)) sensitivity = e.sensitivity;
    raws.push(...r.events);
    if (r.bridge.length) bridges.push(r.bridge);
  }
  const from = opts.from ? Date.parse(opts.from) : Number.NEGATIVE_INFINITY;
  const to = opts.to ? Date.parse(opts.to) : Number.POSITIVE_INFINITY;
  const inWindow = raws.filter((r) => {
    const t = Date.parse(r.t);
    return t >= from && t <= to;
  });
  // deterministik sıra: zaman, kaynak, tür, özet, kanıt
  inWindow.sort((a, b) => Date.parse(a.t) - Date.parse(b.t) || a.source.localeCompare(b.source) || a.kind.localeCompare(b.kind) || a.summary.localeCompare(b.summary) || a.ev.localeCompare(b.ev));
  const truncated = inWindow.length > limit;
  const kept = truncated ? inWindow.slice(inWindow.length - limit) : inWindow;

  // anahtar bağları: her olay kendi anahtarlarını, her köprü kanıtı kendi anahtarlarını birleştirir
  const uf = new UnionFind();
  const allKeys = new Set<string>();
  const unionAll = (keys: readonly string[]): void => {
    for (const k of keys) allKeys.add(k);
    const [first, ...rest] = keys;
    if (first !== undefined) {
      uf.find(first);
      for (const k of rest) uf.union(first, k);
    }
  };
  for (const r of kept) unionAll(r.keys);
  for (const b of bridges) unionAll(b);
  // kısa commit etiketi (commit7:abc1234) ↔ tam SHA öneki
  const fulls = [...allKeys].filter((k) => k.startsWith("commit:"));
  for (const k of allKeys) {
    if (!k.startsWith("commit7:")) continue;
    const prefix = k.slice(8);
    for (const f of fulls) if (f.slice(7).startsWith(prefix)) uf.union(k, f);
  }
  const groups = new Map<string, { keys: Set<string>; events: number[] }>();
  kept.forEach((r, idx) => {
    for (const k of r.keys) {
      const root = uf.find(k);
      const g = groups.get(root) ?? { keys: new Set<string>(), events: [] };
      g.keys.add(k);
      if (!g.events.includes(idx)) g.events.push(idx);
      groups.set(root, g);
    }
  });
  // köprü anahtarları da kümeye ait olarak raporlanır (örn. günlükten gelen digest)
  for (const b of bridges) for (const k of b) groups.get(uf.find(k))?.keys.add(k);
  const links: TimelineLink[] = [];
  for (const g of groups.values()) {
    const sources = [...new Set(g.events.map((i) => (kept[i] as Raw).source))];
    if (sources.length < 2) continue;
    const keys = [...g.keys];
    links.push({
      via: [...new Set(keys.map(kindOfKey).filter((x) => x === "digest" || x === "commit"))].sort(),
      keys: keys.map(shortKey).sort().slice(0, 6),
      events: g.events.sort((a, b) => a - b),
      sources: sources.sort(),
    });
  }
  links.sort((a, b) => (a.events[0] ?? 0) - (b.events[0] ?? 0));

  // yakınlık ipuçları: bağ kurulmamış bir pipeline bitişi ile k8s yayılımı yakın mı?
  const proximity = (opts.proximityMin ?? 120) * 60_000;
  const linked = new Set(links.flatMap((l) => l.events));
  const hints: string[] = [];
  kept.forEach((a, i) => {
    if (a.source !== "pipeline" || !a.kind.startsWith("run_success") || linked.has(i)) return;
    kept.forEach((b, j) => {
      if (b.source !== "k8s" || b.kind !== "rollout" || b.approx || linked.has(j)) return;
      const dt = Date.parse(b.t) - Date.parse(a.t);
      if (dt >= 0 && dt <= proximity) hints.push(`${a.summary} → ${Math.round(dt / 60_000)} dk sonra ${b.summary} (anahtar bağı yok: yalnız zaman yakınlığı)`);
    });
  });

  const sources: Record<string, number> = {};
  for (const r of kept) sources[r.source] = (sources[r.source] ?? 0) + 1;
  const events: TimelineEvent[] = kept.map((r) => ({ t: r.t, source: r.source, kind: r.kind, summary: r.summary, ev: r.ev, ...(r.approx ? { approx: true } : {}) }));
  return {
    sensitivity,
    timeline: {
      window: { from: events[0]?.t ?? null, to: events.at(-1)?.t ?? null },
      events,
      links,
      hints: hints.slice(0, 5),
      sources,
      skipped: skipped.slice(0, 10),
      ...(truncated ? { truncated: true } : {}),
      note: "Olaylar yalnız tipli alanlardan üretildi (commit mesajı/başlık/günlük metni yok). `links` hesaplanmış anahtar bağlarıdır (imaj özeti, commit SHA, koşu/iş kimliği); `approx` zamanlar gözlem zamanıdır. Kanıta atıf için `ev` kullanın.",
    },
  };
}
