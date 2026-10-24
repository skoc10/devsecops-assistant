import { estimateTokens } from "@ops/contracts";

/**
 * Kompaktlaştırma (token ekonomisi, tasarım §4.5-5). Redaksiyondan SONRA, redakte veri üzerinde
 * çalışır: modele giden görünüm tam (redakte) kanıtın türevidir, ham verinin değil.
 */

type Plain = Record<string, unknown>;
const isPlain = (v: unknown): v is Plain => v !== null && typeof v === "object" && !Array.isArray(v);

// ---- alan projeksiyonu -----------------------------------------------------------------------

export interface FieldTrie {
  [key: string]: true | FieldTrie;
}

export function buildTrie(paths: readonly string[]): FieldTrie {
  const root: FieldTrie = {};
  for (const path of paths) {
    const segs = path.split(".").filter((s) => s.length > 0);
    let node = root;
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i] as string;
      const existing = node[seg];
      if (existing === true) break; // üst yol zaten tümüyle seçili
      if (i === segs.length - 1) {
        node[seg] = true;
        break;
      }
      const next: FieldTrie = existing ?? {};
      node[seg] = next;
      node = next;
    }
  }
  return root;
}

function project(value: unknown, trie: FieldTrie): unknown {
  if (Array.isArray(value)) return value.map((v) => project(v, trie));
  if (!isPlain(value)) return value;
  const out: Plain = {};
  for (const [key, sub] of Object.entries(trie)) {
    if (!(key in value)) continue;
    out[key] = sub === true ? value[key] : project(value[key], sub);
  }
  return out;
}

/** Nokta yollu alan listesine göre değeri daraltır (diziler öğe öğe). */
export function projectFields(value: unknown, fields: readonly string[]): unknown {
  return project(value, buildTrie(fields));
}

// ---- boşları atma ----------------------------------------------------------------------------

export function dropEmpty(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(dropEmpty);
  if (!isPlain(value)) return value;
  const out: Plain = {};
  for (const [k, v] of Object.entries(value)) {
    const d = dropEmpty(v);
    if (d === null || d === undefined || d === "") continue;
    if (Array.isArray(d) && d.length === 0) continue;
    if (isPlain(d) && Object.keys(d).length === 0) continue;
    out[k] = d;
  }
  return out;
}

// ---- tablo biçimi ----------------------------------------------------------------------------

export interface TableView {
  columns: string[];
  rows: unknown[][];
  _total?: number;
  _shown?: number;
}

const MAX_TABLE_COLUMNS = 24;

/** Aynı biçimli nesne dizilerini sütunlu tabloya çevirir (anahtar tekrarını ortadan kaldırır). */
export function tabulateDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    const items = value.map(tabulateDeep);
    if (items.length >= 2 && items.every(isPlain)) {
      const cols: string[] = [];
      for (const it of items as Plain[]) for (const k of Object.keys(it)) if (!cols.includes(k)) cols.push(k);
      if (cols.length > 0 && cols.length <= MAX_TABLE_COLUMNS) {
        const table: TableView = { columns: cols, rows: (items as Plain[]).map((it) => cols.map((c) => it[c] ?? null)) };
        return table;
      }
    }
    return items;
  }
  if (isPlain(value)) {
    const out: Plain = {};
    for (const [k, v] of Object.entries(value)) out[k] = tabulateDeep(v);
    return out;
  }
  return value;
}

// ---- liste sınırlama -------------------------------------------------------------------------

export interface ListWrapper {
  _total: number;
  _shown: number;
  items: unknown[];
}

const isWrapper = (v: unknown): v is ListWrapper =>
  isPlain(v) && typeof v["_total"] === "number" && typeof v["_shown"] === "number" && Array.isArray(v["items"]);

export function clampListsDeep(value: unknown, maxItems: number): unknown {
  if (Array.isArray(value)) {
    const items = value.map((v) => clampListsDeep(v, maxItems));
    if (items.length > maxItems) return { _total: items.length, _shown: maxItems, items: items.slice(0, maxItems) } satisfies ListWrapper;
    return items;
  }
  if (isPlain(value)) {
    const out: Plain = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "rows" && Array.isArray(v) && v.length > maxItems && Array.isArray(value["columns"])) {
        out[k] = v.slice(0, maxItems);
        out["_total"] = v.length;
        out["_shown"] = maxItems;
      } else {
        out[k] = clampListsDeep(v, maxItems);
      }
    }
    return out;
  }
  return value;
}

// ---- log kümeleme ----------------------------------------------------------------------------

export interface LogCluster {
  n: number;
  severity: "error" | "warn" | "info";
  pattern: string;
  sample: string;
  firstLine: number;
  lastLine: number;
}

export interface LogView {
  kind: "log";
  lines: number;
  clusters: LogCluster[];
  head: string[];
  tail: string[];
}

const TS_PREFIX = /^\s*(?:\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*/;

export function normalizeLogLine(line: string): string {
  return line
    .replace(TS_PREFIX, "")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, "<ip>")
    .replace(/\b[0-9a-f]{12,}\b/gi, "<hex>")
    .replace(/\b\d+(?:\.\d+)?\b/g, "<n>")
    .slice(0, 160);
}

function severityOf(line: string): LogCluster["severity"] {
  if (/\b(?:error|err|fatal|panic|exception|crit(?:ical)?|fail(?:ed|ure)?|oomkill\w*|denied|refused|timeout)\b/i.test(line)) return "error";
  if (/\bwarn(?:ing)?\b/i.test(line)) return "warn";
  return "info";
}

const SEV_ORDER = { error: 0, warn: 1, info: 2 } as const;

export function clusterLogLines(
  text: string,
  opts: { maxClusters?: number; head?: number; tail?: number; maxLineChars?: number } = {},
): LogView {
  const maxClusters = opts.maxClusters ?? 15;
  const maxChars = opts.maxLineChars ?? 200;
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const clusters = new Map<string, LogCluster>();
  lines.forEach((line, i) => {
    const pattern = normalizeLogLine(line);
    const c = clusters.get(pattern);
    if (c) {
      c.n += 1;
      c.lastLine = i;
    } else {
      clusters.set(pattern, {
        n: 1,
        severity: severityOf(line),
        pattern,
        sample: line.slice(0, maxChars),
        firstLine: i,
        lastLine: i,
      });
    }
  });
  const ranked = [...clusters.values()]
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.n - a.n || a.firstLine - b.firstLine)
    .slice(0, maxClusters);
  const cut = (l: string): string => (l.length > maxChars ? `${l.slice(0, maxChars)}…` : l);
  return {
    kind: "log",
    lines: lines.length,
    clusters: ranked,
    head: lines.slice(0, opts.head ?? 3).map(cut),
    tail: lines.slice(Math.max(0, lines.length - (opts.tail ?? 8))).map(cut),
  };
}

// ---- token tavanına sığdırma -----------------------------------------------------------------

export interface Compacted {
  /** `byReference` ise yoktur. */
  view?: unknown;
  text: string;
  tokens: number;
  byReference: boolean;
  truncated: boolean;
}

function shrinkString(s: string): string | null {
  if (s.length <= 240) return null;
  return `${s.slice(0, 160)}…[+${s.length - 220} karakter]…${s.slice(-60)}`;
}

function shrinkOnce(value: unknown, state: { changed: boolean }): unknown {
  if (typeof value === "string") {
    const s = shrinkString(value);
    if (s !== null) {
      state.changed = true;
      return s;
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 3) {
      const keep = Math.ceil(value.length / 2);
      state.changed = true;
      return { _total: value.length, _shown: keep, items: value.slice(0, keep).map((v) => shrinkOnce(v, state)) } satisfies ListWrapper;
    }
    return value.map((v) => shrinkOnce(v, state));
  }
  if (isWrapper(value)) {
    if (value.items.length > 3) {
      const keep = Math.ceil(value.items.length / 2);
      state.changed = true;
      return { _total: value._total, _shown: keep, items: value.items.slice(0, keep).map((v) => shrinkOnce(v, state)) };
    }
    return { ...value, items: value.items.map((v) => shrinkOnce(v, state)) };
  }
  if (isPlain(value)) {
    if (Array.isArray(value["columns"]) && Array.isArray(value["rows"]) && (value["rows"] as unknown[]).length > 3) {
      const rows = value["rows"] as unknown[];
      const keep = Math.ceil(rows.length / 2);
      state.changed = true;
      return { ...value, rows: rows.slice(0, keep), _total: (value["_total"] as number | undefined) ?? rows.length, _shown: keep };
    }
    const out: Plain = {};
    for (const [k, v] of Object.entries(value)) out[k] = shrinkOnce(v, state);
    return out;
  }
  return value;
}

function render(view: unknown): { text: string; tokens: number } {
  const text = JSON.stringify(view) ?? "null";
  return { text, tokens: estimateTokens(text) };
}

/** Görünümü token tavanına sığdırır; sığmazsa `byReference` (ham görünüm yok, `evidence.get` ile dilimlenir). */
export function fitToTokens(view: unknown, maxTokens: number): Compacted {
  let cur = view;
  let truncated = false;
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = render(cur);
    if (r.tokens <= maxTokens) return { view: cur, text: r.text, tokens: r.tokens, byReference: false, truncated };
    const state = { changed: false };
    cur = shrinkOnce(cur, state);
    if (!state.changed) break;
    truncated = true;
  }
  const r = render(cur);
  if (r.tokens <= maxTokens) return { view: cur, text: r.text, tokens: r.tokens, byReference: false, truncated: true };
  return { text: "", tokens: 0, byReference: true, truncated: true };
}

// ---- giriş noktası ---------------------------------------------------------------------------

export interface CompactOptions {
  readonly projection?: { readonly defaultFields: readonly string[]; readonly selectable: boolean };
  /** Model isteği ile genişletilmiş alan kümesi (yalnız `selectable` ise uygulanır). */
  readonly select?: readonly string[];
  readonly maxTokens: number;
  readonly maxItems: number;
  readonly logLike?: boolean;
}

export function compactForModel(data: unknown, opts: CompactOptions): Compacted {
  let view: unknown;
  if (typeof data === "string" && (opts.logLike === true || data.split("\n").length > 8)) {
    view = clusterLogLines(data);
  } else {
    const fields =
      opts.select && opts.select.length > 0 && opts.projection?.selectable ? opts.select : opts.projection?.defaultFields;
    let v: unknown = data;
    if (fields && fields.length > 0) v = projectFields(v, fields);
    v = dropEmpty(v);
    v = tabulateDeep(v);
    view = clampListsDeep(v, opts.maxItems);
  }
  return fitToTokens(view, opts.maxTokens);
}
