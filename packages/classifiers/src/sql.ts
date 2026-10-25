import { loadModule, normalizeSync, parseSync } from "libpg-query";
import type { SqlClassification } from "@ops/contracts";

/**
 * PostgreSQL SQL sınıflayıcı: GERÇEK PostgreSQL ayrıştırıcısı (libpg_query, WASM) ile AST'yi
 * yürür ve **allowlist** uygular (varsayılan ret): tek ifade; yalnız `SELECT` (CTE'ler dahil,
 * hepsi SELECT) veya ANALYZE'sız `EXPLAIN SELECT`; `INTO`, `FOR UPDATE/SHARE`, parametre,
 * bilinmeyen düğüm türü, izinli olmayan fonksiyon/operatör, sistem katalogları ve `reg*` tipine
 * dönüştürme → ret. Fonksiyon DENYLIST'i değil ALLOWLIST'idir (denylist fail-open olur).
 * Sınıflayıcı kimlik/rol yetkisinin ve salt-okunur oturumun YERİNE geçmez; onlarla birlikte katmandır.
 */
let loaded = false;

/** WASM modülünü yükler. Yüklenmeden `classifySql` her şeyi reddeder (fail-closed). */
export async function initSqlClassifier(): Promise<void> {
  await loadModule();
  loaded = true;
}

export const MAX_SQL_CHARS = 20_000;
const MAX_DEPTH = 60;
const MAX_NODES = 20_000;

export const ALLOWED_FUNCTIONS: ReadonlySet<string> = new Set([
  // toplulaştırma
  "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "bool_and", "bool_or", "every", "json_agg", "jsonb_agg",
  "json_object_agg", "jsonb_object_agg", "stddev", "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp",
  "percentile_cont", "percentile_disc", "mode", "corr",
  // pencere
  "row_number", "rank", "dense_rank", "ntile", "lag", "lead", "first_value", "last_value", "nth_value", "percent_rank", "cume_dist",
  // metin
  "lower", "upper", "length", "char_length", "character_length", "octet_length", "substr", "substring", "trim", "btrim", "ltrim",
  "rtrim", "concat", "concat_ws", "replace", "position", "strpos", "left", "right", "lpad", "rpad", "split_part", "initcap",
  "repeat", "reverse", "md5", "format", "to_char", "to_number", "to_date", "to_timestamp", "regexp_replace", "regexp_match",
  "similar_to_escape", "overlay", "translate", "ascii", "chr",
  // sayısal
  "abs", "ceil", "ceiling", "floor", "round", "trunc", "mod", "power", "sqrt", "sign", "exp", "ln", "log", "div", "random",
  // zaman
  "now", "date_trunc", "date_part", "extract", "age", "make_date", "make_timestamp", "make_interval", "clock_timestamp",
  "statement_timestamp", "timezone", "isfinite", "justify_days", "justify_hours",
  // json / dizi / küme üretimi
  "json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array", "jsonb_extract_path",
  "jsonb_extract_path_text", "json_extract_path", "json_extract_path_text", "jsonb_array_length", "json_array_length",
  "jsonb_typeof", "json_typeof", "jsonb_each", "jsonb_each_text", "json_each", "json_each_text", "jsonb_array_elements",
  "jsonb_array_elements_text", "json_array_elements", "json_array_elements_text", "jsonb_object_keys", "json_object_keys",
  "jsonb_path_query", "jsonb_path_exists", "jsonb_pretty", "array_length", "cardinality", "unnest", "array_to_string",
  "array_position", "array_positions", "array_cat", "array_append", "array_prepend", "generate_series", "generate_subscripts",
  "string_to_array", "pg_typeof",
]);

/** Yalnız tam-satır kuralıyla birlikte izinli olanlar: argümanları `wholeRowRefs`'e yazılır. */
const ROW_JSON_FUNCS = new Set(["to_json", "to_jsonb", "row_to_json"]);

/**
 * Tek bir satır (bileşik) argümanla çağrılabilen yerleşik fonksiyonlar (pg_proc: ilk parametresi record/anyelement/
 * anynonarray/"any"). PostgreSQL `t.f` öznitelik gösterimini, `t` içinde `f` sütunu yoksa `f(t)` çağrısına çevirir:
 * bu yol fonksiyon allowlist'ine uğramaz. Allowlist dışındakiler bu biçimde de reddedilir.
 */
const ROW_ARG_FUNCS = new Set([
  "to_json", "to_jsonb", "row_to_json", "json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array",
  "json_agg", "jsonb_agg", "array_agg", "concat", "quote_literal", "quote_nullable", "record_out", "record_send", "hash_record",
  "any_out", "anyelement_out", "anynonarray_out", "anycompatible_out", "anycompatiblenonarray_out", "count", "mode",
  "first_value", "last_value", "lag", "lead", "rank", "dense_rank", "percent_rank", "cume_dist", "num_nulls", "num_nonnulls",
  "pg_typeof", "pg_column_size", "pg_column_compression", "pg_collation_for",
]);

/**
 * Satırın TÜM sütun değerlerini (JSON/metin/dizi/özet olarak) döndürenler: `f(t.*)` ve `t.f` biçimleri tam-satır
 * başvurusudur. Sunucu hesaplanan sütunun kökenini bildirmediğinden köken maskelemesi bunları yakalayamaz.
 */
const WHOLE_ROW_FUNCS = new Set([
  "to_json", "to_jsonb", "row_to_json", "json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array",
  "json_agg", "jsonb_agg", "array_agg", "concat", "quote_literal", "quote_nullable", "record_out", "record_send", "hash_record",
]);

/** `renamedRelations` içinde: sütun takma adı listeli birleşim (`(a JOIN b ON …) AS j(x, y)`); hangi tablo olduğu bilinmez. */
export const RENAMED_JOIN = "(join)";

const ALLOWED_OPERATORS = new Set([
  "=", "<>", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "^", "||", "~~", "!~~", "~~*", "!~~*", "~", "~*", "!~", "!~*",
  "@>", "<@", "->", "->>", "#>", "#>>", "?", "?|", "?&", "&&", "@@", "BETWEEN", "NOT BETWEEN", "BETWEEN SYMMETRIC", "NOT BETWEEN SYMMETRIC",
]);

const ALLOWED_NODES = new Set([
  "SelectStmt", "ResTarget", "ColumnRef", "A_Const", "A_Expr", "BoolExpr", "FuncCall", "TypeCast", "TypeName", "CaseExpr", "CaseWhen",
  "NullTest", "BooleanTest", "SubLink", "RangeVar", "JoinExpr", "RangeSubselect", "RangeFunction", "SortBy", "WindowDef",
  "A_ArrayExpr", "A_Indirection", "A_Indices", "CoalesceExpr", "MinMaxExpr", "RowExpr", "SQLValueFunction", "WithClause",
  "CommonTableExpr", "Alias", "List", "String", "Integer", "Float", "Boolean", "BitString", "A_Star", "GroupingSet", "GroupingFunc",
  "CollateClause", "NamedArgExpr", "ColumnDef",
]);

const SAFE_SVF = /^SVFOP_(CURRENT_DATE|CURRENT_TIME|CURRENT_TIME_N|CURRENT_TIMESTAMP|CURRENT_TIMESTAMP_N|LOCALTIME|LOCALTIME_N|LOCALTIMESTAMP|LOCALTIMESTAMP_N)$/;
const EXPLAIN_OK = new Set(["verbose", "costs", "format", "summary"]);

class Reject extends Error {}
const rej = (m: string): never => {
  throw new Reject(m);
};

export interface SelectItem {
  readonly kind: "column" | "expression" | "star";
  readonly column?: string;
  readonly relation?: string;
}

/**
 * Sözleşmedeki `SqlClassification`'ın PostgreSQL'e özgü genişlemesi: maskeleme kuralının (`maskedViolations`)
 * ihtiyaç duyduğu, sütun başvurusu olarak görünmeyen yapılar.
 */
export interface PgSqlClassification extends SqlClassification {
  /** UNION/INTERSECT/EXCEPT: sunucu sonuç sütunlarının kökenini bildirmez (kol kol köken izlenemez). */
  readonly setOperation: boolean;
  /** NATURAL JOIN: ortak adlı tüm sütunlar, sorguda adları geçmeden birleştirme koşulu olur. */
  readonly naturalJoin: boolean;
  /** Sütun takma adı listesiyle yeniden adlandırılan ilişkiler (`t AS x(a, b)`); birleşim için {@link RENAMED_JOIN}. */
  readonly renamedRelations: readonly string[];
}

export interface SqlAnalysis {
  readonly allowed: boolean;
  readonly reason?: string;
  readonly explain: boolean;
  readonly classification: PgSqlClassification;
}

export const emptyClassification = (parsed: boolean, count = 0): PgSqlClassification => ({
  parsed,
  statementCount: count,
  statementKinds: [],
  relations: [],
  columnRefs: [],
  functions: [],
  wholeRowRefs: [],
  hasStarSelect: false,
  setOperation: false,
  naturalJoin: false,
  renamedRelations: [],
});
const empty = emptyClassification;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const isNodeWrapper = (o: Obj): string | null => {
  const keys = Object.keys(o);
  const k = keys[0];
  return keys.length === 1 && k !== undefined && /^[A-Z]/.test(k) && (isObj(o[k]) || Array.isArray(o[k])) ? k : null;
};
const strVal = (n: unknown): string | null => (isObj(n) && isObj(n["String"]) && typeof (n["String"] as Obj)["sval"] === "string" ? ((n["String"] as Obj)["sval"] as string) : null);

interface Ctx {
  nodes: number;
  relations: Set<string>;
  /** Tam satırı başvurulabilen FROM öğesi adları: ilişki adı/takma adı ve birleşim takma adları. */
  aliases: Set<string>;
  functions: Set<string>;
  columnRefs: { relation?: string; column: string; insideExpression: boolean }[];
  /** Tek parçalı sütun başvuruları (her konumda): FROM öğesi adıyla eşleşen tam-satır başvurusudur. */
  singleNameRefs: string[];
  rowJsonArgs: string[];
  hasStar: boolean;
  setOp: boolean;
  natural: boolean;
  renamed: Set<string>;
  kinds: string[];
  /** Değişiklik sınıflayıcısı (sql-change.ts) için: SELECT allowlist'ine EK düğüm türleri / fonksiyonlar / düğüm denetimi. */
  extraNodes?: ReadonlySet<string>;
  extraFunctions?: ReadonlySet<string>;
  check?: (kind: string, body: Obj, ctx: Ctx, depth: number) => void;
}

function newCtx(): Ctx {
  return { nodes: 0, relations: new Set(), aliases: new Set(), functions: new Set(), columnRefs: [], singleNameRefs: [], rowJsonArgs: [], hasStar: false, setOp: false, natural: false, renamed: new Set(), kinds: [] };
}

/** Takma adı (varsa) tam-satır başvurulabilen ad olarak kaydeder; sütun takma adı listesi varsa `true` döner. */
function noteAlias(alias: unknown, ctx: Ctx): boolean {
  const al = isObj(alias) ? ((alias as Obj)["Alias"] ?? alias) : undefined;
  if (!isObj(al)) return false;
  if (typeof al["aliasname"] === "string") ctx.aliases.add(al["aliasname"]);
  return Array.isArray(al["colnames"]) && (al["colnames"] as unknown[]).length > 0;
}

/** SELECT hedef listesindeki doğrudan sütun başvurusu mu? Üst düzey (UNION kolları dahil) SELECT'e bağlı. */
function visitSelect(body: Obj, ctx: Ctx, depth: number, top: boolean): void {
  if (body["intoClause"] !== undefined) rej("SELECT ... INTO yazma yapar");
  if (Array.isArray(body["lockingClause"]) && (body["lockingClause"] as unknown[]).length > 0) rej("FOR UPDATE/SHARE kilit alır");
  if (typeof body["op"] === "string" && body["op"] !== "SETOP_NONE") ctx.setOp = true;
  const wc = body["withClause"];
  if (isObj(wc)) {
    const w = (wc as Obj)["WithClause"] ?? wc;
    for (const cte of ((w as Obj)["ctes"] as unknown[] | undefined) ?? []) {
      const q = ((isObj(cte) ? (cte as Obj)["CommonTableExpr"] : null) as Obj | null)?.["ctequery"];
      if (!isObj(q) || !isObj(q["SelectStmt"])) rej("CTE yalnız SELECT olabilir (DML içeren CTE yazma yapar)");
    }
  }
  if (top) {
    for (const t of (body["targetList"] as unknown[] | undefined) ?? []) {
      const rt = isObj(t) ? ((t as Obj)["ResTarget"] as Obj | undefined) : undefined;
      const val = rt?.["val"];
      if (isObj(val) && isObj(val["ColumnRef"])) {
        recordColumn(((val["ColumnRef"] as Obj)["fields"] as unknown[] | undefined) ?? [], ctx, false);
        continue;
      }
      walkAny(t, ctx, depth + 1, true);
    }
  }
  for (const [k, v] of Object.entries(body)) {
    if (top && k === "targetList") continue;
    if (k === "larg" || k === "rarg") {
      // libpg-query tipli alanları (SelectStmt*) sarmalayıcısız verir; Node* alanları sarmalayıcılıdır.
      const arm = isObj(v) ? (isObj(v["SelectStmt"]) ? (v["SelectStmt"] as Obj) : "targetList" in v || "op" in v || "valuesLists" in v ? v : null) : null;
      if (arm) visitSelect(arm, ctx, depth + 1, top);
      else rej("küme işlemi kolu SELECT değil");
      continue;
    }
    walkAny(v, ctx, depth + 1, true);
  }
}

function recordColumn(fields: unknown[], ctx: Ctx, inside: boolean): void {
  const names = fields.map((f) => (isObj(f) && isObj(f["A_Star"]) ? "*" : strVal(f))).filter((x): x is string => x !== null);
  if (names.length === 0) return;
  const column = names[names.length - 1] as string;
  const relation = names.length >= 2 ? (names[names.length - 2] as string) : undefined;
  if (column === "*") ctx.hasStar = true;
  // Tek ad: o adda sütun yoksa PostgreSQL onu FROM öğesinin TAM SATIRI olarak çözer (`f(t)`, `t::text`, `ROW(t)`, `(t).x`).
  else if (names.length === 1) ctx.singleNameRefs.push(column);
  // Öznitelik gösterimi: `t.f` (veya `şema.t.f`), `t` içinde `f` sütunu yoksa `f(t)` çağrısıdır.
  else if (relation !== undefined && ROW_ARG_FUNCS.has(column.toLowerCase())) {
    const fname = column.toLowerCase();
    if (!ALLOWED_FUNCTIONS.has(fname) && !ROW_JSON_FUNCS.has(fname) && !ctx.extraFunctions?.has(fname)) rej(`izinli olmayan fonksiyon (öznitelik gösterimi): ${fname}`);
    if (WHOLE_ROW_FUNCS.has(fname)) ctx.rowJsonArgs.push(relation);
  }
  ctx.columnRefs.push({ ...(relation ? { relation } : {}), column, insideExpression: inside });
}

function visitNode(kind: string, body: unknown, ctx: Ctx, depth: number, inside: boolean): void {
  if (++ctx.nodes > MAX_NODES) rej("sorgu çok karmaşık");
  if (!ALLOWED_NODES.has(kind) && !ctx.extraNodes?.has(kind)) rej(`izinli olmayan düğüm türü: ${kind}`);
  const b = (isObj(body) ? body : {}) as Obj;
  ctx.check?.(kind, b, ctx, depth);
  switch (kind) {
    case "SelectStmt":
      visitSelect(b, ctx, depth, false);
      return;
    case "RangeVar": {
      const rel = typeof b["relname"] === "string" ? (b["relname"] as string) : "";
      const schema = typeof b["schemaname"] === "string" ? (b["schemaname"] as string) : "";
      const lowerSchema = schema.toLowerCase();
      if (lowerSchema === "pg_catalog" || lowerSchema === "information_schema" || lowerSchema.startsWith("pg_")) rej(`sistem kataloğu okunamaz: ${schema}`);
      if (rel.toLowerCase().startsWith("pg_")) rej(`sistem kataloğu okunamaz: ${rel}`);
      if (typeof b["catalogname"] === "string") rej("katalog adı belirtilemez");
      ctx.relations.add(schema ? `${schema}.${rel}` : rel);
      ctx.aliases.add(rel);
      // `t AS x(a, b, c)`: sütunlar konumla yeniden adlandırılır; maskeli sütun sorguda başka adla geçebilir.
      if (noteAlias(b["alias"], ctx)) ctx.renamed.add(rel);
      return;
    }
    case "JoinExpr":
      if (b["isNatural"] === true) ctx.natural = true;
      // `USING (a)`: `a` her iki tarafın sütunudur ve birleştirme koşulunda (ifade içinde) kullanılır.
      for (const u of (b["usingClause"] as unknown[] | undefined) ?? []) {
        const name = strVal(u);
        if (name !== null) ctx.columnRefs.push({ column: name, insideExpression: true });
      }
      // Birleşim takma adı (`(a JOIN b ON …) j`, `USING (x) AS u`) tablo sütunlarını tam satır olarak açar. Alt sorgu ve
      // fonksiyon takma adları gerekmez: alt sorgu hedefleri zaten ifade sayılır, fonksiyon çıktısı argümanlarından gelir.
      if (noteAlias(b["alias"], ctx)) ctx.renamed.add(RENAMED_JOIN);
      noteAlias(b["join_using_alias"], ctx);
      break;
    case "FuncCall": {
      const names = ((b["funcname"] as unknown[] | undefined) ?? []).map(strVal);
      if (names.length === 0 || names.some((n) => n === null)) rej("fonksiyon adı okunamadı");
      const parts = names as string[];
      if (parts.length > 2 || (parts.length === 2 && parts[0]?.toLowerCase() !== "pg_catalog")) rej(`şema nitelikli fonksiyon reddedilir: ${parts.join(".")}`);
      const fname = (parts[parts.length - 1] as string).toLowerCase();
      if (!ALLOWED_FUNCTIONS.has(fname) && !ROW_JSON_FUNCS.has(fname) && !ctx.extraFunctions?.has(fname)) rej(`izinli olmayan fonksiyon: ${fname}`);
      ctx.functions.add(fname);
      if (WHOLE_ROW_FUNCS.has(fname)) {
        // to_jsonb(t) / json_agg(t.*): tam-satır başvurusu (çıplak ad ayrıca `singleNameRefs` ile de yakalanır)
        for (const a of (b["args"] as unknown[] | undefined) ?? []) {
          const cr = isObj(a) ? ((a as Obj)["ColumnRef"] as Obj | undefined) : undefined;
          const fields = (cr?.["fields"] as unknown[] | undefined) ?? [];
          if (fields.length === 1 && strVal(fields[0]) !== null) ctx.rowJsonArgs.push(strVal(fields[0]) as string);
          if (fields.length >= 1 && isObj(fields[fields.length - 1]) && isObj((fields[fields.length - 1] as Obj)["A_Star"])) ctx.rowJsonArgs.push("*");
        }
      }
      for (const [k, v] of Object.entries(b)) if (k !== "funcname") walkAny(v, ctx, depth + 1, true);
      return;
    }
    case "A_Expr": {
      const nm = ((b["name"] as unknown[] | undefined) ?? []).map(strVal);
      if (nm.some((x) => x === null)) rej("operatör adı okunamadı");
      const parts = nm as string[];
      if (parts.length === 2 && parts[0]?.toLowerCase() !== "pg_catalog") rej("şema nitelikli operatör reddedilir");
      const op = parts[parts.length - 1] as string;
      if (!ALLOWED_OPERATORS.has(op)) rej(`izinli olmayan operatör: ${op.slice(0, 20)}`);
      break;
    }
    case "TypeCast": {
      const tn = ((((b["typeName"] as Obj | undefined)?.["names"] as unknown[]) ?? []).map(strVal).filter((x): x is string => x !== null)).join(".").toLowerCase();
      if (/(^|\.)reg[a-z]*$/.test(tn)) rej(`reg* tipine dönüştürme katalog yoklar: ${tn}`);
      break;
    }
    case "SQLValueFunction":
      if (!SAFE_SVF.test(String(b["op"] ?? ""))) rej("SQL değer fonksiyonu (kullanıcı/oturum bilgisi) reddedilir");
      return;
    case "ColumnRef":
      recordColumn((b["fields"] as unknown[] | undefined) ?? [], ctx, inside);
      return;
    default:
      break;
  }
  for (const v of Object.values(b)) walkAny(v, ctx, depth + 1, true);
}

function walkAny(v: unknown, ctx: Ctx, depth: number, inside: boolean): void {
  if (depth > MAX_DEPTH) rej("sorgu çok derin");
  if (Array.isArray(v)) {
    for (const x of v) walkAny(x, ctx, depth + 1, inside);
    return;
  }
  if (!isObj(v)) return;
  const kind = isNodeWrapper(v);
  if (kind) {
    visitNode(kind, v[kind], ctx, depth, inside);
    return;
  }
  for (const x of Object.values(v)) walkAny(x, ctx, depth + 1, inside);
}

export function classifySql(sql: string): SqlAnalysis {
  const deny = (reason: string, cls: PgSqlClassification = empty(false)): SqlAnalysis => ({ allowed: false, reason, explain: false, classification: cls });
  if (!loaded) return deny("SQL sınıflayıcı başlatılmadı (initSqlClassifier)");
  if (typeof sql !== "string" || sql.trim() === "") return deny("boş ifade");
  if (sql.length > MAX_SQL_CHARS) return deny("ifade çok uzun");
  if (sql.includes("\0")) return deny("NUL karakteri");

  let ast: { stmts?: { stmt?: Obj }[] };
  try {
    ast = parseSync(sql) as unknown as typeof ast;
  } catch {
    return deny("SQL ayrıştırılamadı");
  }
  const stmts = ast.stmts ?? [];
  if (stmts.length !== 1) return deny(`tek ifade gerekli (${stmts.length})`, empty(true, stmts.length));

  const top = stmts[0]?.stmt;
  const kind = top ? Object.keys(top)[0] : undefined;
  const ctx = newCtx();
  let explain = false;
  try {
    if (kind === "SelectStmt") {
      ctx.kinds.push("SelectStmt");
      visitSelect((top as Obj)["SelectStmt"] as Obj, ctx, 0, true);
    } else if (kind === "ExplainStmt") {
      explain = true;
      const ex = (top as Obj)["ExplainStmt"] as Obj;
      ctx.kinds.push("ExplainStmt");
      for (const o of (ex["options"] as unknown[] | undefined) ?? []) {
        const name = String(((isObj(o) ? (o as Obj)["DefElem"] : undefined) as Obj | undefined)?.["defname"] ?? "").toLowerCase();
        if (!EXPLAIN_OK.has(name)) rej(`EXPLAIN seçeneği izinli değil: ${name || "?"} (ANALYZE sorguyu ÇALIŞTIRIR)`);
      }
      const q = ex["query"] as Obj | undefined;
      if (!q || !isObj(q["SelectStmt"])) rej("EXPLAIN yalnız SELECT için");
      ctx.kinds.push("SelectStmt");
      visitSelect((q as Obj)["SelectStmt"] as Obj, ctx, 0, true);
    } else {
      rej(`ifade türü izinli değil: ${kind ?? "?"}`);
    }
  } catch (e) {
    if (e instanceof Reject) return deny(e.message, { ...empty(true, 1), statementKinds: kind ? [kind] : [] });
    throw e;
  }

  const classification: PgSqlClassification = {
    parsed: true,
    statementCount: 1,
    statementKinds: ctx.kinds,
    relations: [...ctx.relations],
    columnRefs: ctx.columnRefs,
    functions: [...ctx.functions],
    wholeRowRefs: wholeRowOf(ctx),
    hasStarSelect: ctx.hasStar,
    setOperation: ctx.setOp,
    naturalJoin: ctx.natural,
    renamedRelations: [...ctx.renamed],
  };
  return { allowed: true, explain, classification };
}

/**
 * Tam-satır başvuruları: satır fonksiyonu argümanları (`to_jsonb(t)`, `t.to_jsonb`, `f(t.*)` → `*`) ve FROM öğesi
 * adıyla eşleşen HER tek parçalı başvuru (`json_agg(t)`, `t::text`, `ROW(t)`, `coalesce(t, t)`, `(t).sütun`).
 * Sözdizimseldir: FROM öğesiyle aynı adı taşıyan sütun da (PostgreSQL önce sütunu seçer) muhafazakârca sayılır.
 */
function wholeRowOf(ctx: Ctx): string[] {
  return [...new Set([...ctx.rowJsonArgs, ...ctx.singleNameRefs.filter((n) => ctx.aliases.has(n))])];
}

/**
 * M4 AST kuralı: maskeli sütunlar yalnız DOĞRUDAN seçim öğesi olabilir. İfade/fonksiyon/WHERE/JOIN (ON ve
 * USING) içinde kullanım, `SELECT *`, tam-satır başvurusu → ihlal listesi (boş = uygun). Sütun adı
 * eşleşmesi nitelik çözümlemesi yapmadan (muhafazakâr) tüm sorgudaki başvurulara bakar. Maskeli tabloya
 * dokunan sorguda ayrıca reddedilir: küme işlemleri (sunucu sonuç sütunu kökenini bildirmez, doğrudan seçim
 * bile maskelenemez), NATURAL JOIN (birleştirme sütunları görünmez) ve sütun takma adı listesiyle yeniden
 * adlandırma (maskeli sütun başka adla ifadeye girebilir).
 */
export function maskedViolations(a: SqlAnalysis, masked: ReadonlyMap<string, ReadonlySet<string>>): string[] {
  const out: string[] = [];
  const cls = a.classification;
  const base = (r: string): string => (r.split(".").pop() as string).toLowerCase();
  const touched = cls.relations.map(base).filter((r) => masked.has(r));
  if (touched.length === 0) return out;
  if (cls.hasStarSelect) out.push(`maskeli tabloda SELECT *: ${touched.join(",")}`);
  if (cls.wholeRowRefs.length > 0) out.push(`tam-satır başvurusu maskeli tabloda: ${cls.wholeRowRefs.join(",")}`);
  if (cls.setOperation) out.push(`küme işlemi (UNION/INTERSECT/EXCEPT) maskeli tabloyla: sonuç sütunlarının kökeni bilinmez`);
  if (cls.naturalJoin) out.push(`NATURAL JOIN maskeli tabloyla: birleştirme sütunları açıkça yazılmalı (ON)`);
  for (const r of cls.renamedRelations) {
    if (r === RENAMED_JOIN || masked.has(base(r))) out.push(`maskeli tabloda sütun takma adı listesi: ${r}`);
  }
  const cols = new Set(touched.flatMap((t) => [...(masked.get(t) ?? [])].map((c) => c.toLowerCase())));
  for (const c of cls.columnRefs) {
    if (cols.has(c.column.toLowerCase()) && c.insideExpression) out.push(`maskeli sütun ifade/koşul içinde: ${c.column}`);
  }
  return [...new Set(out)];
}

/**
 * Görüntüleme için sorgu metnini NORMALLEŞTİRİR: değişmezler (`'a@b.com'`, `42`) `$n` olur, böylece
 * `pg_stat_activity.query` gibi kaynaklardan gelen metin literal (PII/secret) taşımaz. Ayrıştırılamayan
 * veya çok uzun metin için `null` döner (hiç göstermemek, ham göstermekten iyidir).
 */
export function normalizeSqlForDisplay(sql: string, max = 160): string | null {
  if (!loaded || typeof sql !== "string" || sql.length === 0 || sql.length > MAX_SQL_CHARS || sql.includes("\0")) return null;
  try {
    const n = normalizeSync(sql).replace(/\s+/g, " ").trim();
    return n.length > max ? `${n.slice(0, max)}…` : n;
  } catch {
    return null;
  }
}


/**
 * `sql-change.ts` ile paylaşılan yürüyüş yardımcıları (paket içi; `index.ts` dışa aktarmaz). Değişiklik
 * sınıflayıcısı SELECT allowlist'inin aynı ifade/alt sorgu denetimini yeniden kullanır; EK düğüm türleri
 * yalnız kendi `Ctx`'inde açılır, SELECT sınıflayıcısını genişletmez.
 */
export const walkKit = {
  Reject,
  rej,
  isObj,
  strVal,
  ready: (): boolean => loaded,
  newCtx,
  wholeRowOf,
  walkAny,
  visitNode,
};
export type WalkCtx = Ctx;
export type WalkObj = Obj;
