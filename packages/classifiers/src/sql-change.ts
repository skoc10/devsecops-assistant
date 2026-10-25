import { createHash } from "node:crypto";
import { parseSync } from "libpg-query";
import { riskRank } from "@ops/contracts";
import type { RiskClass, SqlClassification } from "@ops/contracts";
import { MAX_SQL_CHARS, walkKit } from "./sql.ts";
import type { WalkCtx, WalkObj } from "./sql.ts";

/**
 * PostgreSQL DEĞİŞİKLİK sınıflayıcısı (`db.change.*`): gerçek ayrıştırıcıyla her ifadeyi AST allowlist'ten
 * geçirir. İzinli ifadeler: INSERT (VALUES/SELECT), UPDATE, DELETE, CREATE TABLE, CREATE INDEX, CREATE VIEW,
 * ALTER TABLE (kapalı alt komut listesi), DROP TABLE/VIEW (RESTRICT), TRUNCATE (RESTRICT). Reddedilenler:
 * RETURNING, ON CONFLICT, WITH (DML), CASCADE, CONCURRENTLY, geçici/unlogged tablo, sistem katalogları,
 * izinli olmayan fonksiyon/operatör (SELECT sınıflayıcısıyla AYNI liste), tırnaklı/büyük harfli ilişki adı,
 * COPY/DO/CALL/SET/GRANT/CREATE FUNCTION/EXTENSION vb. (bilinmeyen = ret). Çoklu ifade serbesttir (en çok
 * {@link MAX_CHANGE_STATEMENTS}); her ifade metni ayrı ayrı yeniden ayrıştırılır ve tek ifade olduğu doğrulanır.
 * Sınıflayıcı rol yetkisinin yerine geçmez; onunla birlikte katmandır.
 */

export const MAX_CHANGE_STATEMENTS = 20;
const IDENT = /^[a-z_][a-z0-9_$]{0,62}$/;

const { Reject, rej, isObj, strVal } = walkKit;

export type ChangeKind = "insert" | "update" | "delete" | "create_table" | "create_index" | "create_view" | "alter_table" | "drop" | "truncate";
export type LockMode = "ACCESS SHARE" | "ROW EXCLUSIVE" | "SHARE" | "ACCESS EXCLUSIVE";

export interface ChangeRelation {
  readonly schema?: string;
  readonly name: string;
}

export interface ChangeStatement {
  readonly index: number;
  readonly kind: ChangeKind;
  readonly risk: RiskClass;
  /** Tek ifadenin birebir metni (noktalı virgülsüz); sunucuya aynen gönderilen budur. */
  readonly text: string;
  /** Yazılan / şeması değişen ilişkiler. */
  readonly targets: readonly ChangeRelation[];
  /** Hedeflerin istenen kilit kipi. */
  readonly lockMode: LockMode;
  /** Yalnız okunan ilişkiler (alt sorgu, USING, FROM, FK hedefi...). */
  readonly reads: readonly ChangeRelation[];
  /** WHERE'siz UPDATE/DELETE. */
  readonly unbounded: boolean;
  /** CREATE TABLE/VIEW: hedefin bu ifadeyle yaratıldığı (önceden var olması gerekmez). */
  readonly creates: boolean;
}

export interface ChangeAnalysis {
  readonly allowed: boolean;
  readonly reason?: string;
  readonly statements: readonly ChangeStatement[];
  /** En yüksek ifade sınıfı. */
  readonly risk: RiskClass;
  /** İfade metinlerinin sha256'sı (onaylanan ifade seti). */
  readonly digest: string;
  readonly classification: SqlClassification;
}

const LOCK_ORDER: readonly LockMode[] = ["ACCESS SHARE", "ROW EXCLUSIVE", "SHARE", "ACCESS EXCLUSIVE"];
export const strongerLock = (a: LockMode, b: LockMode): LockMode => (LOCK_ORDER.indexOf(a) >= LOCK_ORDER.indexOf(b) ? a : b);

const EXTRA_NODES: ReadonlySet<string> = new Set(["SetToDefault", "MultiAssignRef", "Constraint", "IndexElem"]);
const EXTRA_FUNCTIONS: ReadonlySet<string> = new Set(["gen_random_uuid"]);
const ALLOWED_CONSTRAINTS = new Set(["CONSTR_NULL", "CONSTR_NOTNULL", "CONSTR_DEFAULT", "CONSTR_IDENTITY", "CONSTR_CHECK", "CONSTR_PRIMARY", "CONSTR_UNIQUE", "CONSTR_FOREIGN"]);
const INDEX_METHODS = new Set(["btree", "hash", "gin", "gist", "brin", "spgist"]);
const ALTER_RISK: Readonly<Record<string, RiskClass>> = {
  AT_AddColumn: "deploy",
  AT_ColumnDefault: "deploy",
  AT_DropNotNull: "deploy",
  AT_SetNotNull: "deploy",
  AT_AddConstraint: "deploy",
  AT_DropColumn: "destroy",
  AT_DropConstraint: "destroy",
  AT_AlterColumnType: "destroy",
};

const empty = (n = 0): SqlClassification => ({ parsed: n > 0, statementCount: n, statementKinds: [], relations: [], columnRefs: [], functions: [], wholeRowRefs: [], hasStarSelect: false });
const deny = (reason: string, n = 0): ChangeAnalysis => ({ allowed: false, reason, statements: [], risk: "destroy", digest: "", classification: empty(n) });

/** Değişiklik ifadesinde bulunmaması gereken (boş olmayan) alanlar. */
function forbid(b: WalkObj, keys: readonly string[], what: string): void {
  for (const k of keys) {
    const v = b[k];
    if (v === undefined || v === false || v === null) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    rej(`${what}: '${k}' desteklenmez`);
  }
}

function checkIdent(name: unknown, what: string): string {
  if (typeof name !== "string" || !IDENT.test(name)) rej(`${what} adı yalnız küçük harf, rakam, _ ve $ içerebilir (tırnaklı/büyük harfli ad desteklenmez)`);
  return name as string;
}

const SYSTEM_SCHEMA = (s: string): boolean => s === "information_schema" || s.startsWith("pg_");

function relationOf(schema: string | undefined, name: string): ChangeRelation {
  return schema !== undefined ? { schema, name } : { name };
}

const keyOf = (r: ChangeRelation): string => (r.schema ? `${r.schema}.${r.name}` : r.name);

/** Yazılan RangeVar: sistem şeması/katalog reddi (visitNode) + katı ad denetimi. */
function writeTarget(v: unknown, ctx: WalkCtx, depth: number, what: string): ChangeRelation {
  if (!isObj(v)) rej(`${what}: ilişki yok`);
  const rv = v as WalkObj;
  walkKit.visitNode("RangeVar", rv, ctx, depth, false);
  const name = checkIdent(rv["relname"], "ilişki");
  const schema = rv["schemaname"] === undefined ? undefined : checkIdent(rv["schemaname"], "şema");
  if (rv["relpersistence"] !== undefined && rv["relpersistence"] !== "p") rej("geçici/unlogged tablo desteklenmez");
  return relationOf(schema, name);
}

/** DROP için `List` içindeki ad parçalarını (şema?, ad) çözer. */
function dropTarget(obj: unknown): ChangeRelation {
  const items = isObj(obj) && isObj(obj["List"]) ? ((obj["List"] as WalkObj)["items"] as unknown[] | undefined) : undefined;
  const parts = (items ?? []).map(strVal);
  if (parts.length === 0 || parts.length > 2 || parts.some((p) => p === null)) rej("DROP hedef adı okunamadı (katalog nitelikli ad desteklenmez)");
  const name = checkIdent(parts[parts.length - 1], "ilişki");
  const schema = parts.length === 2 ? checkIdent(parts[0], "şema") : undefined;
  if ((schema !== undefined && SYSTEM_SCHEMA(schema)) || name.startsWith("pg_")) rej("sistem kataloğu değiştirilemez");
  return relationOf(schema, name);
}

/** SELECT allowlist'ine ek düğüm denetimleri (tür adları, kısıtlar, dizin öğeleri). */
function check(kind: string, b: WalkObj, ctx: WalkCtx, depth: number): void {
  switch (kind) {
    case "TypeName": {
      const names = ((b["names"] as unknown[] | undefined) ?? []).map(strVal);
      if (names.length === 0 || names.some((n) => n === null)) rej("tür adı okunamadı");
      const parts = names as string[];
      const last = (parts[parts.length - 1] as string).toLowerCase();
      if (/^reg[a-z0-9]*$/.test(last)) rej(`reg* türü reddedilir: ${last}`);
      if (parts.length > 2 || (parts.length === 2 && parts[0]?.toLowerCase() !== "pg_catalog")) {
        // kullanıcı tanımlı şema nitelikli tür: şema/ad katı biçimde olmalı
        if (parts.length > 2) rej("katalog nitelikli tür adı reddedilir");
        checkIdent(parts[0], "tür şeması");
        checkIdent(parts[1], "tür");
      }
      if (b["setof"] === true) rej("SETOF türü reddedilir");
      return;
    }
    case "ColumnDef": {
      // typeName tipli alandır (sarmalayıcısız): gezginin göremeyeceği için açıkça denetlenir
      if (!isObj(b["typeName"])) rej("sütun türü okunamadı");
      walkKit.visitNode("TypeName", b["typeName"], ctx, depth + 1, false);
      forbid(b, ["storage", "compression", "fdwoptions"], "sütun");
      return;
    }
    case "Constraint": {
      const ct = String(b["contype"] ?? "");
      if (!ALLOWED_CONSTRAINTS.has(ct)) rej(`kısıt türü izinli değil: ${ct || "?"}`);
      forbid(b, ["options", "indexname", "indexspace", "access_method", "including", "exclusions", "where_clause"], "kısıt");
      if (isObj(b["pktable"])) {
        walkKit.visitNode("RangeVar", b["pktable"], ctx, depth + 1, false);
        checkIdent((b["pktable"] as WalkObj)["relname"], "FK hedef tablosu");
        if ((b["pktable"] as WalkObj)["schemaname"] !== undefined) checkIdent((b["pktable"] as WalkObj)["schemaname"], "FK hedef şeması");
      }
      return;
    }
    default:
      return;
  }
}

function newCtx(): WalkCtx {
  const c = walkKit.newCtx();
  c.extraNodes = EXTRA_NODES;
  c.extraFunctions = EXTRA_FUNCTIONS;
  c.check = check;
  return c;
}

interface Built {
  kind: ChangeKind;
  risk: RiskClass;
  targets: ChangeRelation[];
  lockMode: LockMode;
  unbounded: boolean;
  creates: boolean;
}

function build(top: WalkObj, ctx: WalkCtx): Built {
  const key = Object.keys(top)[0];
  const b = (key ? top[key] : undefined) as WalkObj;
  if (!key || !isObj(b)) return rej("ifade okunamadı");
  const walk = (v: unknown): void => {
    if (v !== undefined) walkKit.walkAny(v, ctx, 1, true);
  };
  switch (key) {
    case "InsertStmt": {
      forbid(b, ["onConflictClause", "returningClause", "returningList", "withClause"], "INSERT");
      if (b["override"] !== undefined && b["override"] !== "OVERRIDING_NOT_SET") rej("INSERT: OVERRIDING desteklenmez");
      const t = writeTarget(b["relation"], ctx, 1, "INSERT");
      walk(b["cols"]);
      walk(b["selectStmt"]);
      return { kind: "insert", risk: "mutate", targets: [t], lockMode: "ROW EXCLUSIVE", unbounded: false, creates: false };
    }
    case "UpdateStmt": {
      forbid(b, ["returningClause", "returningList", "withClause"], "UPDATE");
      const t = writeTarget(b["relation"], ctx, 1, "UPDATE");
      walk(b["targetList"]);
      walk(b["fromClause"]);
      walk(b["whereClause"]);
      const unbounded = b["whereClause"] === undefined;
      return { kind: "update", risk: unbounded ? "deploy" : "mutate", targets: [t], lockMode: "ROW EXCLUSIVE", unbounded, creates: false };
    }
    case "DeleteStmt": {
      forbid(b, ["returningClause", "returningList", "withClause"], "DELETE");
      const t = writeTarget(b["relation"], ctx, 1, "DELETE");
      walk(b["usingClause"]);
      walk(b["whereClause"]);
      const unbounded = b["whereClause"] === undefined;
      return { kind: "delete", risk: unbounded ? "destroy" : "mutate", targets: [t], lockMode: "ROW EXCLUSIVE", unbounded, creates: false };
    }
    case "CreateStmt": {
      forbid(b, ["inhRelations", "partbound", "partspec", "ofTypename", "options", "tablespacename", "accessMethod"], "CREATE TABLE");
      if (b["oncommit"] !== undefined && b["oncommit"] !== "ONCOMMIT_NOOP") rej("CREATE TABLE: ON COMMIT desteklenmez");
      const t = writeTarget(b["relation"], ctx, 1, "CREATE TABLE");
      walk(b["tableElts"]);
      return { kind: "create_table", risk: "deploy", targets: [t], lockMode: "ACCESS EXCLUSIVE", unbounded: false, creates: true };
    }
    case "IndexStmt": {
      forbid(b, ["options", "tableSpace", "excludeOpNames", "concurrent", "isconstraint"], "CREATE INDEX");
      const am = String(b["accessMethod"] ?? "btree").toLowerCase();
      if (!INDEX_METHODS.has(am)) rej(`CREATE INDEX: erişim yöntemi izinli değil: ${am}`);
      const t = writeTarget(b["relation"], ctx, 1, "CREATE INDEX");
      walk(b["indexParams"]);
      walk(b["indexIncludingParams"]);
      walk(b["whereClause"]);
      return { kind: "create_index", risk: "deploy", targets: [t], lockMode: "SHARE", unbounded: false, creates: false };
    }
    case "ViewStmt": {
      forbid(b, ["options"], "CREATE VIEW");
      if (b["withCheckOption"] !== undefined && b["withCheckOption"] !== "NO_CHECK_OPTION") rej("CREATE VIEW: WITH CHECK OPTION desteklenmez");
      const t = writeTarget(b["view"], ctx, 1, "CREATE VIEW");
      if (!isObj(b["query"])) rej("CREATE VIEW: sorgu yok");
      walk(b["query"]);
      return { kind: "create_view", risk: "deploy", targets: [t], lockMode: "ACCESS EXCLUSIVE", unbounded: false, creates: b["replace"] !== true };
    }
    case "AlterTableStmt": {
      if (b["objtype"] !== "OBJECT_TABLE") rej("ALTER yalnız tablolar için (OBJECT_TABLE)");
      forbid(b, ["missing_ok"], "ALTER TABLE");
      const t = writeTarget(b["relation"], ctx, 1, "ALTER TABLE");
      const cmds = (b["cmds"] as unknown[] | undefined) ?? [];
      if (cmds.length === 0) rej("ALTER TABLE: alt komut yok");
      let risk: RiskClass = "deploy";
      for (const c of cmds) {
        const cmd = isObj(c) ? (c["AlterTableCmd"] as WalkObj | undefined) : undefined;
        if (!cmd) rej("ALTER TABLE: alt komut okunamadı");
        const sub = String((cmd as WalkObj)["subtype"] ?? "");
        const r = ALTER_RISK[sub];
        if (!r) rej(`ALTER TABLE alt komutu izinli değil: ${sub || "?"}`);
        const beh = (cmd as WalkObj)["behavior"];
        if (beh !== undefined && beh !== "DROP_RESTRICT") rej("ALTER TABLE: CASCADE desteklenmez");
        if (riskRank(r as RiskClass) > riskRank(risk)) risk = r as RiskClass;
        walk((cmd as WalkObj)["def"]);
      }
      return { kind: "alter_table", risk, targets: [t], lockMode: "ACCESS EXCLUSIVE", unbounded: false, creates: false };
    }
    case "DropStmt": {
      if (b["removeType"] !== "OBJECT_TABLE" && b["removeType"] !== "OBJECT_VIEW") rej("DROP yalnız TABLE/VIEW için");
      if (b["behavior"] !== undefined && b["behavior"] !== "DROP_RESTRICT") rej("DROP: CASCADE desteklenmez");
      forbid(b, ["concurrent"], "DROP");
      const objs = (b["objects"] as unknown[] | undefined) ?? [];
      if (objs.length === 0) rej("DROP: hedef yok");
      return { kind: "drop", risk: "destroy", targets: objs.map(dropTarget), lockMode: "ACCESS EXCLUSIVE", unbounded: false, creates: false };
    }
    case "TruncateStmt": {
      if (b["behavior"] !== undefined && b["behavior"] !== "DROP_RESTRICT") rej("TRUNCATE: CASCADE desteklenmez");
      const rels = (b["relations"] as unknown[] | undefined) ?? [];
      if (rels.length === 0) rej("TRUNCATE: hedef yok");
      const targets = rels.map((r) => writeTarget(isObj(r) ? r["RangeVar"] : undefined, ctx, 1, "TRUNCATE"));
      return { kind: "truncate", risk: "destroy", targets, lockMode: "ACCESS EXCLUSIVE", unbounded: false, creates: false };
    }
    default:
      return rej(`ifade türü izinli değil: ${key}`);
  }
}

/** Tek ifade metnini ayrıştırır; tam olarak 1 ifade ve beklenen düğüm türü olmalıdır. */
function parseOne(text: string): WalkObj {
  const ast = parseSync(text) as unknown as { stmts?: { stmt?: WalkObj }[] };
  const stmts = ast.stmts ?? [];
  if (stmts.length !== 1 || !isObj(stmts[0]?.stmt)) return rej("ifade bölünemedi (tek ifade değil)");
  return stmts[0]?.stmt as WalkObj;
}

/**
 * Çok ifadeli SQL'i tek tek ifade metinlerine böler (bayt ofsetleriyle) ve her parçayı yeniden ayrıştırıp
 * doğrular. Sunucuya GİDEN metin ile analiz edilen metin aynıdır.
 */
export function splitChangeStatements(sql: string): { text: string; node: WalkObj }[] {
  const ast = parseSync(sql) as unknown as { stmts?: { stmt?: WalkObj; stmt_location?: number; stmt_len?: number }[] };
  const stmts = ast.stmts ?? [];
  const bytes = Buffer.from(sql, "utf8");
  const out: { text: string; node: WalkObj }[] = [];
  for (const s of stmts) {
    const loc = s.stmt_location ?? 0;
    const len = s.stmt_len && s.stmt_len > 0 ? s.stmt_len : bytes.length - loc;
    const text = bytes.subarray(loc, loc + len).toString("utf8").trim().replace(/[;\s]+$/u, "").trim();
    if (text === "") return rej("boş ifade");
    const node = parseOne(text);
    const want = s.stmt ? Object.keys(s.stmt)[0] : undefined;
    if (!want || !(want in node)) rej("ifade bölme tutarsız");
    out.push({ text, node });
  }
  return out;
}

export function classifySqlChange(sql: string): ChangeAnalysis {
  if (!walkKit.ready()) return deny("SQL sınıflayıcı başlatılmadı (initSqlClassifier)");
  if (typeof sql !== "string" || sql.trim() === "") return deny("boş ifade");
  if (sql.length > MAX_SQL_CHARS) return deny("ifade çok uzun");
  if (sql.includes("\0")) return deny("NUL karakteri");

  const statements: ChangeStatement[] = [];
  const kinds: string[] = [];
  const allRelations = new Set<string>();
  const columnRefs: SqlClassification["columnRefs"][number][] = [];
  const functions = new Set<string>();
  const wholeRow = new Set<string>();
  let hasStar = false;
  let risk: RiskClass = "mutate";
  try {
    let parts: { text: string; node: WalkObj }[];
    try {
      parts = splitChangeStatements(sql);
    } catch (e) {
      if (e instanceof Reject) throw e;
      return deny("SQL ayrıştırılamadı");
    }
    if (parts.length === 0) return deny("boş ifade");
    if (parts.length > MAX_CHANGE_STATEMENTS) return deny(`en çok ${MAX_CHANGE_STATEMENTS} ifade (${parts.length})`, parts.length);
    parts.forEach((p, index) => {
      const ctx = newCtx();
      const built = build(p.node, ctx);
      const targetKeys = new Set(built.targets.map(keyOf));
      const reads: ChangeRelation[] = [];
      for (const rel of ctx.relations) {
        allRelations.add(rel);
        const bits = rel.split(".");
        if (bits.length > 2) rej("katalog nitelikli ilişki adı reddedilir");
        const schema = bits.length === 2 ? checkIdent(bits[0], "şema") : undefined;
        const name = checkIdent(bits[bits.length - 1], "ilişki");
        const r = relationOf(schema, name);
        if (!targetKeys.has(keyOf(r))) reads.push(r);
      }
      for (const c of ctx.columnRefs) columnRefs.push(c);
      for (const f of ctx.functions) functions.add(f);
      for (const w of [...ctx.rowJsonArgs, ...ctx.singleNameRefs.filter((n) => ctx.aliases.has(n))]) wholeRow.add(w);
      if (ctx.hasStar) hasStar = true;
      kinds.push(Object.keys(p.node)[0] as string);
      if (riskRank(built.risk) > riskRank(risk)) risk = built.risk;
      statements.push({ index, kind: built.kind, risk: built.risk, text: p.text, targets: built.targets, lockMode: built.lockMode, reads, unbounded: built.unbounded, creates: built.creates });
    });
  } catch (e) {
    if (e instanceof Reject) return deny(e.message);
    throw e;
  }
  const classification: SqlClassification = {
    parsed: true,
    statementCount: statements.length,
    statementKinds: kinds,
    relations: [...allRelations],
    columnRefs,
    functions: [...functions],
    wholeRowRefs: [...wholeRow],
    hasStarSelect: hasStar,
  };
  const digest = createHash("sha256").update(JSON.stringify(statements.map((s) => s.text))).digest("hex");
  return { allowed: true, statements, risk, digest, classification };
}
