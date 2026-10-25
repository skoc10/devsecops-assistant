import { AuditBodySchema, AuditRecordSchema, isOpsError, OpsError } from "@ops/contracts";
import type { AuditBody, AuditEntry, AuditRecord, AuditSink } from "@ops/contracts";
import { checkAnchor, signAnchor } from "./anchor.ts";
import { chainHash, GENESIS_HASH } from "./chain.ts";
import type { AuditStorage, HeadAnchor } from "./storage.ts";

export interface AuditLogOptions {
  storage: AuditStorage;
  /** Zincir HMAC anahtarı (kasadan); ≥ 16 bayt. */
  key: Uint8Array;
  anchor?: HeadAnchor;
  principal?: string;
  now?: () => Date;
  /** Metin alanlarına uygulanan son-savunma temizleyicisi (M2+M3). */
  scrub?: (text: string) => string;
  maxOutputChars?: number;
  maxArgsChars?: number;
}

function mapStrings(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    // defineProperty: `__proto__` adlı argüman anahtarı da kendi alanı olarak kalır. Atama prototipi değiştirip
    // anahtarı kayıttan düşürürdü; denetim, modelin gönderdiği argümanı eksiksiz yansıtmalı.
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      Object.defineProperty(out, fn(k), { value: mapStrings(v, fn), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Satırı kayıt olarak ayrıştırır ve zincir MAC'ini doğrular; olmazsa nedeni. */
function readRecord(key: Uint8Array, line: string): AuditRecord | "okunamadı" | "doğrulanamadı" {
  let rec: AuditRecord;
  try {
    rec = AuditRecordSchema.parse(JSON.parse(line));
  } catch {
    return "okunamadı";
  }
  const { hash, ...rest } = rec;
  return chainHash(key, rec.prevHash, rest) === hash ? rec : "doğrulanamadı";
}

/**
 * Hash zincirli, write-ahead, fail-closed denetim günlüğü.
 * - `append` başarısız olursa günlük "bozuk" işaretlenir ve sonraki tüm çağrılar reddedilir:
 *   çağıran (PEP) araç çağrısını ÇALIŞTIRMAZ.
 * - Anahtarsız yeniden yazım zinciri doğrulatamaz; kuyruk kesme MAC'li çapa ile tespit edilir (bkz. `anchor.ts`).
 * - Aynı günlüğe birden çok süreç yazabilir (opsd + tek seferlik `ops` komutları): her ekleme depo kilidi
 *   altında yapılır ve baş (seq/hash) yazmadan önce dosyanın son kaydından tazelenir. Bellekteki baş
 *   yalnız "son bilinen"dir; zincir çatallanmaz.
 */
export class AuditLog implements AuditSink {
  private readonly o: Required<Pick<AuditLogOptions, "storage" | "key" | "principal" | "now">> & AuditLogOptions;
  private lastSeq = -1;
  private lastHash = GENESIS_HASH;
  private queue: Promise<unknown> = Promise.resolve();
  private failure: string | null = null;

  private constructor(opts: AuditLogOptions) {
    if (opts.key.length < 16) throw new OpsError("audit_key_invalid", "denetim anahtarı en az 16 bayt olmalı");
    this.o = { ...opts, principal: opts.principal ?? "local-user", now: opts.now ?? (() => new Date()) };
  }

  /** Var olan günlüğü açar: son kaydı ve çapayı doğrular; bozuksa AÇMAZ. */
  static async open(opts: AuditLogOptions): Promise<AuditLog> {
    const log = new AuditLog(opts);
    // Satırlar ve çapa kilit altında birlikte okunur: tam o anda başka bir süreç eklerken (satır yazıldı, çapa
    // henüz yazılmadı) tutarsız görüntüden sahte "kuyruk kesilmiş" kararı çıkmaz.
    const { lines, anchor } = await opts.storage.withLock(async () => ({
      lines: await opts.storage.readLines(),
      anchor: opts.anchor ? await opts.anchor.read() : null,
    }));
    if (lines.length > 0) {
      const rec = readRecord(opts.key, lines[lines.length - 1] as string);
      if (typeof rec === "string") throw new OpsError("audit_corrupt", `denetim günlüğünün son kaydı ${rec}`);
      if (rec.seq !== lines.length - 1) throw new OpsError("audit_corrupt", "denetim günlüğü sıra numarası tutarsız");
      log.lastSeq = rec.seq;
      log.lastHash = rec.hash;
    }
    // Yalnız MAC'i doğrulanan çapaya göre karar verilir. Çapa yok ya da doğrulanamıyorsa (eski biçim, sahte)
    // içeriğine güvenilmez; açılış sürer, ilk yazım çapayı `since` izi bırakarak yeniden kurar (`anchorSince`).
    const a = opts.anchor ? checkAnchor(opts.key, anchor) : null;
    if (a?.status === "ok") {
      if (log.lastSeq < a.seq) {
        throw new OpsError("audit_truncated", "denetim günlüğü çapadan kısa: kuyruk kesilmiş olabilir");
      }
      if (log.lastSeq === a.seq && log.lastHash !== a.hash) {
        throw new OpsError("audit_truncated", "denetim günlüğü çapayla uyuşmuyor");
      }
    }
    return log;
  }

  /** Bu yazıcının son bildiği baş (başka süreçlerin eklemeleri bir sonraki eklemede tazelenir). */
  get head(): { seq: number; hash: string } | null {
    return this.lastSeq < 0 ? null : { seq: this.lastSeq, hash: this.lastHash };
  }

  /** Bir yazma hatasından sonra `true`; bozuk günlük hiçbir kaydı kabul etmez. */
  get broken(): boolean {
    return this.failure !== null;
  }

  append(entry: AuditEntry): Promise<AuditRecord> {
    const run = this.queue.then(() => this.appendNow(entry));
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async appendNow(entry: AuditEntry): Promise<AuditRecord> {
    if (this.failure !== null) {
      throw new OpsError("audit_unavailable", "denetim günlüğü kullanılamıyor", { cause: this.failure });
    }
    // Çağıran hatası (şema dışı alan vb.) günlüğü bozmaz: depolamaya (ve kilide) dokunmadan reddedilir.
    let body: AuditBody;
    try {
      body = this.sanitize(entry);
    } catch (e) {
      throw new OpsError("audit_invalid_entry", "denetim girdisi geçersiz", { cause: errMessage(e) });
    }
    try {
      return await this.o.storage.withLock(() => this.appendLocked(body));
    } catch (e) {
      if (isOpsError(e)) throw e;
      // Kilit zamanında alınamadı ya da son kayıt okunamadı (G/Ç): hiçbir şey yazılmadı, zincir durumu belli →
      // günlük bozuk işaretlenmez; yalnız bu kayıt reddedilir ve çağıran araç çağrısını ÇALIŞTIRMAZ.
      throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı", { cause: errMessage(e) });
    }
  }

  /** Kilit altında: başı dosyadan tazele, çapayı denetle, kaydı zincirle, yaz. */
  private async appendLocked(body: AuditBody): Promise<AuditRecord> {
    await this.syncHead();
    const since = this.o.anchor ? await this.anchorSince(this.o.anchor) : 0;
    let record: AuditRecord;
    try {
      const seq = this.lastSeq + 1;
      const rest = { ...body, seq, prevHash: this.lastHash };
      const hash = chainHash(this.o.key, this.lastHash, rest);
      record = AuditRecordSchema.parse({ ...rest, hash });
    } catch (e) {
      throw new OpsError("audit_invalid_entry", "denetim girdisi geçersiz", { cause: errMessage(e) });
    }
    try {
      await this.o.storage.append(JSON.stringify(record));
      this.lastSeq = record.seq;
      this.lastHash = record.hash;
      if (this.o.anchor) await this.o.anchor.write(signAnchor(this.o.key, record, since));
      return record;
    } catch (e) {
      // Kilit yazmadan önce kaybedildiyse hiçbir şey yazılmadı: yalnız bu kayıt reddedilir.
      if (isOpsError(e) && e.code === "audit_lock_lost") {
        throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı", { cause: e.message });
      }
      // Depolama/çapa hatası: zincir durumu belirsiz → fail-closed, günlük artık kayıt kabul etmez.
      this.failure = errMessage(e);
      throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı", { cause: this.failure });
    }
  }

  /**
   * Kilit altında başı günlüğün son kaydından tazeler: başka bir süreç zinciri ilerletmiş olabilir. Son kayıt
   * okunamıyor/doğrulanamıyorsa ya da bilinen başın gerisindeyse (kesilmiş/değiştirilmiş) zincire güvenilmez →
   * kalıcı fail-closed. Tam zincir denetimi `verifyAudit`'tedir; burada yalnız son kayıt okunur.
   */
  private async syncHead(): Promise<void> {
    const line = await this.o.storage.readLastLine();
    if (line === null) {
      if (this.lastSeq >= 0) this.fail("audit_truncated", "denetim günlüğü boşalmış: kuyruk kesilmiş olabilir");
      return;
    }
    const rec = readRecord(this.o.key, line);
    if (typeof rec === "string") return this.fail("audit_corrupt", `denetim günlüğünün son kaydı ${rec}`);
    if (rec.seq < this.lastSeq || (rec.seq === this.lastSeq && rec.hash !== this.lastHash)) {
      this.fail("audit_truncated", "denetim günlüğü bilinen başın gerisinde: kuyruk kesilmiş olabilir");
    }
    this.lastSeq = rec.seq;
    this.lastHash = rec.hash;
  }

  /**
   * Kilit altında çapayı denetler; yazılacak çapanın `since` değerini döndürür. Doğrulanan çapa günlükten
   * ilerideyse (bu süreç bakmazken kuyruk kesilmiş) kalıcı fail-closed. Çapa yok ya da doğrulanamıyorsa
   * içeriğine güvenilmez: günlük boşsa yeni zincirdir (`since` 0); doluysa çapa bu kayıtta yeniden kurulur ve
   * `since` bu kaydın seq'i olur. İz kalıcıdır, `verifyAudit` onu `anchor_reset` olarak bildirir.
   */
  private async anchorSince(anchor: HeadAnchor): Promise<number> {
    const a = checkAnchor(this.o.key, await anchor.read());
    if (a.status !== "ok") return this.lastSeq + 1;
    if (this.lastSeq < a.seq || (this.lastSeq === a.seq && this.lastHash !== a.hash)) {
      this.fail("audit_truncated", "denetim günlüğü çapadan kısa: kuyruk kesilmiş olabilir");
    }
    return a.since;
  }

  /** Zincir bütünlüğü sorunu: günlük kalıcı olarak bozuk işaretlenir (fail-closed). */
  private fail(code: "audit_corrupt" | "audit_truncated", problem: string): never {
    this.failure = problem;
    throw new OpsError(code, problem);
  }

  private sanitize(entry: AuditEntry): AuditBody {
    const scrub = this.o.scrub ?? ((s: string) => s);
    const maxOut = this.o.maxOutputChars ?? 8192;
    const maxArgs = this.o.maxArgsChars ?? 4096;
    const body = AuditBodySchema.parse({
      ts: this.o.now().toISOString(),
      principal: this.o.principal,
      ...entry,
    });
    const out: Record<string, unknown> = { ...body };
    if (body.message !== undefined) out["message"] = scrub(body.message);
    if (body.target !== undefined) out["target"] = scrub(body.target);
    if (body.outputRedacted !== undefined) {
      const s = scrub(body.outputRedacted);
      out["outputRedacted"] = s.length > maxOut ? `${s.slice(0, maxOut)}…[kesildi]` : s;
    }
    if (body.argsRedacted !== undefined) {
      const scrubbed = mapStrings(body.argsRedacted, scrub);
      const serialized = JSON.stringify(scrubbed) ?? "";
      out["argsRedacted"] = serialized.length > maxArgs ? { _truncated: true, bytes: serialized.length } : scrubbed;
    }
    return AuditBodySchema.parse(out);
  }
}
