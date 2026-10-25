import { AuditBodySchema, AuditRecordSchema, OpsError } from "@ops/contracts";
import type { AuditBody, AuditEntry, AuditRecord, AuditSink } from "@ops/contracts";
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

/**
 * Hash zincirli, write-ahead, fail-closed denetim günlüğü.
 * - `append` başarısız olursa günlük "bozuk" işaretlenir ve sonraki tüm çağrılar reddedilir:
 *   çağıran (PEP) araç çağrısını ÇALIŞTIRMAZ.
 * - Anahtarsız yeniden yazım zinciri doğrulatamaz; kuyruk kesme çapa ile tespit edilir.
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
    const lines = await opts.storage.readLines();
    const anchor = opts.anchor ? await opts.anchor.read() : null;
    if (lines.length > 0) {
      const last = lines[lines.length - 1] as string;
      let rec: AuditRecord;
      try {
        rec = AuditRecordSchema.parse(JSON.parse(last));
      } catch {
        throw new OpsError("audit_corrupt", "denetim günlüğünün son kaydı okunamadı");
      }
      const { hash, ...rest } = rec;
      if (chainHash(opts.key, rec.prevHash, rest) !== hash) {
        throw new OpsError("audit_corrupt", "denetim günlüğünün son kaydı doğrulanamadı");
      }
      if (rec.seq !== lines.length - 1) throw new OpsError("audit_corrupt", "denetim günlüğü sıra numarası tutarsız");
      log.lastSeq = rec.seq;
      log.lastHash = rec.hash;
    }
    if (anchor) {
      if (log.lastSeq < anchor.seq) {
        throw new OpsError("audit_truncated", "denetim günlüğü çapadan kısa: kuyruk kesilmiş olabilir");
      }
      if (log.lastSeq === anchor.seq && log.lastHash !== anchor.hash) {
        throw new OpsError("audit_truncated", "denetim günlüğü çapayla uyuşmuyor");
      }
    }
    return log;
  }

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
    // Çağıran hatası (şema dışı alan vb.) günlüğü bozmaz: depolamaya dokunmadan reddedilir.
    let record: AuditRecord;
    try {
      const body = this.sanitize(entry);
      const seq = this.lastSeq + 1;
      const rest = { ...body, seq, prevHash: this.lastHash };
      const hash = chainHash(this.o.key, this.lastHash, rest);
      record = AuditRecordSchema.parse({ ...rest, hash });
    } catch (e) {
      throw new OpsError("audit_invalid_entry", "denetim girdisi geçersiz", {
        cause: e instanceof Error ? e.message : String(e),
      });
    }
    try {
      await this.o.storage.append(JSON.stringify(record));
      this.lastSeq = record.seq;
      this.lastHash = record.hash;
      if (this.o.anchor) await this.o.anchor.write({ seq: record.seq, hash: record.hash });
      return record;
    } catch (e) {
      // Depolama/çapa hatası: zincir durumu belirsiz → fail-closed, günlük artık kayıt kabul etmez.
      this.failure = e instanceof Error ? e.message : String(e);
      throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı", { cause: this.failure });
    }
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
