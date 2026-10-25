import { AuditRecordSchema } from "@ops/contracts";
import type { AuditRecord } from "@ops/contracts";
import { chainHash, GENESIS_HASH } from "./chain.ts";
import type { AuditStorage, HeadAnchor } from "./storage.ts";

export interface VerifyProblem {
  readonly seq: number | null;
  readonly code:
    | "unparseable"
    | "schema"
    | "seq_gap"
    | "prev_hash_mismatch"
    | "hash_mismatch"
    | "tail_truncated"
    | "anchor_mismatch";
  readonly message: string;
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly records: number;
  readonly head: { seq: number; hash: string } | null;
  readonly problems: VerifyProblem[];
}

/** Kilit dosyası oluşturulamayan konum (salt-okunur kopya, başkasının dizini): orada yazıcı kilidi de yoktur. */
function isUnwritable(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException | null)?.code;
  return code === "EROFS" || code === "EACCES" || code === "EPERM";
}

/** Zinciri baştan yeniden hesaplar. Düzenleme, silme, yeniden sıralama ve (çapa varsa) kuyruk kesme tespit edilir. */
export async function verifyAudit(storage: AuditStorage, key: Uint8Array, anchor?: HeadAnchor): Promise<VerifyResult> {
  // Tutarlı anlık görüntü: satırlar ve çapa kilit altında okunur (eşzamanlı ekleme sahte kesme/yarım satır
  // göstermez); hash hesabı kilit bırakıldıktan sonra yapılır, yazıcılar beklemez. Kilit hiç oluşturulamıyorsa
  // (salt-okunur kopyanın adli incelemesi) kilitsiz okunur; çapa önce okunur ki eşzamanlı ekleme sahte kesme göstermesin.
  const snapshot = async () => {
    const head = anchor ? await anchor.read() : null;
    return { head, lines: await storage.readLines() };
  };
  const { lines, head } = await storage.withLock(snapshot).catch((e: unknown) => {
    if (isUnwritable(e)) return snapshot();
    throw e;
  });
  const problems: VerifyProblem[] = [];
  const records: AuditRecord[] = [];
  let prev = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    let rec: AuditRecord;
    try {
      rec = AuditRecordSchema.parse(JSON.parse(lines[i] as string));
    } catch (e) {
      const isSchema = e instanceof Error && e.name === "ZodError";
      problems.push({
        seq: i,
        code: isSchema ? "schema" : "unparseable",
        message: isSchema ? `satır ${i}: şema dışı alan veya değer` : `satır ${i}: JSON okunamadı`,
      });
      continue;
    }
    if (rec.seq !== i) {
      problems.push({ seq: i, code: "seq_gap", message: `satır ${i}: beklenen seq ${i}, bulunan ${rec.seq}` });
    }
    if (rec.prevHash !== prev) {
      problems.push({ seq: rec.seq, code: "prev_hash_mismatch", message: `seq ${rec.seq}: önceki hash zincire uymuyor` });
    }
    const { hash, ...rest } = rec;
    if (chainHash(key, rec.prevHash, rest) !== hash) {
      problems.push({ seq: rec.seq, code: "hash_mismatch", message: `seq ${rec.seq}: kayıt hash'i doğrulanamadı` });
    }
    records.push(rec);
    prev = rec.hash;
  }

  if (anchor) {
    const a = head;
    if (a) {
      const last = records[records.length - 1];
      if (!last || last.seq < a.seq) {
        problems.push({ seq: null, code: "tail_truncated", message: `günlük çapadan kısa (çapa seq ${a.seq}): kuyruk kesilmiş` });
      } else {
        const at = records.find((r) => r.seq === a.seq);
        if (!at || at.hash !== a.hash) {
          problems.push({ seq: a.seq, code: "anchor_mismatch", message: `seq ${a.seq}: çapa hash'i ile uyuşmuyor` });
        }
      }
    }
  }

  const last = records[records.length - 1];
  return { ok: problems.length === 0, records: records.length, head: last ? { seq: last.seq, hash: last.hash } : null, problems };
}
