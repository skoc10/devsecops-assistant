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

/** Zinciri baştan yeniden hesaplar. Düzenleme, silme, yeniden sıralama ve (çapa varsa) kuyruk kesme tespit edilir. */
export async function verifyAudit(storage: AuditStorage, key: Uint8Array, anchor?: HeadAnchor): Promise<VerifyResult> {
  const lines = await storage.readLines();
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
    const a = await anchor.read();
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
