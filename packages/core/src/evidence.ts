import { createHash } from "node:crypto";
import { estimateTokens } from "@ops/contracts";
import type { Sensitivity, Taint } from "@ops/contracts";
import { clampListsDeep, projectFields } from "@ops/redaction";

export interface EvidenceEntry {
  readonly id: string;
  readonly callId: string;
  readonly tool: string;
  readonly profileId: string | undefined;
  readonly epoch: number;
  readonly observedAt: string;
  /** Kaynak başvuruları (ör. `Deployment/payments/api`); mutasyon atfı bunlarla eşleşir. */
  readonly subjects: readonly string[];
  readonly sensitivity: Sensitivity;
  readonly taint: Taint;
  readonly summary: string;
  /** Tam REDAKTE sonuç (JSON metni). Ham çıktı hiçbir zaman saklanmaz. */
  readonly text: string;
  readonly tokens: number;
  readonly hash: string;
}

export type NewEvidence = Omit<EvidenceEntry, "id" | "tokens" | "hash">;

export interface SliceResult {
  readonly data: unknown;
  readonly total: number | null;
  readonly shown: number | null;
  readonly offset: number;
}

const isPlain = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Bellek içi kanıt deposu. Modele giden görünümler buradaki tam redakte kanıtın türevidir. */
export class EvidenceStore {
  private readonly entries = new Map<string, EvidenceEntry>();
  private counter = 0;

  put(e: NewEvidence): EvidenceEntry {
    const id = `ev-${++this.counter}`;
    const entry: EvidenceEntry = {
      ...e,
      id,
      tokens: estimateTokens(e.text),
      hash: createHash("sha256").update(e.text).digest("hex"),
    };
    this.entries.set(id, entry);
    return entry;
  }

  get(id: string): EvidenceEntry | undefined {
    return this.entries.get(id);
  }

  all(): EvidenceEntry[] {
    return [...this.entries.values()];
  }

  /** `select` (alan yolları), `offset` ve `limit` ile kanıttan dilim alır. */
  slice(id: string, opts: { select?: readonly string[]; offset?: number; limit?: number }): SliceResult | null {
    const e = this.entries.get(id);
    if (!e) return null;
    let data: unknown = JSON.parse(e.text) as unknown;
    const offset = Math.max(0, opts.offset ?? 0);
    const limit = Math.max(1, opts.limit ?? 20);
    let total: number | null = null;
    let shown: number | null = null;

    // Liste biçimleri: dizi, {items}, {columns, rows}
    const sliceList = (list: unknown[]): unknown[] => {
      total = list.length;
      const part = list.slice(offset, offset + limit);
      shown = part.length;
      return part;
    };
    if (Array.isArray(data)) {
      data = sliceList(data);
    } else if (isPlain(data) && Array.isArray(data["items"])) {
      data = { ...data, items: sliceList(data["items"] as unknown[]) };
    } else if (isPlain(data) && Array.isArray(data["columns"]) && Array.isArray(data["rows"])) {
      data = { ...data, rows: sliceList(data["rows"] as unknown[]) };
    }
    if (opts.select && opts.select.length > 0) data = projectFields(data, opts.select);
    data = clampListsDeep(data, Math.max(limit, 1));
    return { data, total, shown, offset };
  }

  search(query: string, limit = 10): { id: string; tool: string; summary: string; matches: number }[] {
    const q = query.toLowerCase();
    const out: { id: string; tool: string; summary: string; matches: number }[] = [];
    for (const e of this.entries.values()) {
      const hay = `${e.summary}\n${e.text}`.toLowerCase();
      let matches = 0;
      for (let i = hay.indexOf(q); i !== -1 && matches < 1000; i = hay.indexOf(q, i + q.length)) matches++;
      if (matches > 0) out.push({ id: e.id, tool: e.tool, summary: e.summary, matches });
    }
    return out.sort((a, b) => b.matches - a.matches).slice(0, limit);
  }

  /**
   * Mutasyon atfı denetimi (sözdizimsel): hedefin kaynak başvurularından EN AZ biri, atıf yapılan
   * taze kanıtların `subject`'inde geçmeli; kanıt aynı profil ve çağdan olmalı. Anlamsal ilgiyi insan
   * onayı doğrular.
   */
  supports(args: {
    ids: readonly string[];
    targetRefs: readonly string[];
    profileId: string;
    epoch: number;
    maxAgeMs: number;
    now: Date;
  }): { ok: true } | { ok: false; why: string } {
    if (args.targetRefs.length === 0) return { ok: false, why: "hedef kaynak başvurusu yok" };
    if (args.ids.length === 0) return { ok: false, why: "atıf yapılan kanıt yok" };
    for (const id of args.ids) {
      const e = this.entries.get(id);
      if (!e) continue;
      if (e.profileId !== args.profileId) continue;
      if (e.epoch !== args.epoch) continue;
      if (args.now.getTime() - Date.parse(e.observedAt) > args.maxAgeMs) continue;
      if (e.subjects.some((s) => args.targetRefs.includes(s))) return { ok: true };
    }
    return { ok: false, why: "atıf yapılan taze kanıtların hiçbiri hedef kaynağı kapsamıyor (profil/çağ/subject)" };
  }
}
