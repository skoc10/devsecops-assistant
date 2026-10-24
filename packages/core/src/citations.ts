import type { EvidenceStore } from "./evidence.ts";

const EVIDENCE_ID = /\bev-\d+\b/g;

export interface CitationCheck {
  readonly cited: string[];
  readonly valid: string[];
  readonly invalid: string[];
}

/**
 * "Kanıt yoksa iddia yok": cevaptaki her `ev-N` başvurusu Evidence Store'da bulunmalıdır.
 * Deterministik ve sözdizimseldir; anlamsal ilgiyi insan değerlendirir.
 */
export function verifyCitations(text: string, store: EvidenceStore): CitationCheck {
  const cited = [...new Set(text.match(EVIDENCE_ID) ?? [])];
  const valid = cited.filter((id) => store.get(id) !== undefined);
  return { cited, valid, invalid: cited.filter((id) => !valid.includes(id)) };
}
