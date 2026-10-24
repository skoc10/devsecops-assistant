import { estimateTokens } from "@ops/contracts";
import type { Message } from "@ops/contracts";

export interface LedgerEntry {
  readonly id: string;
  readonly tool: string;
  readonly summary: string;
  readonly subjects: readonly string[];
}

/**
 * Bağlam defteri (tasarım §4.5-6): ham sonuç mesajları döngüde tutulmaz. Konuşma durumu =
 * hedef + kanıt defteri (id + tek satır özet + konu) + son sonuçlar. Eşikte eski turlar bu
 * defterden üretilen DETERMİNİSTİK özetle değiştirilir (model çağrısı yok).
 */
export class Ledger {
  goal: string | undefined;
  private readonly entries: LedgerEntry[] = [];
  private readonly conclusions: string[] = [];

  noteGoal(text: string): void {
    this.goal ??= text.slice(0, 300);
  }

  noteEvidence(e: LedgerEntry): void {
    this.entries.push(e);
  }

  noteConclusion(text: string): void {
    this.conclusions.push(text.slice(0, 600));
    if (this.conclusions.length > 3) this.conclusions.shift();
  }

  all(): readonly LedgerEntry[] {
    return this.entries;
  }

  /** Eski turların yerine geçen özet metni. */
  summarize(maxTokens: number): string {
    const lines: string[] = ["[ÖNCEKİ TURLARIN ÖZETİ — ham sonuçlar çıkarıldı; ayrıntı için evidence.get(id, select, limit)]"];
    if (this.goal) lines.push(`Hedef: ${this.goal}`);
    if (this.entries.length > 0) {
      lines.push("Kanıtlar:");
      for (const e of this.entries) lines.push(`- ${e.id} ${e.tool}: ${e.summary}${e.subjects.length ? ` [${e.subjects.slice(0, 3).join(", ")}]` : ""}`);
    }
    for (const c of this.conclusions) lines.push(`Önceki sonuç: ${c}`);
    let text = lines.join("\n");
    // Çok uzarsa en eski kanıt satırlarından kırp
    while (estimateTokens(text) > maxTokens && lines.length > 3) {
      lines.splice(2, 1);
      text = lines.join("\n");
    }
    return text;
  }
}

export interface CompactOptions {
  /** Mesajların tahmini toplamı bu eşiği aşarsa sıkıştırılır. */
  readonly thresholdTokens: number;
  /** Özetin token tavanı. */
  readonly summaryTokens: number;
  /** Mevcut turdaki en yeni bu kadar araç mesajı tam kalır; eskilerin gövdesi referansla değişir. */
  readonly keepToolMessages: number;
}

export const DEFAULT_COMPACT: CompactOptions = { thresholdTokens: 6_000, summaryTokens: 1_200, keepToolMessages: 4 };

export function messagesTokens(messages: readonly Message[]): number {
  return estimateTokens(JSON.stringify(messages));
}

/**
 * Mesaj geçmişini defter özetiyle sıkıştırır. Son kullanıcı mesajından itibaren olan mevcut tur
 * korunur; öncesi tek özet mesajına iner. Mevcut tur hâlâ büyükse en eski araç sonuçlarının
 * gövdesi "kanıt olarak saklandı" notuyla değiştirilir (araç çağrısı/yanıt eşleşmesi bozulmaz).
 */
export function compactMessages(messages: readonly Message[], ledger: Ledger, opts: CompactOptions = DEFAULT_COMPACT): { messages: Message[]; compacted: boolean } {
  if (messagesTokens(messages) <= opts.thresholdTokens) return { messages: [...messages], compacted: false };
  let lastUser = -1;
  for (let i = messages.length - 1; i >= 0; i--) if (messages[i]?.role === "user" && !isSummary(messages[i] as Message)) { lastUser = i; break; }
  let out: Message[] = [...messages];
  if (lastUser > 0) {
    out = [{ role: "user", content: ledger.summarize(opts.summaryTokens) }, ...messages.slice(lastUser)];
  }
  // mevcut tur hâlâ büyükse eski araç sonuçlarını referansa çevir
  if (messagesTokens(out) > opts.thresholdTokens) {
    const toolIdx = out.flatMap((m, i) => (m.role === "tool" ? [i] : []));
    const stale = toolIdx.slice(0, Math.max(0, toolIdx.length - opts.keepToolMessages));
    out = out.map((m, i) => {
      if (!stale.includes(i) || m.role !== "tool") return m;
      const id = /"id":"(ev-\d+)"/.exec(m.content)?.[1] ?? /\bev-\d+\b/.exec(m.content)?.[0];
      return { ...m, content: id ? `(sonuç ${id} olarak saklandı; evidence.get ile alın)` : "(eski sonuç çıkarıldı)" };
    });
  }
  return { messages: out, compacted: true };
}

function isSummary(m: Message): boolean {
  return m.role === "user" && m.content.startsWith("[ÖNCEKİ TURLARIN ÖZETİ");
}
