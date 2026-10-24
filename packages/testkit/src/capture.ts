import type { Canary } from "./canary.ts";
import { findCanary } from "./canary.ts";

export interface Leak {
  readonly channel: string;
  readonly label: string;
  readonly variant: string;
}

/**
 * Sınırdan geçen her baytı kanal adıyla toplar (model yükü, denetim, UI akışı, stdout/stderr...).
 * Sızıntı raporları canary DEĞERİNİ değil etiket + biçim adını içerir.
 */
export class CaptureSink {
  private readonly chunks: { channel: string; text: string }[] = [];

  push(channel: string, data: unknown): void {
    const text =
      typeof data === "string"
        ? data
        : data instanceof Uint8Array
          ? Buffer.from(data).toString("utf8")
          : JSON.stringify(data) ?? String(data);
    this.chunks.push({ channel, text });
  }

  channels(): string[] {
    return [...new Set(this.chunks.map((c) => c.channel))];
  }

  text(channel?: string): string {
    return this.chunks
      .filter((c) => channel === undefined || c.channel === channel)
      .map((c) => c.text)
      .join("\n");
  }

  bytes(channel?: string): number {
    return Buffer.byteLength(this.text(channel), "utf8");
  }

  leaks(canaries: readonly Canary[], channels?: readonly string[]): Leak[] {
    const found: Leak[] = [];
    for (const channel of channels ?? this.channels()) {
      const text = this.text(channel);
      for (const c of canaries) {
        const variant = findCanary(text, c);
        if (variant) found.push({ channel, label: c.label, variant });
      }
    }
    return found;
  }

  assertNoCanary(canaries: readonly Canary[], channels?: readonly string[]): void {
    const leaks = this.leaks(canaries, channels);
    if (leaks.length > 0) {
      const msg = leaks.map((l) => `${l.channel}:${l.label}(${l.variant})`).join(", ");
      throw new Error(`canary sızıntısı: ${msg}`);
    }
  }
}
