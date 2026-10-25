import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import type { OrchestratorEvent } from "@ops/core";
import { runChat } from "../src/index.ts";
import type { ChatBackend } from "../src/index.ts";

/** Hiç yanıt vermeyen arka uç (takılmış model çağrısı); `honor` ise iptal sinyalini dinler. */
function hungBackend(honor: boolean): { backend: ChatBackend; signals: AbortSignal[] } {
  const signals: AbortSignal[] = [];
  const backend: ChatBackend = {
    send(_text: string, signal?: AbortSignal): AsyncIterable<OrchestratorEvent> {
      if (signal) signals.push(signal);
      return {
        [Symbol.asyncIterator]: () => ({
          next: () =>
            new Promise<IteratorResult<OrchestratorEvent>>((resolve) => {
              if (honor) signal?.addEventListener("abort", () => resolve({ done: true, value: undefined }), { once: true });
            }),
        }),
      };
    },
    bind: async () => { throw new Error("yok"); },
    profiles: async () => [],
    usage: async () => "",
    evidenceShow: async () => "",
    evidenceRelease: async () => "",
    breakGlassStatus: async () => [],
    breakGlassStart: async () => [],
    breakGlassEnd: async () => "",
  };
  return { backend, signals };
}

describe("sohbet: Ctrl-C / SIGTERM süren turu iptal eder (takılmış model çağrısı süreci kilitlemez)", () => {
  for (const honor of [true, false]) {
    it(honor ? "yerel arka uç: tur sinyali iptal edilir ve sohbet kapanır" : "sinyali tanımayan (uzak) arka uç: döngü yine bırakılır", async () => {
      const { backend, signals } = hungBackend(honor);
      const input = new PassThrough();
      const output = new PassThrough();
      const chunks: string[] = [];
      output.on("data", (b: Buffer) => chunks.push(b.toString()));
      const stop = new AbortController();
      const done = runChat(backend, { input, output }, { stop: stop.signal });
      input.write("neden çöktü?\n");
      await new Promise((r) => setTimeout(r, 20));
      expect(signals).toHaveLength(1);
      stop.abort();
      await done; // takılı kalsaydı test zaman aşımına uğrardı
      expect(signals[0]?.aborted).toBe(true);
      expect(chunks.join("")).toContain("tur iptal edildi");
    });
  }
});
