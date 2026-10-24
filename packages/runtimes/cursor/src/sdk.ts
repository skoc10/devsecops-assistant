/**
 * Cursor SDK'nın KULLANDIĞIMIZ dar yüzü. Bu şekiller https://cursor.com/docs/sdk/typescript
 * sayfasından türetilmiş VARSAYIMLARDIR; gerçek SDK ile ELLE doğrulanmadı (ADR-0004). Bu dosya
 * ve `map.ts` dışında SDK'ya dair hiçbir şey bilinmez. Bağımlılıksız tutulur: `cursor-host`
 * sandbox içinde yalnız bu dosyalarla çalışır.
 */
export interface CursorCustomTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  execute(args: unknown): Promise<string>;
}

export interface CursorAgentOptions {
  readonly apiKey?: string;
  readonly model: string;
  readonly systemPrompt: string;
  /** Yerleşik araç ALLOWLIST'i: boş = yerleşik araç yok. Asıl kontrol budur. */
  readonly tools: readonly string[];
  /** İkincil kemer ("deny wins"). */
  readonly disallowedTools: readonly string[];
  readonly local: {
    readonly cwd: string;
    readonly sandboxOptions: { readonly enabled: boolean };
    readonly customTools: readonly CursorCustomTool[];
  };
}

export type SdkMessage = { readonly type: string; readonly [k: string]: unknown };

export interface CursorRun {
  stream(): AsyncIterable<SdkMessage>;
  cancel(): Promise<void>;
}
export interface CursorAgent {
  send(prompt: string): Promise<CursorRun>;
  close(): Promise<void>;
}
export interface CursorSdk {
  readonly Agent: { create(opts: CursorAgentOptions): Promise<CursorAgent> };
}
