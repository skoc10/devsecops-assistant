/** Ana süreç ↔ cursor-host NDJSON protokolü (bağımlılıksız; host sandbox içinde bunu kullanır). */
export interface ToolSpecWire {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

export type ParentToHost =
  | {
      readonly t: "task";
      readonly model: string;
      /** Anahtar env/argv ile DEĞİL, bu ilk mesajla geçer. */
      readonly apiKey?: string;
      readonly system: string;
      readonly prompt: string;
      readonly ledgerSummary?: string;
      readonly tools: readonly ToolSpecWire[];
      readonly cwd: string;
    }
  | { readonly t: "tool_result"; readonly id: string; readonly text: string; readonly isError: boolean }
  | { readonly t: "cancel" };

export type HostToParent =
  | { readonly t: "event"; readonly event: unknown }
  | { readonly t: "tool_request"; readonly id: string; readonly name: string; readonly args: unknown }
  | { readonly t: "done" }
  | { readonly t: "error"; readonly message: string };

export const MAX_LINE_BYTES = 2 * 1024 * 1024;
