import type { CursorAgentOptions, CursorCustomTool } from "./sdk.ts";

export class LaunchError extends Error {
  readonly code = "cursor_launch_unsafe";
  constructor(message: string) {
    super(message);
    this.name = "LaunchError";
  }
}

/**
 * Yerleşik araç adları (kabuk, dosya, ağ). **Adlar doğrulanmadı**: "Tam ToolName listesi sayfada
 * yok" (ADR-0004 spike). Asıl kontrol `tools: []` allowlist'idir; bu liste ikincil kemerdir ve
 * `mcp` grubunu İÇERMEZ (özel araçlar SDK'da bir MCP sunucusu olarak kaydedilir).
 */
export const BUILTIN_DENY: readonly string[] = ["shell", "edit", "write", "read", "grep", "glob", "search", "web_search", "web_fetch", "task", "todo", "notebook"];

/** `.` işlev adlarında sorun çıkarabilir: `__` ile kodlanır (OpenAI uyumlu uçlarla aynı kural). */
export const encodeName = (n: string): string => n.replaceAll(".", "__");

export interface LaunchInput {
  readonly apiKey?: string;
  readonly model: string;
  readonly system: string;
  readonly cwd: string;
  readonly tools: readonly { readonly name: string; readonly description: string; readonly inputSchema: Record<string, unknown>; execute(args: unknown): Promise<string> }[];
}

/**
 * Cursor ajanı için TEK başlatma fonksiyonu. `tools`/`disallowedTools`/`systemPrompt`/inline
 * `mcpServers` `resume`'da geri gelmediğinden (varsayılan: kabuk AÇIK, onaysız) her tur YENİ
 * `Agent.create` yapılır ve seçenekler BURADAN geçer; eksik/gevşek seçenek = fırlatır (araçsız
 * fail-closed, kabuk değil). Birim testi seçenek kümesini kilitler.
 */
export function buildCursorLaunchOptions(inp: LaunchInput): CursorAgentOptions {
  const customTools: CursorCustomTool[] = inp.tools.map((t) => ({
    name: encodeName(t.name),
    description: t.description,
    inputSchema: t.inputSchema,
    execute: t.execute,
  }));
  const opts: CursorAgentOptions = {
    ...(inp.apiKey ? { apiKey: inp.apiKey } : {}),
    model: inp.model,
    systemPrompt: inp.system,
    tools: [],
    disallowedTools: [...BUILTIN_DENY],
    local: { cwd: inp.cwd, sandboxOptions: { enabled: true }, customTools },
  };
  assertSafeLaunch(opts, inp.tools.map((t) => t.name), inp.apiKey);
  return opts;
}

const FORBIDDEN_KEYS = ["settingSources", "mcpServers", "resume", "agentId", "hooks", "env", "envVars"];

/** Fail-closed doğrulama: gevşek başlatma seçenekleri ASLA SDK'ya gitmez. */
export function assertSafeLaunch(opts: unknown, allowedCustom: readonly string[], apiKey?: string): asserts opts is CursorAgentOptions {
  const o = opts as Partial<CursorAgentOptions> & Record<string, unknown>;
  if (o === null || typeof o !== "object") throw new LaunchError("seçenekler nesne değil");
  for (const k of FORBIDDEN_KEYS) if (k in o) throw new LaunchError(`yasak seçenek: ${k}`);
  if (!Array.isArray(o.tools) || o.tools.length !== 0) throw new LaunchError("yerleşik araç allowlist'i boş olmalı (tools: [])");
  if (!Array.isArray(o.disallowedTools)) throw new LaunchError("disallowedTools eksik");
  for (const d of BUILTIN_DENY) if (!o.disallowedTools.includes(d)) throw new LaunchError(`disallowedTools '${d}' içermeli`);
  if (o.disallowedTools.includes("mcp")) throw new LaunchError("'mcp' grubu kapatılamaz: özel araçlar bu grupta kaydedilir");
  const local = o.local;
  if (!local || typeof local !== "object") throw new LaunchError("local seçenekleri eksik");
  if (local.sandboxOptions?.enabled !== true) throw new LaunchError("SDK sandbox'ı açık olmalı (sandboxOptions.enabled: true)");
  if (typeof local.cwd !== "string" || !local.cwd.startsWith("/")) throw new LaunchError("cwd mutlak yol olmalı");
  const allowed = new Set(allowedCustom.map(encodeName));
  for (const t of local.customTools ?? []) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(t.name)) throw new LaunchError("özel araç adı geçersiz");
    if (!allowed.has(t.name)) throw new LaunchError("izin listesinde olmayan özel araç");
  }
  if (typeof o.systemPrompt !== "string" || typeof o.model !== "string" || o.model === "") throw new LaunchError("model/systemPrompt eksik");
  if (apiKey && (o.systemPrompt.includes(apiKey) || JSON.stringify(local.customTools.map((t) => [t.name, t.description, t.inputSchema])).includes(apiKey))) {
    throw new LaunchError("API anahtarı istem veya araç tanımlarına sızmış");
  }
}
