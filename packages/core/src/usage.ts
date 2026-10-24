import type { AuditRecord, Usage } from "@ops/contracts";

export interface UsageRow {
  readonly turn: number;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
}

export interface UsageReport {
  readonly modelCalls: number;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
  readonly toolCalls: number;
  /** Modele giden araç sonucu görünümlerinin tahmini toplamı. */
  readonly resultTokens: number;
  readonly byTool: Record<string, { calls: number; resultTokens: number }>;
  readonly top: { tool: string; evidenceId?: string; resultTokens: number }[];
}

/** Oturum içi sayaç (orkestratör besler). */
export class UsageMeter {
  private readonly rows: UsageRow[] = [];
  private readonly tools = new Map<string, { calls: number; resultTokens: number }>();
  private readonly results: { tool: string; evidenceId?: string; resultTokens: number }[] = [];

  addModel(u: Usage): void {
    this.rows.push({ turn: this.rows.length + 1, ...u });
  }

  addTool(tool: string, resultTokens: number, evidenceId?: string): void {
    const t = this.tools.get(tool) ?? { calls: 0, resultTokens: 0 };
    t.calls += 1;
    t.resultTokens += resultTokens;
    this.tools.set(tool, t);
    this.results.push({ tool, resultTokens, ...(evidenceId ? { evidenceId } : {}) });
  }

  report(): UsageReport {
    return buildReport(
      this.rows.length,
      this.rows.reduce((a, r) => a + r.inputTokens, 0),
      this.rows.reduce((a, r) => a + r.outputTokens, 0),
      this.rows.reduce((a, r) => a + r.cacheReadTokens, 0),
      this.tools,
      this.results,
    );
  }
}

function buildReport(
  modelCalls: number,
  inputTokens: number,
  outputTokens: number,
  cacheReadTokens: number,
  tools: Map<string, { calls: number; resultTokens: number }>,
  results: { tool: string; evidenceId?: string; resultTokens: number }[],
): UsageReport {
  const byTool = Object.fromEntries([...tools.entries()].sort(([a], [b]) => a.localeCompare(b)));
  return {
    modelCalls,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    toolCalls: [...tools.values()].reduce((a, t) => a + t.calls, 0),
    resultTokens: [...tools.values()].reduce((a, t) => a + t.resultTokens, 0),
    byTool,
    top: [...results].sort((a, b) => b.resultTokens - a.resultTokens).slice(0, 5),
  };
}

/** `ops usage`: denetim kaydından (post-hoc) aynı raporu üretir. */
export function usageFromAudit(records: readonly AuditRecord[], sessionId?: string): UsageReport {
  let modelCalls = 0;
  let input = 0;
  let output = 0;
  let cacheRead = 0;
  const tools = new Map<string, { calls: number; resultTokens: number }>();
  const results: { tool: string; evidenceId?: string; resultTokens: number }[] = [];
  for (const r of records) {
    if (sessionId && r.sessionId !== sessionId) continue;
    if (r.event === "model_call" && r.tokens) {
      modelCalls += 1;
      input += r.tokens.input;
      output += r.tokens.output;
      cacheRead += r.tokens.cacheRead;
    }
    if (r.event === "result" && r.tool) {
      const t = tools.get(r.tool) ?? { calls: 0, resultTokens: 0 };
      t.calls += 1;
      t.resultTokens += r.resultTokensEstimate ?? 0;
      tools.set(r.tool, t);
      results.push({ tool: r.tool, resultTokens: r.resultTokensEstimate ?? 0 });
    }
  }
  return buildReport(modelCalls, input, output, cacheRead, tools, results);
}

export function formatUsage(r: UsageReport): string {
  const lines = [
    `Model çağrısı: ${r.modelCalls}  girdi ${r.inputTokens}  çıktı ${r.outputTokens}  önbellek-okuma ${r.cacheReadTokens}`,
    `Araç çağrısı: ${r.toolCalls}  modele giden sonuç (tahmini) ${r.resultTokens} token`,
  ];
  for (const [tool, t] of Object.entries(r.byTool)) lines.push(`  ${tool}: ${t.calls} çağrı, ${t.resultTokens} token`);
  if (r.top.length > 0) lines.push(`En pahalı sonuçlar: ${r.top.map((x) => `${x.evidenceId ?? x.tool}=${x.resultTokens}`).join(", ")}`);
  return lines.join("\n");
}
