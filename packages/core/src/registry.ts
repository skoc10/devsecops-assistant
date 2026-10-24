import { createHash } from "node:crypto";
import { OpsError } from "@ops/contracts";
import type { Adapter, ToolDefinition, ToolSpec } from "@ops/contracts";

export interface RegisteredTool {
  readonly adapter: Adapter;
  readonly def: ToolDefinition;
}

function fingerprint(v: unknown): string {
  const sort = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sort);
    if (x !== null && typeof x === "object") {
      return Object.fromEntries(Object.entries(x as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, val]) => [k, sort(val)]));
    }
    return x;
  };
  return createHash("sha256").update(JSON.stringify(sort(v))).digest("hex");
}

/**
 * Mutasyon+ araçların modele gösterilen şemasına eklenen ayrılmış alan: modelin, işlemi dayandırdığı kanıt
 * kimlikleri. `ToolExecutor` bunu şemadan ÖNCE ayırır (araç şemaları `additionalProperties: false` kalır).
 */
export const CITED_PROPERTY = {
  type: "array",
  items: { type: "string", pattern: "^ev-\\d+$" },
  maxItems: 10,
  description: "Bu işlemi destekleyen kanıt kimlikleri (ev-N); hedef kaynağı içeren taze kanıt olmalı",
} as const;

function withCited(schema: Record<string, unknown>): Record<string, unknown> {
  const props = (schema["properties"] ?? {}) as Record<string, unknown>;
  return { ...schema, properties: { ...props, cited: CITED_PROPERTY } };
}

/** Araç kayıt defteri: manifest ve çalışma zamanı tanımları birebir uyumlu olmak zorundadır. */
export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();

  register(adapter: Adapter, definitions: readonly ToolDefinition[]): void {
    const manifestTools = new Map(adapter.manifest.tools.map((t) => [t.name, t]));
    const defs = new Map(definitions.map((d) => [d.descriptor.name, d]));
    for (const [name, mt] of manifestTools) {
      const d = defs.get(name);
      if (!d) throw new OpsError("registry_mismatch", `manifestte olup tanımı olmayan araç: ${name}`);
      if (fingerprint(d.descriptor) !== fingerprint(mt)) {
        throw new OpsError("registry_mismatch", `araç tanımı manifestle uyuşmuyor: ${name}`);
      }
    }
    for (const name of defs.keys()) {
      if (!manifestTools.has(name)) throw new OpsError("registry_mismatch", `manifestte olmayan araç tanımı: ${name}`);
    }
    for (const [name, def] of defs) {
      if (this.tools.has(name)) throw new OpsError("registry_duplicate", `araç zaten kayıtlı: ${name}`);
      this.tools.set(name, { adapter, def });
    }
  }

  get(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  all(): RegisteredTool[] {
    return [...this.tools.values()];
  }

  /**
   * Etkin araç setlerine ait araç şemaları. Sıra DETERMİNİSTİKTİR: araç setleri etkinleşme
   * sırasıyla, her set içinde ada göre. Yeni bir set etkinleşince liste YALNIZ SONA eklenir:
   * önek bayt-bayt aynı kalır ve istem önbelleği isabeti korunur (B-05).
   */
  specsFor(toolsets: Iterable<string>): ToolSpec[] {
    const out: ToolSpec[] = [];
    const seen = new Set<string>();
    for (const ts of toolsets) {
      if (seen.has(ts)) continue;
      seen.add(ts);
      out.push(
        ...this.all()
          .filter((t) => t.def.descriptor.toolset === ts)
          .map((t) => ({
            name: t.def.descriptor.name,
            description: t.def.descriptor.description,
            inputSchema: t.def.descriptor.class === "read" ? t.def.descriptor.inputSchema : withCited(t.def.descriptor.inputSchema),
          }))
          .sort((a, b) => a.name.localeCompare(b.name)),
      );
    }
    return out;
  }
}
