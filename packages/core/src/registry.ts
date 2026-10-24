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
   * Etkin araç setlerine ait araç şemaları. Sıra DETERMİNİSTİKTİR (ada göre): önek kararlılığı ve
   * istem önbelleği için (B-05).
   */
  specsFor(toolsets: Iterable<string>): ToolSpec[] {
    const wanted = new Set(toolsets);
    return this.all()
      .filter((t) => wanted.has(t.def.descriptor.toolset))
      .map((t) => ({
        name: t.def.descriptor.name,
        description: t.def.descriptor.description,
        inputSchema: t.def.descriptor.inputSchema,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }
}
