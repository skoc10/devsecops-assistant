import { readFile } from "node:fs/promises";
import { AuditRecordSchema } from "@ops/contracts";
import type { AuditRecord, DoctorReport } from "@ops/contracts";
import { formatUsage, usageFromAudit } from "@ops/core";
import type { Orchestrator, OrchestratorEvent } from "@ops/core";
import type { ChatBackend, ProfileRow } from "./chat.ts";
import type { Runtime } from "./runtime.ts";

export async function readAuditRecords(path: string): Promise<AuditRecord[]> {
  const text = await readFile(path, "utf8").catch(() => "");
  return text
    .split("\n")
    .filter(Boolean)
    .flatMap((l) => {
      try {
        const r = AuditRecordSchema.safeParse(JSON.parse(l));
        return r.success ? [r.data] : [];
      } catch {
        return [];
      }
    });
}

/** Süreç içi arka uç (`ops chat --embedded`, testler). */
export class LocalBackend implements ChatBackend {
  private readonly rt: Runtime;
  private readonly orch: Orchestrator;
  constructor(rt: Runtime, orch: Orchestrator) {
    this.rt = rt;
    this.orch = orch;
  }
  send(text: string, signal?: AbortSignal): AsyncIterable<OrchestratorEvent> {
    return this.orch.send(text, signal);
  }
  bind(id: string): Promise<DoctorReport> {
    return this.rt.bindProfile(id);
  }
  async profiles(): Promise<ProfileRow[]> {
    return this.rt.registry.list().map((p) => ({
      id: p.id, kind: p.kind, environment: p.environment, classCeiling: p.classCeiling, displayName: p.displayName,
      bound: this.rt.session.getBound(p.id) !== undefined,
    }));
  }
  async usage(): Promise<string> {
    return formatUsage(usageFromAudit(await readAuditRecords(this.rt.paths.auditLog), this.rt.session.id));
  }
}
