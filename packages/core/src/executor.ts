import { randomUUID } from "node:crypto";
import type { AuditSink, ToolResult, TrustZone } from "@ops/contracts";
import type { ToolGateway } from "./gateway.ts";
import type { ToolRegistry } from "./registry.ts";
import type { Session } from "./session.ts";

export interface ExecutorDeps {
  readonly gateway: ToolGateway;
  readonly registry: ToolRegistry;
  readonly session: Session;
  readonly audit: AuditSink;
  readonly provider: { readonly id: string; readonly model: string };
  readonly zone: TrustZone;
}

export function synthDenied(tool: string, reasonCode: string, summary: string): ToolResult {
  return {
    callId: randomUUID(),
    tool,
    status: "denied",
    summary,
    byReference: false,
    truncated: false,
    redactions: [],
    provenance: { source: "orchestrator", observedAt: new Date().toISOString() },
    sensitivity: "none",
    taint: "trusted",
    subjects: [],
    tokens: { estimate: 0 },
    reasonCode,
  };
}

/**
 * Model/ajan kaynaklı TEK araç çağrısını PEP'e iletir. İki orkestratör (host döngüsü ve
 * sağlayıcı döngüsü/Cursor köprüsü) AYNI yolu kullanır:
 *  - etkin olmayan araç seti → ret (token ekonomisi + modelin görmediği aracı çağıramaması),
 *  - kimlikli araç → tür başına bağlı TEK profil enjekte edilir; yoksa ret,
 *  - sonra `ToolGateway.invoke` (şema → ... → egress).
 */
export class ToolExecutor {
  private readonly d: ExecutorDeps;
  constructor(deps: ExecutorDeps) {
    this.d = deps;
  }

  async execute(call: { id: string; name: string; args: unknown }, signal?: AbortSignal, nested?: { parentCallId: string }): Promise<ToolResult> {
    const { gateway, registry, session, audit } = this.d;
    const reg = registry.get(call.name);
    let profileId: string | undefined;
    let args = call.args;
    let cited: string[] | undefined;
    if (reg) {
      const desc = reg.def.descriptor;
      // mutasyon+ araçlarda ayrılmış `cited` alanı şemadan ÖNCE ayrılır (model kanıt kimliklerini böyle bildirir)
      if (desc.class !== "read" && args !== null && typeof args === "object" && !Array.isArray(args) && "cited" in args) {
        const { cited: c, ...rest } = args as Record<string, unknown>;
        if (!Array.isArray(c) || c.length > 10 || !c.every((x) => typeof x === "string" && /^ev-\d+$/.test(x))) {
          return synthDenied(call.name, "schema_invalid", "cited: en çok 10 kanıt kimliği (ev-N) dizisi olmalı");
        }
        cited = c as string[];
        args = rest;
      }
      if (!session.activeToolsets.has(desc.toolset)) {
        await audit
          .append({ event: "intent", sessionId: session.id, callId: call.id, tool: call.name, decision: "deny", reasonCode: "unknown_tool", message: "araç seti etkin değil" })
          .catch(() => undefined);
        return synthDenied(call.name, "unknown_tool", `araç seti etkin değil ('${desc.toolset}'): önce ilgili skill'i skill.load ile yükleyin`);
      }
      if (desc.profileKind !== null) {
        const p = session.boundByKind(desc.profileKind);
        if (!p) {
          await audit
            .append({ event: "intent", sessionId: session.id, callId: call.id, tool: call.name, decision: "deny", reasonCode: "profile_not_bound", message: `'${desc.profileKind}' profili bağlı değil` })
            .catch(() => undefined);
          return synthDenied(call.name, "profile_not_bound", `'${desc.profileKind}' türünde bağlı profil yok: kullanıcı /use ile bir profil bağlamalı`);
        }
        profileId = p.id;
      }
    }
    return gateway.invoke({
      tool: call.name,
      args,
      ...(cited ? { citedEvidence: cited } : {}),
      ...(profileId ? { profile: profileId } : {}),
      providerZone: this.d.zone,
      provider: this.d.provider,
      ...(signal ? { signal } : {}),
      ...(nested ? { parentCallId: nested.parentCallId } : {}),
    });
  }
}
