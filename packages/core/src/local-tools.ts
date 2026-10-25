import { z } from "zod";
import { ADAPTER_CONTRACT, AdapterManifestSchema, defineTool, OpsError } from "@ops/contracts";
import type { Adapter, AdapterCall, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import { openToModel } from "./evidence.ts";
import type { EvidenceStore } from "./evidence.ts";
import { buildTimeline } from "./timeline.ts";

const limits = { timeoutMs: 5000, maxBytes: 200_000, maxItems: 200, maxOutputTokens: 1500 };

const base = {
  class: "read",
  scope: "local",
  profileKind: null,
  sensitivity: "none",
  idempotent: true,
  limits,
  untrustedOutput: false, // taint, kanıtın kendisinden miras alınır (RawToolOutput.taint)
  toolset: "core",
  typicalOutputTokens: 600,
} as const;

const getTool = defineTool(
  {
    ...base,
    name: "evidence.get",
    description:
      "Kanıtı id ile getirir; büyük sonuçlar için select (alan yolları), offset ve limit ile dilimleyin.",
  },
  z.strictObject({
    id: z.string().regex(/^ev-\d+$/),
    select: z.array(z.string().min(1).max(100)).max(20).optional(),
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(1).max(200).optional(),
  }),
);

const searchTool = defineTool(
  {
    ...base,
    name: "evidence.search",
    description: "Oturumdaki kanıtlarda metin arar; eşleşen kanıt kimliklerini döndürür.",
  },
  z.strictObject({ query: z.string().min(1).max(200), limit: z.number().int().min(1).max(20).optional() }),
);

const ISO = /^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})$/;

const timelineTool = defineTool(
  {
    ...base,
    name: "timeline.build",
    description:
      "Kanıtlardan tek zaman çizelgesi; imaj özeti, commit SHA, koşu kimliğiyle deterministik bağ. Serbest metin içermez.",
    typicalOutputTokens: 900,
  },
  z.strictObject({
    evidence: z.array(z.string().regex(/^ev-\d+$/)).max(30).optional(),
    from: z.string().regex(ISO).optional(),
    to: z.string().regex(ISO).optional(),
    limit: z.number().int().min(1).max(100).optional(),
  }),
);

/** Çekirdek yerel araçlar (kimliksiz): kanıt deposu okuma. Bunlar da PEP boru hattından geçer. */
export function createLocalAdapter(evidence: EvidenceStore): { adapter: Adapter; definitions: ToolDefinition[] } {
  const definitions = [getTool, searchTool, timelineTool];
  const manifest = AdapterManifestSchema.parse({
    id: "core-local",
    version: "0.0.0",
    contract: ADAPTER_CONTRACT,
    kind: "cli",
    profileKinds: [],
    credentialKinds: [],
    capabilities: [],
    tools: definitions.map((d) => d.descriptor),
  });

  const adapter: Adapter = {
    manifest,
    validateProfile: () => ["yerel adapter profil kullanmaz"],
    resolveTarget: (_t: string, _a: unknown, p: Profile): Target => ({
      profileId: p.id,
      kind: p.kind,
      endpoint: p.targetPin.endpoint,
      scopes: [],
      refs: [],
    }),
    async invoke(call: AdapterCall): Promise<RawToolOutput> {
      if (call.tool === "evidence.get") {
        const a = call.args as { id: string; select?: string[]; offset?: number; limit?: number };
        const e = evidence.get(a.id);
        if (!e) throw new OpsError("evidence_not_found", `kanıt bulunamadı: ${a.id}`);
        if (!openToModel(e)) throw new OpsError("quarantined", `${a.id} karantinada: ham içerik modele verilmez (tipli özet zaten bağlamda). Kullanıcı /show ile görebilir, /raw ile açabilir`);
        const s = evidence.slice(a.id, {
          ...(a.select ? { select: a.select } : {}),
          ...(a.offset !== undefined ? { offset: a.offset } : {}),
          ...(a.limit !== undefined ? { limit: a.limit } : {}),
        });
        return {
          data: { id: e.id, tool: e.tool, observedAt: e.observedAt, total: s?.total, shown: s?.shown, offset: s?.offset, data: s?.data },
          summary: `${e.id} dilimi (${e.tool})`,
          sensitivity: e.sensitivity,
          taint: e.taint,
          subjects: [...e.subjects],
        };
      }
      if (call.tool === "evidence.search") {
        const a = call.args as { query: string; limit?: number };
        const hits = evidence.search(a.query, a.limit ?? 10);
        const touched = hits.map((h) => evidence.get(h.id)).filter((x) => x !== undefined);
        const maxSens = touched.reduce<"none" | "internal" | "pii" | "secret-adjacent">(
          (acc, e) => (["none", "internal", "pii", "secret-adjacent"].indexOf(e.sensitivity) > ["none", "internal", "pii", "secret-adjacent"].indexOf(acc) ? e.sensitivity : acc),
          "none",
        );
        return {
          data: hits,
          summary: `${hits.length} eşleşme`,
          sensitivity: maxSens,
          // yalnız modele AÇIK untrusted içerik bağlamı kirletir (karantinadakilerden salt kimlik/özet döner)
          ...(touched.some((e) => e.taint === "untrusted" && openToModel(e)) ? { taint: "untrusted" as const } : {}),
        };
      }
      if (call.tool === "timeline.build") {
        const a = call.args as { evidence?: string[]; from?: string; to?: string; limit?: number };
        const used = a.evidence
          ? a.evidence.map((id) => {
              const e = evidence.get(id);
              if (!e) throw new OpsError("evidence_not_found", `kanıt bulunamadı: ${id}`);
              return e;
            })
          : evidence.all().filter((e) => !e.tool.startsWith("evidence.") && e.tool !== "timeline.build").slice(-30);
        const { timeline, sensitivity } = buildTimeline(used, { ...(a.from ? { from: a.from } : {}), ...(a.to ? { to: a.to } : {}), ...(a.limit ? { limit: a.limit } : {}) });
        return {
          data: timeline,
          summary: `${timeline.events.length} olay, ${timeline.links.length} anahtar bağı (${used.length} kanıt)`,
          sensitivity,
          subjects: [...new Set(used.flatMap((e) => [...e.subjects]))].slice(0, 60),
        };
      }
      throw new OpsError("unknown_tool", `bilinmeyen yerel araç: ${call.tool}`);
    },
  };
  return { adapter, definitions };
}
