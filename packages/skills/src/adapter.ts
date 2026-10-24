import { z } from "zod";
import { ADAPTER_CONTRACT, AdapterManifestSchema, defineTool, OpsError } from "@ops/contracts";
import type { Adapter, AdapterCall, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import type { Session, ToolRegistry } from "@ops/core";
import type { SkillRegistry } from "./registry.ts";

const base = {
  class: "read",
  scope: "local",
  profileKind: null,
  sensitivity: "none",
  idempotent: true,
  untrustedOutput: false,
  toolset: "core",
} as const;
const limits = { timeoutMs: 2_000, maxBytes: 20_000, maxItems: 50, maxOutputTokens: 600 };

const listTool = defineTool(
  { ...base, name: "skill.list", description: "Kullanılabilir skill'leri ve etkin olanları listeler.", limits, typicalOutputTokens: 150 },
  z.strictObject({}),
);
const loadTool = defineTool(
  {
    ...base,
    name: "skill.load",
    description: "Skill'i yükler: yönergeleri bağlama eklenir ve ilgili araç seti açılır. En çok 2 skill etkin kalır.",
    limits,
    typicalOutputTokens: 80,
  },
  z.strictObject({ name: z.string().min(1).max(64) }),
);

/**
 * `skill.list` / `skill.load` (çekirdek araçlar). Skill YETKİ VERMEZ: yalnız talimat ekler ve araç
 * SETİNİ görünür kılar; her araç çağrısı yine PEP'ten geçer. Gövde bağlama araç sonucu olarak
 * değil, orkestratörün sistem isteminin DEĞİŞKEN SONUNA eklenir (önek kararlılığı).
 */
export function createSkillAdapter(
  skills: SkillRegistry,
  session: Session,
  toolRegistry: () => ToolRegistry,
  opts: { maxActive?: number } = {},
): { adapter: Adapter; definitions: ToolDefinition[] } {
  const definitions = [listTool, loadTool];
  const manifest = AdapterManifestSchema.parse({
    id: "skills",
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
    resolveTarget: (_t: string, _a: unknown, p: Profile): Target => ({ profileId: p.id, kind: p.kind, endpoint: p.targetPin.endpoint, scopes: [], refs: [] }),
    async invoke(call: AdapterCall): Promise<RawToolOutput> {
      if (call.tool === "skill.list") {
        return {
          data: {
            skills: skills.all().map((s) => ({ name: s.name, description: s.description, tier: s.tier, active: session.activeSkills.has(s.name) })),
          },
          summary: `${skills.all().length} skill`,
        };
      }
      if (call.tool === "skill.load") {
        const { name } = call.args as { name: string };
        const s = skills.get(name);
        if (!s) {
          throw new OpsError("skill_not_found", `skill bulunamadı: '${name.slice(0, 64)}'. Mevcut: ${skills.all().map((x) => x.name).join(", ") || "(yok)"}`);
        }
        // yalnız kayıtlı araç setleri açılır; olmayanlar sessizce düşmez, raporlanır
        const known = new Set(toolRegistry().all().map((t) => t.def.descriptor.toolset));
        const granted = s.sidecar.requests.toolsets.filter((t) => known.has(t));
        const missing = s.sidecar.requests.toolsets.filter((t) => !known.has(t));
        const evicted = session.activateSkill({ name: s.name, tier: s.tier, body: s.body, tokens: s.tokens, toolsets: granted }, opts.maxActive ?? 2);
        return {
          data: { loaded: s.name, tier: s.tier, tokens: s.tokens, toolsets: granted, ...(missing.length ? { toolsetsMissing: missing } : {}), ...(evicted.length ? { evicted } : {}) },
          summary: `skill '${s.name}' yüklendi (${s.tokens} token)`,
          ...(s.tier === "imported" ? { taint: "untrusted" as const } : {}),
        };
      }
      throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    },
  };
  return { adapter, definitions };
}
