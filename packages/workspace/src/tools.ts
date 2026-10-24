import { z } from "zod";
import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, defineTool } from "@ops/contracts";
import type { Adapter, AdapterCall, AdapterManifest, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import type { WorkspaceManager } from "./manager.ts";

const base = {
  scope: "local",
  profileKind: null,
  network: "none",
  idempotent: true,
  toolset: "workspace",
  untrustedOutput: false,
} as const;

const p = z.string().min(1).max(200);

export const fsRead = defineTool(
  {
    ...base,
    name: "fs.read",
    description: "Çalışma alanı (anlık kopya) dosyasını satır aralığıyla okur. Gizli/state/anahtar dosyaları reddedilir.",
    class: "read",
    sensitivity: "internal",
    limits: { timeoutMs: 5_000, maxBytes: 200_000, maxItems: 400, maxOutputTokens: 1_500 },
    typicalOutputTokens: 600,
  },
  z.strictObject({ path: p, startLine: z.number().int().min(1).max(1_000_000).optional(), maxLines: z.number().int().min(1).max(400).optional() }),
);

export const fsList = defineTool(
  {
    ...base,
    name: "fs.list",
    description: "Çalışma alanı dizinini listeler (depth ≤ 3). Yalnız izinli, güvenli adlı yollar görünür.",
    class: "read",
    sensitivity: "none",
    limits: { timeoutMs: 5_000, maxBytes: 100_000, maxItems: 200, maxOutputTokens: 1_000 },
    typicalOutputTokens: 300,
  },
  z.strictObject({ path: p.optional(), depth: z.number().int().min(1).max(3).optional() }),
);

export const fsWrite = defineTool(
  {
    ...base,
    name: "fs.write",
    description: "Çalışma alanındaki (anlık kopya) dosyayı oluşturur/değiştirir. CI tanımları, state, anahtar, tfvars yazılamaz; gömülü secret reddedilir.",
    class: "read",
    localWrite: true,
    idempotent: false,
    sensitivity: "none",
    limits: { timeoutMs: 5_000, maxBytes: 300_000, maxItems: 1, maxOutputTokens: 500 },
    typicalOutputTokens: 80,
  },
  z.strictObject({ path: p, content: z.string().max(262_144) }),
);

export const fsDiff = defineTool(
  {
    ...base,
    name: "fs.diff",
    description: "Anlık kopyadaki değişiklikler (özgün HEAD'e göre) ve birleşik diff.",
    class: "read",
    sensitivity: "internal",
    limits: { timeoutMs: 10_000, maxBytes: 300_000, maxItems: 100, maxOutputTokens: 1_500 },
    typicalOutputTokens: 600,
  },
  z.strictObject({ path: p.optional() }),
);

export const WORKSPACE_TOOLS: readonly ToolDefinition[] = [fsRead, fsList, fsWrite, fsDiff];

/** `fs.*` araçları: etkin çalışma alanı yoksa açık hata. Kimlik/profil kullanmaz. */
export class WorkspaceAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  private readonly manager: WorkspaceManager;

  constructor(manager: WorkspaceManager) {
    this.manager = manager;
    this.manifest = AdapterManifestSchema.parse({
      id: "workspace",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "cli",
      profileKinds: [],
      credentialKinds: [],
      capabilities: ["snapshot", "path-policy"],
      tools: WORKSPACE_TOOLS.map((t) => t.descriptor),
    });
  }

  get definitions(): readonly ToolDefinition[] {
    return WORKSPACE_TOOLS;
  }

  validateProfile(): string[] {
    return ["workspace adapter profil kullanmaz"];
  }

  resolveTarget(_t: string, _a: unknown, profile: Profile): Target {
    return { profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes: [], refs: [] };
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const cur = this.manager.current();
    if (!cur) throw new OpsError("workspace_inactive", "etkin çalışma alanı yok: `ops chat --workspace ID` ile başlatın (ops workspace add ile kaydedin)");
    const a = (call.args ?? {}) as { path?: string; startLine?: number; maxLines?: number; content?: string; depth?: number };
    const ref = (path: string): string => `File/${cur.ws.id}/${path}`;
    switch (call.tool) {
      case "fs.read": {
        const r = await cur.fs.read(a.path as string, { ...(a.startLine ? { startLine: a.startLine } : {}), ...(a.maxLines ? { maxLines: a.maxLines } : {}) });
        return {
          data: { path: r.path, totalLines: r.totalLines, startLine: r.startLine, shownLines: r.shownLines, content: r.content },
          summary: `${r.path} satır ${r.startLine}-${r.startLine + r.shownLines - 1}/${r.totalLines}`,
          truncated: r.truncated,
          subjects: [ref(r.path)],
        };
      }
      case "fs.list": {
        const r = await cur.fs.list(a.path ?? ".", a.depth ?? 1);
        return { data: r, summary: `${r.entries.length} girdi (${r.path})`, truncated: r.truncated, subjects: [`Dir/${cur.ws.id}/${r.path}`] };
      }
      case "fs.write": {
        const r = await cur.fs.write(a.path as string, a.content as string);
        return {
          data: { ...r, note: "yazıldı (anlık kopya; kullanıcının çalışma kopyasına dokunulmadı). iac.fmt/iac.validate ile doğrulayın." },
          summary: `${r.created ? "oluşturuldu" : "güncellendi"}: ${r.path} (${r.lines} satır)`,
          subjects: [ref(r.path)],
        };
      }
      case "fs.diff": {
        const r = await cur.fs.changes(a.path);
        return {
          data: { changes: r.changes, patch: r.patch.length > 12_000 ? `${r.patch.slice(0, 12_000)}\n… (kırpıldı)` : r.patch, note: r.changes.length === 0 ? "değişiklik yok" : "kullanıcı `ops workspace diff/export` ile alır" },
          summary: `${r.changes.length} dosya değişti`,
          subjects: r.changes.map((c) => ref(c.path)).slice(0, 30),
        };
      }
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    }
  }
}
