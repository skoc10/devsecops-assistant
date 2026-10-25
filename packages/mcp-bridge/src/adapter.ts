import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, defineTool } from "@ops/contracts";
import type { Adapter, AdapterCall, AdapterManifest, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { fsOf } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { McpProtocolError, McpSession } from "./client.ts";
import { buildInputSchema, mcpToolName, roBindProblem, toolsetOf } from "./manifest.ts";
import type { McpManifest, McpServerSpec, McpToolSpec } from "./manifest.ts";

export const MCP_HOME = "/home/ops-mcp";

export interface McpBridgeOptions {
  readonly manifest: McpManifest;
  readonly sandbox: Sandbox | null;
  /** Ağ açık sunucularda argümanlardaki secret'ları yakalamak için (M2/M3). */
  readonly known?: KnownSecrets;
}

export interface McpCheckReport {
  readonly server: string;
  readonly ok: boolean;
  readonly protocolVersion?: string;
  readonly serverName?: string;
  /** Manifestte olup sunucuda bulunmayan araçlar. */
  readonly missing: string[];
  /** Sunucunun sunduğu ama manifestte OLMAYAN araç sayısı (bunlar asla modele açılmaz). */
  readonly undeclared: number;
  readonly error?: string;
}

interface Entry {
  readonly server: McpServerSpec;
  readonly tool: McpToolSpec;
}

/**
 * MCP istemci köprüsü v0: kullanıcı manifestinde sarılmış, `read` sınıflı dış MCP araçlarını PEP
 * altında sunar. Her çağrı: ikili/dosya pini yeniden doğrulanır → OS sandbox içinde süreç başlar
 * (temiz env, boş ev dizini, ağ yok) → initialize → tools/list (araç var mı?) → tools/call → süreç
 * öldürülür. Çıktı HER ZAMAN untrusted'dır (üçüncü taraf metin).
 */
export class McpBridgeAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  readonly definitions: readonly ToolDefinition[];
  private readonly o: McpBridgeOptions;
  private readonly byTool = new Map<string, Entry>();
  private readonly servers = new Map<string, McpServerSpec>();

  constructor(opts: McpBridgeOptions) {
    this.o = opts;
    const defs: ToolDefinition[] = [];
    for (const s of opts.manifest.servers) {
      this.servers.set(s.id, s);
      for (const t of s.tools) {
        const name = mcpToolName(s.id, t.name);
        this.byTool.set(name, { server: s, tool: t });
        defs.push(
          defineTool(
            {
              name,
              description: `[mcp:${s.id}] ${t.description}`.slice(0, 400),
              class: t.class,
              scope: "local",
              profileKind: null,
              network: s.network === "host" ? "open" : "none",
              sensitivity: t.sensitivity,
              idempotent: false,
              limits: { timeoutMs: s.timeoutMs, maxBytes: s.maxOutputBytes, maxItems: 100, maxOutputTokens: t.maxOutputTokens },
              untrustedOutput: true,
              toolset: toolsetOf(s),
              typicalOutputTokens: t.typicalOutputTokens,
            },
            buildInputSchema(t),
          ),
        );
      }
    }
    this.definitions = defs;
    this.manifest = AdapterManifestSchema.parse({
      id: "mcp-bridge",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "cli",
      profileKinds: [],
      credentialKinds: [],
      capabilities: ["sandboxed-exec", "pinned-binary", "read-only"],
      tools: defs.map((d) => d.descriptor),
    });
  }

  validateProfile(): string[] {
    return ["mcp-bridge profil kullanmaz"];
  }

  resolveTarget(_t: string, _a: unknown, profile: Profile): Target {
    return { profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes: [], refs: [] };
  }

  /**
   * Sunucu ikilisi ve ek dosyaları pinli sha256 ile eşleşmeli; aksi halde ÇALIŞTIRILMAZ. Özet, sandbox'ın İKİLİ
   * dosya sisteminden alınır (VM'de konuk: çalışacak dosya host'taki değil, konuktakidir).
   */
  private async verifyPins(s: McpServerSpec): Promise<void> {
    const fs = fsOf(this.o.sandbox);
    const check = async (path: string, want: string, label: string): Promise<void> => {
      const got = await fs.sha256(path);
      if (got === null) throw new OpsError("mcp_pin_mismatch", `${label} okunamadı: ${path}`);
      if (got !== want) throw new OpsError("mcp_pin_mismatch", `${label} sha256 pini uyuşmuyor (${path}): sunucu ÇALIŞTIRILMADI`);
    };
    await check(s.command, s.sha256, "sunucu ikilisi");
    for (const f of s.files) await check(f.path, f.sha256, "sunucu dosyası");
  }

  private async open(s: McpServerSpec, signal?: AbortSignal): Promise<McpSession> {
    const sb = this.o.sandbox;
    if (!sb || sb.kind === "none") throw new OpsError("sandbox_required", "MCP sunucuları yalnız OS sandbox içinde çalışır (bubblewrap/seatbelt)");
    // Manifest doğrulaması bunu zaten reddeder; şemayı atlayarak kurulan adapter için ikinci savunma hattı
    for (const b of s.roBinds) {
      const why = roBindProblem(b);
      if (why) throw new OpsError("mcp_bind_denied", `salt-okunur bağ reddedildi (${why}): ${b.slice(0, 120)}`);
    }
    await this.verifyPins(s);
    const proc = await sb.spawn({
      argv: [s.command, ...s.args],
      env: { LC_ALL: "C.UTF-8", NO_COLOR: "1", ...s.env },
      roBinds: [s.command, ...s.files.map((f) => f.path), ...s.roBinds],
      network: s.network,
      home: MCP_HOME,
      cwd: MCP_HOME,
      timeoutMs: s.timeoutMs + 2_000,
      maxOutputBytes: s.maxOutputBytes,
    });
    return new McpSession(proc, { timeoutMs: s.timeoutMs, maxTotalBytes: s.maxOutputBytes, ...(signal ? { signal } : {}) });
  }

  /** `ops mcp check`: sunucu başlar, el sıkışır, araç adlarını manifestle karşılaştırır. Araç ÇAĞIRMAZ. */
  async check(serverId: string): Promise<McpCheckReport> {
    const s = this.servers.get(serverId);
    if (!s) throw new OpsError("mcp_server_unknown", `manifestte sunucu yok: ${serverId}`);
    let session: McpSession | undefined;
    try {
      session = await this.open(s);
      await session.initialize();
      const listing = await session.listTools();
      const have = new Set(listing.names);
      const declared = s.tools.map((t) => t.name);
      return {
        server: s.id,
        ok: declared.every((n) => have.has(n)),
        protocolVersion: session.protocolVersion,
        serverName: session.serverName,
        missing: declared.filter((n) => !have.has(n)),
        undeclared: listing.names.filter((n) => !declared.includes(n)).length,
      };
    } catch (e) {
      if (e instanceof OpsError && e.code === "sandbox_required") throw e;
      return { server: s.id, ok: false, missing: [], undeclared: 0, error: e instanceof Error ? e.message.slice(0, 200) : "?" };
    } finally {
      session?.close();
    }
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const entry = this.byTool.get(call.tool);
    if (!entry) throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    const { server, tool } = entry;
    const args = (call.args ?? {}) as Record<string, unknown>;

    if (server.network === "host") {
      // kısıtsız ağ = veri çıkış kanalı: argümanlar secret içeremez (M2/M3)
      const json = JSON.stringify(args);
      if (scrubText(json, this.o.known ?? new KnownSecrets()) !== json) {
        throw new OpsError("secret_in_args", "ağ erişimli MCP aracının argümanlarında secret benzeri değer var: çağrı reddedildi");
      }
    }

    let session: McpSession | undefined;
    try {
      session = await this.open(server, call.signal);
      await session.initialize();
      const listing = await session.listTools();
      if (!listing.names.includes(tool.name)) throw new OpsError("mcp_tool_missing", `sunucu '${server.id}' manifestteki '${tool.name}' aracını sunmuyor`);
      const r = await session.callTool(tool.name, args);
      const refused = session.serverRequests;
      return {
        data: {
          server: server.id,
          tool: tool.name,
          protocol: session.protocolVersion,
          isError: r.isError,
          content: r.texts,
          ...(r.structured !== undefined ? { structured: r.structured } : {}),
          ...(r.resourceLinks.length ? { resourceLinks: r.resourceLinks } : {}),
          ...(r.droppedBlocks ? { droppedBlocks: r.droppedBlocks } : {}),
          ...(refused ? { refusedServerRequests: refused } : {}),
        },
        summary: `mcp:${server.id}/${tool.name}: ${r.texts.length} metin bloğu${r.isError ? " (sunucu hata bildirdi)" : ""}${r.structured !== undefined ? ", yapısal içerik var" : ""}`,
        truncated: r.truncated,
        subjects: [`McpServer/${server.id}`],
        sensitivity: tool.sensitivity,
        taint: "untrusted",
      };
    } catch (e) {
      if (e instanceof McpProtocolError) {
        const hint = session?.stderrSnippet ? ` [stderr: ${session.stderrSnippet}]` : "";
        throw new OpsError(e.code, `${e.message}${e.code === "mcp_server_exited" ? hint : ""}`.slice(0, 300));
      }
      throw e;
    } finally {
      session?.close();
    }
  }
}
