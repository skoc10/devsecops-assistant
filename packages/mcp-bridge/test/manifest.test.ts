import { homedir } from "node:os";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import type { AdapterCall } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import { McpBridgeAdapter, McpManifestError, buildInputSchema, mcpToolName, parseMcpManifest, roBindProblem } from "../src/index.ts";

const SHA = "a".repeat(64);
const base = (extra = "", tool = ""): string => `
servers:
  - id: tfdocs
    command: /opt/mcp/terraform-mcp-server
    sha256: ${SHA}
    args: [stdio]
    ${extra}
    tools:
      - name: search_providers
        description: Sağlayıcı arar.
        args:
          query: { type: string, required: true, maxLength: 80 }
          limit: { type: integer, min: 1, max: 20 }
        ${tool}
`;

describe("parseMcpManifest", () => {
  it("geçerli manifest: varsayılanlar (read, internal, ağ yok, toolset mcp-<id>)", () => {
    const m = parseMcpManifest(base());
    const s = m.servers[0]!;
    expect(s).toMatchObject({ id: "tfdocs", network: "none", timeoutMs: 30_000, files: [], env: {}, roBinds: [] });
    expect(s.tools[0]).toMatchObject({ name: "search_providers", class: "read", sensitivity: "internal", maxOutputTokens: 1500 });
    expect(mcpToolName("tfdocs", "search-providers")).toBe("mcp.tfdocs.search_providers");
  });

  const bad: [string, string, RegExp][] = [
    ["göreli komut", base().replace("/opt/mcp/terraform-mcp-server", "bin/server"), /mutlak yol/],
    ["'..' içeren yol", base().replace("/opt/mcp/terraform-mcp-server", "/opt/../bin/x"), /mutlak yol/],
    ["bozuk sha256", base().replace(SHA, "xyz"), /sha256/],
    ["pinsiz sunucu", base().replace(`sha256: ${SHA}`, ""), /sha256/],
    ["read dışı sınıf (v0)", base("", "class: mutate"), /yalnız 'read'/],
    ["ağ=host onaysız", base("network: host"), /acknowledgeUnrestrictedNetwork/],
    ["secret benzeri ortam adı", base("env: { API_TOKEN: x }"), /kimlik\/secret/],
    ["bilinmeyen alan (strict)", base("surprise: 1"), /surprise|Unrecognized/i],
    ["bozuk düzenli ifade", base().replace("maxLength: 80", "maxLength: 80, pattern: '('"), /düzenli ifade/],
    ["geçersiz araç adı", base().replace("search_providers", "bad name"), /name/],
  ];
  for (const [label, text, re] of bad) {
    it(`reddeder: ${label}`, () => {
      expect(() => parseMcpManifest(text), label).toThrow(McpManifestError);
      expect(() => parseMcpManifest(text)).toThrow(re);
    });
  }

  it("yinelenen sunucu kimliği ve yinelenen araç adı (- ve _ aynı ada iner) reddedilir", () => {
    const two = `servers:\n  - id: a\n    command: /x/a\n    sha256: ${SHA}\n    tools: [{ name: t, description: d }]\n  - id: a\n    command: /x/b\n    sha256: ${SHA}\n    tools: [{ name: t, description: d }]\n`;
    expect(() => parseMcpManifest(two)).toThrow(/yinelenen sunucu/);
    const dup = `servers:\n  - id: a\n    command: /x/a\n    sha256: ${SHA}\n    tools: [{ name: get-x, description: d }, { name: get_x, description: d }]\n`;
    expect(() => parseMcpManifest(dup)).toThrow(/yinelenen araç adı/);
  });

  it("sha256 değeri YAML'da sayıya benzese de (000…0, 12e3…) özgün metin olarak okunur — pin sessizce bozulmaz", () => {
    const allDigits = "0".repeat(64);
    const expLike = "1234e" + "5".repeat(59);
    for (const h of [allDigits, expLike]) {
      const m = parseMcpManifest(base().replace(SHA, h));
      expect(m.servers[0]!.sha256).toBe(h);
    }
  });

  it("YAML takma adı (alias), yinelenen anahtar ve aşırı büyük manifest reddedilir", () => {
    const alias = `servers:\n  - id: a\n    command: /x/a\n    sha256: &h ${SHA}\n    files: [{ path: /x/f, sha256: *h }]\n    tools: [{ name: t, description: d }]\n`;
    expect(() => parseMcpManifest(alias)).toThrow(McpManifestError);
    expect(() => parseMcpManifest("servers: []\nservers: []\n")).toThrow(McpManifestError);
    expect(() => parseMcpManifest("x: " + "a".repeat(70_000))).toThrow(/çok büyük/);
  });
});

describe("roBinds: kimlik/secret/IPC konumları bağlanamaz (network: host sunucusu okuyup dışarı taşıyabilirdi)", () => {
  const H = homedir();
  const withBinds = (binds: readonly string[]): string => base(`roBinds: [${binds.map((b) => JSON.stringify(b)).join(", ")}]`);

  it("reddeder: kök, ev dizini ve ataları, kimlik dizinleri (harfe duyarsız) ve ataları, ürün durum dizini, IPC/soket konumları", () => {
    const bad = [
      "/",
      H,
      `${H}/`,
      dirname(H),
      `${H}/.ssh`,
      `${H}/.SSH/id_ed25519`,
      `${H}/.aws/credentials`,
      `${H}/.kube/config`,
      `${H}/.docker`,
      `${H}/.gnupg`,
      `${H}/.config`,
      `${H}/.config/gcloud`,
      `${H}/.Azure`,
      `${H}/Library`,
      `${H}/library/keychains/login.keychain-db`,
      `${H}/.ops-assistant`,
      `${H}/.ops-assistant/vault/vault.json`,
      "/root/.ssh",
      "/srv/x/.aws",
      "/Library/Keychains",
      "/var/run/docker.sock",
      "/run/user/1000",
      "/var",
      "/proc",
      "/proc/1/environ",
      "/tmp",
      "/private/tmp/com.apple.launchd.x/Listeners",
      "/dev",
      `${H}/.colima/default/docker.sock`,
      "/opt/x/agent.socket",
    ];
    for (const b of bad) {
      expect(() => parseMcpManifest(withBinds([b])), b).toThrow(McpManifestError);
      expect(() => parseMcpManifest(withBinds([b])), b).toThrow(/roBinds\.0: salt-okunur bağ reddedildi/);
    }
  });

  it("izin verir: kurulum önekleri ve ev dizini altındaki kimlik dışı yollar", () => {
    const ok = ["/opt/node", "/usr/local/lib/node_modules", `${H}/.nvm/versions/node/v22.0.0`, "/etc/ssl/certs", `${H}/tools/bin`];
    expect(parseMcpManifest(withBinds(ok)).servers[0]!.roBinds).toEqual(ok);
  });

  it("OPS_HOME (ve ataları) reddedilir; sembolik bağın gerçek yolu da denetlenir; NFKC katlama", () => {
    const ctx = { home: "/home/u", opsHome: "/srv/ops-state" };
    expect(roBindProblem("/srv/ops-state/vault", ctx)).toMatch(/ürün durum/);
    expect(roBindProblem("/srv", ctx)).toMatch(/ürün durum/);
    expect(roBindProblem("/srv/other", ctx)).toBeNull();
    const links: Record<string, string> = { "/opt/innocent": "/home/u/.ssh", "/opt/home-link": "/home/u" };
    const linked = { home: "/home/u", realpath: (p: string): string | undefined => links[p] };
    expect(roBindProblem("/opt/innocent", linked)).toMatch(/kimlik/);
    expect(roBindProblem("/opt/home-link", linked)).toMatch(/ev dizini/);
    expect(roBindProblem("/opt/plain", linked)).toBeNull();
    expect(roBindProblem("/home/u/.ſsh", { home: "/home/u" })).not.toBeNull(); // ſ → s (harfe duyarsız dosya sisteminde .ssh)
    const prev = process.env["OPS_HOME"];
    process.env["OPS_HOME"] = "/srv/ops-manifest-test";
    try {
      expect(() => parseMcpManifest(withBinds(["/srv/ops-manifest-test/audit"]))).toThrow(/ürün durum/);
    } finally {
      if (prev === undefined) delete process.env["OPS_HOME"];
      else process.env["OPS_HOME"] = prev;
    }
  });

  it("şemayı atlayan manifestte de adapter bağlamadan önce reddeder; sunucu hiç başlamaz", async () => {
    const m = parseMcpManifest(base());
    const manifest = { servers: [{ ...m.servers[0]!, roBinds: [`${H}/.aws`] }] };
    let spawned = 0;
    const never = async (): Promise<never> => {
      spawned++;
      throw new Error("sunucu başlamamalıydı");
    };
    const sandbox: Sandbox = { kind: "bwrap", run: never, spawn: never };
    const a = new McpBridgeAdapter({ manifest, sandbox });
    await expect(a.invoke({ tool: "mcp.tfdocs.search_providers", args: { query: "x" } } as unknown as AdapterCall)).rejects.toMatchObject({ code: "mcp_bind_denied" });
    expect(spawned).toBe(0);
  });
});

describe("buildInputSchema: modelin argümanları sıkı doğrulanır", () => {
  const tool = parseMcpManifest(
    base("", "").replace("limit: { type: integer, min: 1, max: 20 }", "limit: { type: integer, min: 1, max: 20 }\n          mode: { type: string, enum: [a, b] }\n          deep: { type: boolean }"),
  ).servers[0]!.tools[0]!;
  const z = buildInputSchema(tool);

  it("geçerli girdi", () => {
    expect(z.safeParse({ query: "aws", limit: 5, mode: "a", deep: true }).success).toBe(true);
    expect(z.safeParse({ query: "aws" }).success).toBe(true);
  });
  it("zorunlu alan, tür, sınır, enum, fazladan alan, kontrol karakteri", () => {
    for (const bad of [{}, { query: 1 }, { query: "x".repeat(81) }, { query: "a", limit: 0 }, { query: "a", limit: 21 }, { query: "a", limit: 1.5 }, { query: "a", mode: "c" }, { query: "a", extra: 1 }, { query: "a\u0000b" }, { query: "a\u001b[31m" }]) {
      expect(z.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("McpBridgeAdapter: araç tanımları", () => {
  it("her araç read/local/untrusted; ağ eşlemesi; toolset", () => {
    const none = new McpBridgeAdapter({ manifest: parseMcpManifest(base()), sandbox: null });
    const d = none.definitions[0]!.descriptor;
    expect(d).toMatchObject({ name: "mcp.tfdocs.search_providers", class: "read", scope: "local", profileKind: null, network: "none", untrustedOutput: true, toolset: "mcp-tfdocs", localWrite: false });
    expect(d.description).toMatch(/^\[mcp:tfdocs\]/);
    expect(d.inputSchema["additionalProperties"]).toBe(false);

    const host = new McpBridgeAdapter({ manifest: parseMcpManifest(base("network: host\n    acknowledgeUnrestrictedNetwork: true")), sandbox: null });
    expect(host.definitions[0]!.descriptor.network).toBe("open");
  });

  it("sunucunun kendi açıklaması/şeması/annotation'ı manifeste hiç girmez (yalnız bizim metnimiz)", () => {
    const a = new McpBridgeAdapter({ manifest: parseMcpManifest(base()), sandbox: null });
    expect(JSON.stringify(a.manifest)).not.toMatch(/readOnlyHint|destructiveHint/);
    expect(a.definitions[0]!.descriptor.description).toContain("Sağlayıcı arar.");
  });
});
