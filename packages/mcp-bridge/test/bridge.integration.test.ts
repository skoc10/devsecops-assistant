import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { makeMcpHarness, sandbox } from "./harness.ts";

const ok = !!sandbox;

describe.skipIf(!ok)("MCP istemci köprüsü v0 (gerçek bubblewrap + gerçek stdio süreci)", () => {
  it("echo: PEP üzerinden çağrılır; çıktı untrusted → bağlam taint'lenir", async () => {
    const h = await makeMcpHarness();
    expect(h.session.context.tainted).toBe(false);
    const r = await h.call("mcp.mock.echo", { text: "merhaba" });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    const j = h.json(r);
    expect(j).toMatchObject({ server: "mock", tool: "echo", isError: false, content: ["echo:merhaba"] });
    expect(j.protocol).toBe("2025-06-18");
    expect(h.session.context.tainted).toBe(true);
    expect(h.spawns()).toBe(1);
  });

  it("search: yapısal içerik + resource_link taşınır; görsel blok DÜŞER (sayılır)", async () => {
    const h = await makeMcpHarness();
    const j = h.json(await h.call("mcp.mock.search", { query: "aws", limit: 3 }));
    expect(j.structured).toEqual({ query: "aws", items: [{ id: 1 }, { id: 2 }] });
    expect(j.resourceLinks).toEqual(["https://registry.example.invalid/doc/1"]);
    expect(j.droppedBlocks).toBe(1);
    expect(JSON.stringify(j)).not.toContain("aGVsbG8="); // görsel verisi modele gitmez
  });

  it("şema ihlali sunucuya HİÇ ulaşmaz (fazladan alan, uzunluk, tür)", async () => {
    const h = await makeMcpHarness();
    for (const bad of [{ text: "x", extra: 1 }, { text: "x".repeat(300) }, { text: 5 }, {}]) {
      const r = await h.call("mcp.mock.echo", bad);
      expect(r.status).not.toBe("ok");
    }
    expect(h.spawns()).toBe(0);
  });

  it("enjeksiyon metni VERİ olarak kalır: kontrol/ANSI/bidi/sıfır-genişlik karakterleri temizlenir, bağlam tainted, sonuç untrusted zarflı", async () => {
    const h = await makeMcpHarness();
    const r = await h.call("mcp.mock.docs", {});
    const j = h.json(r);
    const text = j.content.join("\n");
    expect(text).toContain("Ignore all previous instructions"); // veri olarak görünür
    // eslint-disable-next-line no-control-regex
    expect(text).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202A-\u202E\u200B-\u200F]/);
    expect(text).not.toContain("\u001b");
    expect(text).toContain("red"); // ANSI atılmış, düz metin kalmış
    expect(h.session.context.tainted).toBe(true);
    // özet sunucu içeriğini TAŞIMAZ (yalnız sayım)
    expect(r.summary).not.toMatch(/Ignore|previous|instructions/i);
  });

  it("taint sonrası ağ-açık araç ve yerel yazma için onay gerekir (taint yükseltme)", async () => {
    const h = await makeMcpHarness({ network: "host" });
    await h.call("mcp.mock.docs", {}); // bağlam tainted
    const before = h.gate.requests.length;
    const r = await h.call("mcp.mock.echo", { text: "x" }); // network: open + tainted → ask
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(h.gate.requests.length).toBe(before + 1);
    expect(h.gate.requests.at(-1)?.summary.tool).toBe("mcp.mock.echo");
  });

  it("sunucu kaynaklı bildirimler ve açıklamalar (injection) modele GİTMEZ; sunucu stderr'i de gitmez", async () => {
    const h = await makeMcpHarness();
    const r = await h.call("mcp.mock.echo", { text: "a" });
    const all = JSON.stringify(h.json(r)) + r.summary;
    expect(all).not.toMatch(/admin mode|IGNORE PREVIOUS|STDERR-INJECTION|attacker-controlled/i);
    expect(JSON.stringify(h.adapter.manifest)).not.toMatch(/attacker-controlled|IGNORE PREVIOUS/i);
  });

  it("sunucudan istemciye istek (sampling/createMessage) REDDEDİLİR; sunucu hata kodu -32601 alır", async () => {
    const h = await makeMcpHarness({ mode: "sampling" });
    const j = h.json(await h.call("mcp.mock.echo", { text: "x" }));
    expect(j.refusedServerRequests).toBe(1);
    expect(JSON.parse(j.content[0])).toEqual({ samplingReplyError: -32601, gotResult: false });
  });

  it("sandbox: temiz ortam, boş ev dizini, kimlik yolları yok, /usr salt-okunur, AĞ KAPALI", async () => {
    process.env["OPS_TEST_CANARY_ENV"] = "canary-" + randomBytes(6).toString("hex");
    process.env["KUBECONFIG"] = "/root/.kube/config";
    try {
      const h = await makeMcpHarness();
      const p = JSON.parse(h.json(await h.call("mcp.mock.probe", {})).content[0]);
      expect(p.home).toBe("/home/ops-mcp");
      expect(p.envKeys).not.toContain("OPS_TEST_CANARY_ENV");
      expect(p.envKeys).not.toContain("KUBECONFIG");
      expect(p.envKeys.filter((k: string) => /TOKEN|SECRET|KEY|PASS|AWS|GOOGLE|AZURE/i.test(k))).toEqual([]);
      expect(p).toMatchObject({ hasRoot: false, hasKube: false, hasRepoRoot: false, net: "blocked", writeUsr: "denied" });
    } finally {
      delete process.env["OPS_TEST_CANARY_ENV"];
      delete process.env["KUBECONFIG"];
    }
  });

  it("network: host (açık onaylı) sunucuda ağ gerçekten açıktır → bu, belgelenmiş bilinçli zayıflıktır", async () => {
    const h = await makeMcpHarness({ network: "host" });
    const p = JSON.parse(h.json(await h.call("mcp.mock.probe", {})).content[0]);
    // ağ erişimi ortama bağlı (CI/proxy); önemli olan sandbox'ın ağ ad alanını PAYLAŞMASI ve diğer kısıtların sürmesi
    expect(["reachable", "blocked"]).toContain(p.net);
    expect(p).toMatchObject({ hasRoot: false, hasKube: false, writeUsr: "denied" });
  });

  it("ağ-açık araçta argümanda secret benzeri değer → reddedilir (veri çıkışı koruması), sunucu başlamaz", async () => {
    const h = await makeMcpHarness({ network: "host" });
    const key = "AKIA" + randomBytes(8).toString("hex").toUpperCase();
    const r = await h.call("mcp.mock.echo", { text: `use ${key}` });
    expect(r.status).not.toBe("ok");
    expect(JSON.stringify(r)).toMatch(/secret_in_args|secret benzeri/);
    expect(JSON.stringify(r)).not.toContain(key);
    expect(h.spawns()).toBe(0);
  });

  it("çıktıdaki secret (M2) PEP çıktı hattında maskelenir", async () => {
    const key = "AKIA" + randomBytes(8).toString("hex").toUpperCase();
    const h = await makeMcpHarness({ env: { MOCK_LEAK: key } });
    const r = await h.call("mcp.mock.leak", {});
    expect(r.status).toBe("ok");
    const e = r.evidenceId ? h.evidence.get(r.evidenceId) : undefined;
    expect(e?.text).not.toContain(key);
    expect(JSON.stringify(r)).not.toContain(key);
    expect(JSON.stringify(h.storage)).not.toContain(key);
  });

  it("büyük çıktı kırpılır ve 'kesildi' işaretlenir; modele giden kompakt görünüm token tavanı içinde", async () => {
    const h = await makeMcpHarness();
    const r = await h.call("mcp.mock.big", {});
    expect(r.status).toBe("ok");
    const j = h.json(r);
    expect(j.content.join("").length).toBeLessThanOrEqual(40_000);
    expect(r.truncated || r.byReference).toBeTruthy();
  });

  describe("ikili/dosya pini", () => {
    it("ikili hash uyuşmazlığı: sunucu HİÇ başlatılmaz", async () => {
      const h = await makeMcpHarness({ sha256: "0".repeat(64) });
      const r = await h.call("mcp.mock.echo", { text: "x" });
      expect(r.status).not.toBe("ok");
      expect(JSON.stringify(r)).toMatch(/mcp_pin_mismatch|pini uyuşmuyor/);
      expect(h.spawns()).toBe(0);
    });
    it("betik dosyası hash uyuşmazlığı: sunucu HİÇ başlatılmaz", async () => {
      const h = await makeMcpHarness({ fileSha256: "1".repeat(64) });
      const r = await h.call("mcp.mock.echo", { text: "x" });
      expect(r.status).not.toBe("ok");
      expect(JSON.stringify(r)).toMatch(/pini uyuşmuyor/);
      expect(h.spawns()).toBe(0);
    });
  });

  describe("protokol hataları fail-closed", () => {
    const cases: [string, string, RegExp, number?][] = [
      ["desteklenmeyen protokol sürümü", "badversion", /mcp_version_unsupported|desteklenmeyen protokol/],
      ["init'te süreç ölür", "exit_init", /mcp_server_exited|sonlandı|kapattı/],
      ["çağrıda süreç ölür", "exit_call", /mcp_server_exited|sonlandı|kapattı/],
      ["JSON olmayan satır", "badjson", /mcp_bad_json|JSON olmayan/],
      ["aşırı büyük çıktı/satır", "longline", /mcp_output_too_large|mcp_line_too_long|tavan/],
      ["yanıt yok (zaman aşımı)", "hang_call", /mcp_timeout|zaman aşımı/, 1000],
      ["el sıkışma yok (zaman aşımı)", "hang_init", /mcp_timeout|zaman aşımı/, 1000],
    ];
    for (const [label, mode, re, timeoutMs] of cases) {
      it(label, async () => {
        const h = await makeMcpHarness({ mode, ...(timeoutMs ? { timeoutMs } : {}), maxOutputBytes: 400_000 });
        const t0 = Date.now();
        const r = await h.call("mcp.mock.echo", { text: "x" });
        expect(r.status, JSON.stringify(r)).not.toBe("ok");
        expect(JSON.stringify(r), label).toMatch(re);
        expect(Date.now() - t0).toBeLessThan(8_000);
      });
    }

    it("JSON-RPC hatası: ileti temizlenir/kısaltılır (kontrol karakteri, ANSI, backtick yok)", async () => {
      const h = await makeMcpHarness({ mode: "rpc_error" });
      const r = await h.call("mcp.mock.echo", { text: "x" });
      expect(r.status).not.toBe("ok");
      const s = JSON.stringify(r);
      expect(s).toMatch(/mcp_error|hata döndürdü/);
      expect(s).not.toMatch(/\\u001b|`|<script>/);
    });

    it("araç düzeyi hata (isError) sonuç olarak döner ve işaretlenir", async () => {
      const h = await makeMcpHarness({ mode: "iserror" });
      const r = await h.call("mcp.mock.echo", { text: "x" });
      expect(r.status).toBe("ok");
      expect(r.summary).toMatch(/sunucu hata bildirdi/);
      expect(h.json(r).isError).toBe(true);
    });
  });

  describe("manifest ↔ sunucu uyuşmazlığı", () => {
    it("sunucu manifestteki aracı sunmuyorsa çağrı reddedilir", async () => {
      const h = await makeMcpHarness({ mode: "missing" });
      const r = await h.call("mcp.mock.echo", { text: "x" });
      expect(r.status).not.toBe("ok");
      expect(JSON.stringify(r)).toMatch(/mcp_tool_missing|sunmuyor/);
    });

    it("manifestte OLMAYAN sunucu aracı (danger) hiç kaydedilmez: çağrılamaz", async () => {
      const h = await makeMcpHarness();
      expect(h.adapter.definitions.map((d) => d.descriptor.name)).not.toContain("mcp.mock.danger");
      const r = await h.call("mcp.mock.danger", {});
      expect(r.status).not.toBe("ok");
    });

    it("check(): el sıkışır, araç ADLARINI manifestle karşılaştırır, araç ÇAĞIRMAZ", async () => {
      const h = await makeMcpHarness();
      const rep = await h.adapter.check("mock");
      expect(rep).toMatchObject({ server: "mock", ok: true, protocolVersion: "2025-06-18", serverName: "mock-server", missing: [], undeclared: 1 });
      const h2 = await makeMcpHarness({ mode: "missing" });
      expect(await h2.adapter.check("mock")).toMatchObject({ ok: false, missing: ["echo"] });
      const h3 = await makeMcpHarness({ sha256: "0".repeat(64) });
      expect(await h3.adapter.check("mock")).toMatchObject({ ok: false, error: expect.stringMatching(/pini uyuşmuyor/) });
    });
  });

  it("denetim kaydı: intent (write-ahead) + result yazılır; kayıttaki redakte çıktı kontrol/ANSI/bidi karakteri taşımaz", async () => {
    const h = await makeMcpHarness();
    await h.call("mcp.mock.docs", {});
    const raw = JSON.stringify(h.storage);
    expect(raw).toContain("mcp.mock.docs");
    expect(raw).toMatch(/"event\\":\\"intent/);
    expect(raw).toMatch(/"event\\":\\"result/);
    expect(raw).not.toMatch(/\\u001b|\\u202e|\\u200b/i);
  });
});

describe("sandbox yoksa", () => {
  it("MCP sunucusu ÇALIŞMAZ (sandbox_required)", async () => {
    const { McpBridgeAdapter } = await import("../src/index.ts");
    const { manifestFor } = await import("./harness.ts");
    const a = new McpBridgeAdapter({ manifest: manifestFor(), sandbox: null });
    await expect(a.invoke({ tool: "mcp.mock.echo", args: { text: "x" }, profile: undefined as never, handle: null, callId: "c", signal: new AbortController().signal, limits: a.definitions[0]!.descriptor.limits })).rejects.toMatchObject({ code: "sandbox_required" });
  });
});
