import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Message } from "@ops/contracts";
import { makeCanary } from "@ops/testkit";
import { AnthropicProvider } from "../src/index.ts";

interface Captured {
  headers: IncomingMessage["headers"];
  body: any;
  url: string;
}

let server: Server;
let url = "";
let captured: Captured[] = [];
let responder: (n: number, c: Captured, res: ServerResponse) => void = () => undefined;

beforeEach(async () => {
  captured = [];
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (b: Buffer) => chunks.push(b));
    req.on("end", () => {
      const c: Captured = { headers: req.headers, body: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"), url: req.url ?? "" };
      captured.push(c);
      responder(captured.length, c, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const reply = (res: ServerResponse, body: unknown, status = 200): void => {
  res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" });
  res.end(JSON.stringify(body));
};
const message = (content: unknown[], over: Record<string, unknown> = {}) => ({
  id: "msg_1",
  type: "message",
  role: "assistant",
  model: "claude-opus-5-5",
  content,
  stop_reason: "end_turn",
  stop_sequence: null,
  usage: { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
  ...over,
});
const KEY = "sk-ant-test-" + "x".repeat(20);
const mk = (over: Record<string, unknown> = {}) => new AnthropicProvider({ apiKey: KEY, baseUrl: url, ...over });
const tools = [{ name: "k8s.workload.health", description: "Sağlık.", inputSchema: { type: "object", properties: { name: { type: "string" } }, additionalProperties: false } }];

describe("AnthropicProvider (resmî SDK, yerel sahte uç)", () => {
  it("istek biçimi: anahtar başlığı, model, sistem, araç adı kodlaması, üst düzey cache_control, effort; zorlayıcı tool_choice/temperature/thinking-disabled YOK", async () => {
    responder = (_n, _c, res) => reply(res, message([{ type: "text", text: "merhaba" }]));
    const p = mk({ effort: "high" });
    const r = await p.generate({ system: "SİSTEM", messages: [{ role: "user", content: "selam" }], tools });
    expect(r.message.content).toBe("merhaba");
    const c = captured[0]!;
    expect(c.url).toBe("/v1/messages");
    // SDK 1.x anahtarı `Authorization: Bearer` ile taşır (eski `x-api-key` değil); hangisi olursa olsun yalnız BU uca gider
    expect(c.headers["authorization"] ?? c.headers["x-api-key"]).toContain(KEY);
    expect(c.headers["anthropic-version"]).toBeTruthy();
    expect(c.body).toMatchObject({
      model: "claude-opus-5-5",
      max_tokens: 16000,
      system: "SİSTEM",
      messages: [{ role: "user", content: "selam" }],
      tools: [{ name: "k8s__workload__health", description: "Sağlık.", input_schema: { type: "object" } }],
      tool_choice: { type: "auto" },
      output_config: { effort: "high" },
      cache_control: { type: "ephemeral" },
    });
    for (const forbidden of ["temperature", "top_p", "top_k", "thinking"]) expect(c.body, forbidden).not.toHaveProperty(forbidden);
    expect(p.capabilities).toMatchObject({ loopOwner: "host", trustZone: "local", tier: "large", costClass: "high" }); // loopback → local
  });

  it("varsayılan effort 'medium'; önbellek kapatılabilir; araçsız istekte tools/tool_choice gönderilmez", async () => {
    responder = (_n, _c, res) => reply(res, message([{ type: "text", text: "x" }]));
    await mk({ promptCache: false }).generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [] });
    const b = captured[0]!.body;
    expect(b.output_config).toEqual({ effort: "medium" });
    expect(b).not.toHaveProperty("cache_control");
    expect(b).not.toHaveProperty("tools");
    expect(b).not.toHaveProperty("tool_choice");
  });

  it("araç çağrısı: tool_use → ToolCall (ad çözülür), kullanım eşlenir (girdi = yeni + yazım + okuma; önbellek okuması ayrı)", async () => {
    responder = (_n, _c, res) =>
      reply(
        res,
        message([{ type: "text", text: "bakıyorum" }, { type: "tool_use", id: "toolu_1", name: "k8s__workload__health", input: { name: "api" } }], {
          stop_reason: "tool_use",
          usage: { input_tokens: 7, output_tokens: 20, cache_creation_input_tokens: 100, cache_read_input_tokens: 900 },
        }),
      );
    const r = await mk().generate({ system: "s", messages: [{ role: "user", content: "api?" }], tools });
    expect(r.stopReason).toBe("tool_use");
    expect(r.message.toolCalls).toEqual([{ id: "toolu_1", name: "k8s.workload.health", args: { name: "api" } }]);
    expect(r.message.content).toBe("bakıyorum");
    expect(r.usage).toEqual({ inputTokens: 1007, outputTokens: 20, cacheReadTokens: 900 });
  });

  it("araç sonuçları TEK kullanıcı iletisinde birleşir; düşünme blokları providerData ile DEĞİŞTİRİLMEDEN geri gider", async () => {
    const thinking = { type: "thinking", thinking: "", signature: "sig-opak-123" };
    const toolUse1 = { type: "tool_use", id: "toolu_1", name: "k8s__workload__health", input: { name: "api" } };
    const toolUse2 = { type: "tool_use", id: "toolu_2", name: "k8s__workload__health", input: { name: "db" } };
    let n = 0;
    responder = (_x, _c, res) => {
      n += 1;
      reply(res, n === 1 ? message([thinking, toolUse1, toolUse2], { stop_reason: "tool_use" }) : message([{ type: "text", text: "bitti" }]));
    };
    const p = mk();
    const first = await p.generate({ system: "s", messages: [{ role: "user", content: "kontrol et" }], tools });
    const history: Message[] = [
      { role: "user", content: "kontrol et" },
      { role: "assistant", content: first.message.content, toolCalls: first.message.toolCalls, providerData: first.message.providerData },
      { role: "tool", toolCallId: "toolu_1", name: "k8s.workload.health", content: "sonuç-1" },
      { role: "tool", toolCallId: "toolu_2", name: "k8s.workload.health", content: "sonuç-2" },
    ];
    await p.generate({ system: "s", messages: history, tools });
    const m = captured[1]!.body.messages;
    expect(m).toHaveLength(3);
    expect(m[1]).toEqual({ role: "assistant", content: [thinking, toolUse1, toolUse2] }); // ham bloklar, imza dahil
    expect(m[2]).toEqual({
      role: "user",
      content: [
        { type: "tool_result", tool_use_id: "toolu_1", content: "sonuç-1" },
        { type: "tool_result", tool_use_id: "toolu_2", content: "sonuç-2" },
      ],
    });
  });

  it("geçmiş DÜZENLENİRSE (defter sıkıştırması) düşünme blokları o konuşma için TÜMÜYLE bırakılır (yapışkan); metin/araç blokları kalır", async () => {
    const thinking = { type: "thinking", thinking: "", signature: "sig" };
    const tu = { type: "tool_use", id: "toolu_1", name: "k8s__workload__health", input: {} };
    responder = (n, _c, res) => reply(res, n === 1 ? message([thinking, tu], { stop_reason: "tool_use" }) : message([{ type: "text", text: "ok" }]));
    const p = mk();
    const first = await p.generate({ system: "s", messages: [{ role: "user", content: "a" }], tools });
    const asst: Message = { role: "assistant", content: "", toolCalls: first.message.toolCalls, providerData: first.message.providerData };
    const tool = (c: string): Message => ({ role: "tool", toolCallId: "toolu_1", name: "k8s.workload.health", content: c });
    // 2. istek: salt-ekleme → düşünme KALIR
    await p.generate({ system: "s", messages: [{ role: "user", content: "a" }, asst, tool("tam-sonuç")], tools });
    expect(JSON.stringify(captured[1]!.body.messages)).toContain("sig");
    // 3. istek: eski araç sonucu referansa çevrildi (düzenleme) → düşünme bırakılır
    await p.generate({ system: "s", messages: [{ role: "user", content: "a" }, asst, tool("(sonuç ev-1 olarak saklandı)"), { role: "assistant", content: "ok" }, { role: "user", content: "devam" }], tools });
    const wire3 = JSON.stringify(captured[2]!.body.messages);
    expect(wire3).not.toContain("sig");
    expect(wire3).toContain("toolu_1");
    // yapışkan: sonraki isteklerde de gönderilmez
    await p.generate({ system: "s", messages: [{ role: "user", content: "a" }, asst, tool("(sonuç ev-1 olarak saklandı)"), { role: "assistant", content: "ok" }, { role: "user", content: "devam" }, { role: "assistant", content: "x" }, { role: "user", content: "y" }], tools });
    expect(JSON.stringify(captured[3]!.body.messages)).not.toContain("sig");
  });

  it("providerData yoksa/bozuksa içerik ortak iletiden kurulur; boş asistan iletisi geçerli kalır", async () => {
    responder = (_n, _c, res) => reply(res, message([{ type: "text", text: "x" }]));
    const msgs: Message[] = [
      { role: "user", content: "a" },
      { role: "assistant", content: "yanıt", toolCalls: [{ id: "t1", name: "db.query.read", args: { sql: "SELECT 1" } }], providerData: "bozuk" },
      { role: "tool", toolCallId: "t1", name: "db.query.read", content: "r" },
      { role: "assistant", content: "" },
      { role: "user", content: "b" },
    ];
    await mk().generate({ system: "s", messages: msgs, tools });
    expect(captured[0]!.body.messages[1]).toEqual({ role: "assistant", content: [{ type: "text", text: "yanıt" }, { type: "tool_use", id: "t1", name: "db__query__read", input: { sql: "SELECT 1" } }] });
    expect(captured[0]!.body.messages[3]).toEqual({ role: "assistant", content: [{ type: "text", text: "(boş)" }] });
  });

  it("durdurma nedenleri: max_tokens → length; refusal → provider_refusal (kategori); sağlayıcı hataları anahtar SIZDIRMAZ", async () => {
    const p = mk();
    responder = (_n, _c, res) => reply(res, message([{ type: "text", text: "kesik" }], { stop_reason: "max_tokens" }));
    expect((await p.generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [] })).stopReason).toBe("length");
    responder = (_n, _c, res) => reply(res, message([], { stop_reason: "refusal", stop_details: { type: "refusal", category: "cyber", explanation: "x" } }));
    await expect(p.generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [] })).rejects.toMatchObject({ code: "provider_refusal", message: expect.stringContaining("cyber") });
    const leak = makeCanary("echo-key");
    for (const status of [401, 429, 400]) {
      responder = (_n, _c, res) => reply(res, { type: "error", error: { type: "api_error", message: `istek ${KEY} ve ${leak.value} yansıttı` } }, status);
      const err = await mk().generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [] }).catch((e: Error) => e);
      expect(err, String(status)).toBeInstanceOf(Error);
      expect((err as Error).message).toMatch(new RegExp(`HTTP ${status}`));
      expect((err as Error).message).not.toContain(KEY);
    }
  }, 30_000);

  it("yönlendirme İZLENMEZ (anahtar başka hosta gitmesin) ve ağ hatası anahtarsız bildirilir", async () => {
    let targetHit = false;
    const target = createServer((_q, r) => {
      targetHit = true;
      r.end("{}");
    });
    await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
    const tport = (target.address() as { port: number }).port;
    responder = (_n, _c, res) => {
      res.writeHead(307, { location: `http://127.0.0.1:${tport}/v1/messages` });
      res.end();
    };
    await expect(mk().generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [] })).rejects.toMatchObject({ code: "provider_error" });
    expect(targetHit).toBe(false);
    await new Promise<void>((r) => target.close(() => r()));
  }, 30_000);

  it("yapılandırma: anahtar gerekli; uzak uç yalnız https; kimlik bilgisi içeren URL ve geçersiz bölge reddedilir; varsayılan bölge third-party-cloud", () => {
    expect(() => new AnthropicProvider({ apiKey: "" })).toThrow(/API anahtarı/);
    expect(() => new AnthropicProvider({ apiKey: KEY, baseUrl: "http://api.example.invalid" })).toThrow(/https/);
    expect(() => new AnthropicProvider({ apiKey: KEY, baseUrl: "https://u:p@api.example.invalid" })).toThrow(/kimlik bilgisi/);
    expect(() => new AnthropicProvider({ apiKey: KEY, baseUrl: "not a url" })).toThrow(/baseUrl/);
    expect(() => new AnthropicProvider({ apiKey: KEY, trustZone: "mars" as never })).toThrow(/trustZone/);
    const cloud = new AnthropicProvider({ apiKey: KEY });
    expect(cloud.capabilities.trustZone).toBe("third-party-cloud");
    expect(cloud.model).toBe("claude-opus-5-5");
    const small = new AnthropicProvider({ apiKey: KEY, model: "claude-haiku-5-5" });
    expect(small.capabilities).toMatchObject({ tier: "small", costClass: "low" });
    expect(new AnthropicProvider({ apiKey: KEY, baseUrl: "https://llm.corp.invalid", trustZone: "tenant-cloud" }).capabilities.trustZone).toBe("tenant-cloud");
  });

  it("araç adı kodlaması: '__' içeren ad ve geçersiz karakter reddedilir (sessiz çakışma yok)", async () => {
    responder = (_n, _c, res) => reply(res, message([{ type: "text", text: "x" }]));
    const bad = { name: "a__b.c", description: "x", inputSchema: { type: "object" } };
    await expect(mk().generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [bad] })).rejects.toMatchObject({ code: "tool_name_unencodable" });
    const bad2 = { name: "a b", description: "x", inputSchema: { type: "object" } };
    await expect(mk().generate({ system: "s", messages: [{ role: "user", content: "a" }], tools: [bad2] })).rejects.toMatchObject({ code: "tool_name_unencodable" });
  });
});
