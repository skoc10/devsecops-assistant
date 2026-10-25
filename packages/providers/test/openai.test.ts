import { afterEach, describe, expect, it } from "vitest";
import { FakeOpenAiServer, makeCanary, openAiText, openAiToolCalls } from "@ops/testkit";
import type { GenerateRequest } from "@ops/contracts";
import { OpenAiCompatibleProvider, decodeToolName, defaultZone, encodeToolName, parseResponse, toWireMessages } from "../src/index.ts";

const req = (over: Partial<GenerateRequest> = {}): GenerateRequest => ({
  system: "sistem",
  messages: [{ role: "user", content: "merhaba" }],
  tools: [{ name: "k8s.workload.health", description: "sağlık", inputSchema: { type: "object", additionalProperties: false, properties: {} } }],
  ...over,
});

describe("araç adı kodlaması", () => {
  it("noktalar '__' olur ve geri döner; çakışan ad reddedilir", () => {
    expect(encodeToolName("k8s.auth.can_i")).toBe("k8s__auth__can_i");
    expect(decodeToolName("k8s__auth__can_i")).toBe("k8s.auth.can_i");
    expect(decodeToolName(encodeToolName("evidence.get"))).toBe("evidence.get");
    // `__` içeren veya `_` ile biten parçalı adlar TAKMA ADLA taşınır ve geri çözülür (sessiz çakışma yok)
    for (const n of ["mcp.srv.get__item", "a.b_.c", "x.y__z__w"]) {
      const w = encodeToolName(n);
      expect(w, n).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
      expect(decodeToolName(w), n).toBe(n);
    }
    expect(() => encodeToolName("a b")).toThrow(/biçimi geçersiz/);
    expect(encodeToolName("k8s.workload.health")).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
  });
});

describe("mesaj eşleme", () => {
  it("system + user + assistant(tool_calls) + tool", () => {
    const w = toWireMessages("S", [
      { role: "user", content: "u" },
      { role: "assistant", content: "", toolCalls: [{ id: "1", name: "k8s.pods.logs", args: { a: 1 } }] },
      { role: "tool", toolCallId: "1", name: "k8s.pods.logs", content: "sonuç" },
      { role: "assistant", content: "bitti" },
    ]);
    expect(w[0]).toEqual({ role: "system", content: "S" });
    expect(w[2]).toEqual({ role: "assistant", content: null, tool_calls: [{ id: "1", type: "function", function: { name: "k8s__pods__logs", arguments: '{"a":1}' } }] });
    expect(w[3]).toEqual({ role: "tool", tool_call_id: "1", content: "sonuç" });
    expect(w[4]).toEqual({ role: "assistant", content: "bitti" });
  });
});

describe("yanıt ayrıştırma", () => {
  it("araç çağrısı + önbellek kullanımı", () => {
    const r = parseResponse(
      JSON.stringify({
        choices: [{ message: { content: null, tool_calls: [{ id: "x", function: { name: "k8s__events__list", arguments: '{"since":"1h"}' } }] }, finish_reason: "tool_calls" }],
        usage: { prompt_tokens: 500, completion_tokens: 30, prompt_tokens_details: { cached_tokens: 400 } },
      }),
    );
    expect(r.stopReason).toBe("tool_use");
    expect(r.message.toolCalls).toEqual([{ id: "x", name: "k8s.events.list", args: { since: "1h" } }]);
    expect(r.usage).toEqual({ inputTokens: 500, outputTokens: 30, cacheReadTokens: 400 });
  });
  it("bozuk argüman JSON'u şemayı bozacak işaretle döner (model hatayı görür)", () => {
    const r = parseResponse(JSON.stringify({ choices: [{ message: { tool_calls: [{ id: "x", function: { name: "a__b", arguments: "{bozuk" } }] } }] }));
    expect(r.message.toolCalls[0]?.args).toEqual({ _argumentsParseError: true });
  });
  it("kullanım yoksa istek gövdesinden tahmin edilir; length bitişi", () => {
    const r = parseResponse(JSON.stringify({ choices: [{ message: { content: "kesik" }, finish_reason: "length" }] }), 321);
    expect(r.usage.inputTokens).toBe(321);
    expect(r.stopReason).toBe("length");
  });
  it.each([["json değil"], [JSON.stringify({ choices: [] })]])("geçersiz yanıt provider_error: %s", (t) => {
    expect(() => parseResponse(t)).toThrow(expect.objectContaining({ code: "provider_error" }));
  });
});

describe("yapılandırma güvenliği", () => {
  it("uzak düz http, kimlik bilgili URL ve geçersiz bölge reddedilir; loopback http serbest", () => {
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "http://api.example.invalid/v1", model: "m" })).toThrow(/https/);
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "https://u:p@api.example.invalid/v1", model: "m" })).toThrow(/kimlik/);
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "https://api.example.invalid/v1", model: "m", trustZone: "mars" as never })).toThrow(/trustZone/);
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "kötü url", model: "m" })).toThrow(/baseUrl/);
    expect(new OpenAiCompatibleProvider({ baseUrl: "http://127.0.0.1:11434/v1", model: "m" }).capabilities.trustZone).toBe("local");
  });
  it("varsayılan bölge: loopback local, uzak third-party-cloud; açık bölge kazanır", () => {
    expect(defaultZone("http://localhost:8000/v1")).toBe("local");
    expect(defaultZone("https://api.example.invalid/v1")).toBe("third-party-cloud");
    const p = new OpenAiCompatibleProvider({ baseUrl: "https://llm.corp.example.invalid/v1", model: "m", trustZone: "private-net" });
    expect(p.capabilities).toMatchObject({ loopOwner: "host", trustZone: "private-net", toolCalling: true });
  });
  it("'local' bölgesi yalnız loopback uca verilebilir (OPS_PROVIDER_ZONE=local uzak ucu local-only'den geçiremez)", () => {
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "https://api.example.invalid/v1", model: "m", trustZone: "local" })).toThrow(/yalnız loopback/);
    expect(() => new OpenAiCompatibleProvider({ baseUrl: "https://10.0.0.5:8000/v1", model: "m", trustZone: "local" })).toThrow(/private-net/);
    expect(new OpenAiCompatibleProvider({ baseUrl: "http://127.0.0.1:11434/v1", model: "m", trustZone: "local" }).capabilities.trustZone).toBe("local");
  });
});

describe("HTTP davranışı (sahte uç)", () => {
  let srv: FakeOpenAiServer;
  afterEach(async () => {
    await srv?.stop();
  });

  it("istek gövdesi: model, kodlanmış araç adları, tool_choice; Authorization yalnız anahtar varsa", async () => {
    srv = await FakeOpenAiServer.start([() => openAiText("merhaba!")]);
    const key = makeCanary("api-key").value;
    const withKey = new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "yerel-model", apiKey: key });
    const r = await withKey.generate(req({ maxOutputTokens: 256 }));
    expect(r.message.content).toBe("merhaba!");
    expect(r.usage.inputTokens).toBe(100);
    const sent = srv.requests[0]!;
    expect(sent.path).toBe("/v1/chat/completions");
    expect(sent.authorization).toBe(`Bearer ${key}`);
    expect(sent.body).toMatchObject({ model: "yerel-model", tool_choice: "auto", max_tokens: 256 });
    expect(sent.body.tools?.[0]?.function.name).toBe("k8s__workload__health");
    expect(sent.raw).not.toContain(key); // anahtar gövdede değil, yalnız başlıkta
    const noKey = new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m" });
    await noKey.generate(req({ tools: [] }));
    expect(srv.requests[1]!.authorization).toBeNull();
    expect(srv.requests[1]!.body.tools).toBeUndefined();
  });

  it("araç çağrısı yanıtı çözülür", async () => {
    srv = await FakeOpenAiServer.start([() => openAiToolCalls([{ name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }])]);
    const r = await new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m" }).generate(req());
    expect(r.stopReason).toBe("tool_use");
    expect(r.message.toolCalls[0]).toMatchObject({ name: "k8s.workload.health", args: { kind: "Deployment" } });
  });

  it("HTTP hatası: anahtar mesajda YOK (sağlayıcı yansıtsa bile)", async () => {
    const key = makeCanary("echoed-key").value;
    srv = await FakeOpenAiServer.start([() => ({ status: 401, raw: `Incorrect API key provided: ${key}` })]);
    const err = await new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m", apiKey: key }).generate(req()).catch((e: Error) => e);
    expect(err).toMatchObject({ code: "provider_error" });
    expect((err as Error).message).toContain("401");
    expect((err as Error).message).not.toContain(key);
  });

  it("yönlendirme izlenmez (anahtar başka hosta gitmesin)", async () => {
    srv = await FakeOpenAiServer.start([() => ({ redirectTo: "http://127.0.0.1:1/steal" })]);
    await expect(new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m", apiKey: "k".repeat(20) }).generate(req())).rejects.toMatchObject({ code: "provider_error" });
  });

  it("zaman aşımı ve iptal; dev yanıt sınırı", async () => {
    srv = await FakeOpenAiServer.start([() => ({ hang: true })]);
    await expect(new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m", requestTimeoutMs: 150 }).generate(req())).rejects.toMatchObject({ code: "provider_error" });
    const ac = new AbortController();
    const p = new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m" }).generate(req({ signal: ac.signal }));
    setTimeout(() => ac.abort(), 50);
    await expect(p).rejects.toMatchObject({ code: "provider_error" });
    await srv.stop();
    srv = await FakeOpenAiServer.start([() => ({ raw: "x".repeat(3000) })]);
    await expect(new OpenAiCompatibleProvider({ baseUrl: srv.url, model: "m", maxResponseBytes: 1000 }).generate(req())).rejects.toThrow(/boyut sınırını/);
  });
});
