import { createServer } from "node:net";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OpsError, runtimeIsSafe } from "@ops/contracts";
import type { RuntimeEvent, ToolBridge } from "@ops/contracts";
import { RuntimeOrchestrator } from "@ops/core";
import type { OrchestratorEvent } from "@ops/core";
import { detectSandbox, UnsafeDirectRunner } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { makeCanary } from "@ops/testkit";
import {
  BUILTIN_DENY,
  CursorRuntime,
  LaunchError,
  assertSafeLaunch,
  buildCursorLaunchOptions,
  isAllowedToolName,
  mapSdkMessage,
} from "../src/index.ts";
import { makeFixtureForRuntime } from "./fixture.ts";
import type { RuntimeFixture } from "./fixture.ts";

const here = dirname(fileURLToPath(import.meta.url));
const HOST = join(here, "..", "src", "host-main.ts");
const MOCK = join(here, "mock-sdk.mjs");
const real: Sandbox | null = await detectSandbox();
const direct = (): Sandbox => new UnsafeDirectRunner({ acknowledgeNoIsolation: true });

describe("buildCursorLaunchOptions: seçenek kümesi KİLİTLİ (resume'a güvenme)", () => {
  const tool = { name: "k8s.workload.health", description: "d", inputSchema: { type: "object" }, execute: async () => "x" };
  it("tools boş allowlist, kabuk/dosya/ağ kapalı, sandbox açık, özel araç adları kodlu", () => {
    const o = buildCursorLaunchOptions({ model: "m", system: "S", cwd: "/tmp", tools: [tool], apiKey: "KEY-12345678" });
    expect(o).toMatchObject({ model: "m", systemPrompt: "S", tools: [], local: { cwd: "/tmp", sandboxOptions: { enabled: true } } });
    expect(o.disallowedTools).toEqual([...BUILTIN_DENY]);
    expect(o.disallowedTools).not.toContain("mcp");
    expect(o.local.customTools.map((t) => t.name)).toEqual(["k8s__workload__health"]);
    expect(Object.keys(o).sort()).toEqual(["apiKey", "disallowedTools", "local", "model", "systemPrompt", "tools"]);
    expect(Object.keys(o.local).sort()).toEqual(["customTools", "cwd", "sandboxOptions"]);
  });
  it.each([
    ["settingSources", { settingSources: ["project"] }],
    ["mcpServers", { mcpServers: { x: {} } }],
    ["resume", { resume: "agent-1" }],
    ["hooks", { hooks: {} }],
    ["env", { env: { A: "1" } }],
    ["tools dolu", { tools: ["shell"] }],
    ["disallowedTools eksik", { disallowedTools: ["shell"] }],
    ["mcp grubu kapalı", { disallowedTools: [...BUILTIN_DENY, "mcp"] }],
    ["sandbox kapalı", { local: { cwd: "/tmp", sandboxOptions: { enabled: false }, customTools: [] } }],
    ["göreli cwd", { local: { cwd: "tmp", sandboxOptions: { enabled: true }, customTools: [] } }],
    ["izinsiz özel araç", { local: { cwd: "/tmp", sandboxOptions: { enabled: true }, customTools: [{ name: "evil", description: "", inputSchema: {}, execute: async () => "" }] } }],
  ])("gevşek seçenek reddedilir: %s", (_n, patch) => {
    const good = buildCursorLaunchOptions({ model: "m", system: "S", cwd: "/tmp", tools: [tool] });
    expect(() => assertSafeLaunch({ ...good, ...patch }, [tool.name])).toThrow(LaunchError);
  });
  it("API anahtarı istem veya araç tanımına sızdıysa reddedilir", () => {
    expect(() => buildCursorLaunchOptions({ model: "m", system: "anahtar KEY-12345678 burada", cwd: "/tmp", tools: [], apiKey: "KEY-12345678" })).toThrow(LaunchError);
  });
});

describe("SDK mesaj eşleme (tolerant ama muhafazakâr)", () => {
  it("assistant/tool_call/usage/status; bilinmeyenler yok sayılır; adı okunamayan tool_call '<unknown>'", () => {
    expect(mapSdkMessage({ type: "assistant", message: { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] } })).toEqual({ type: "text", text: "ab" });
    expect(mapSdkMessage({ type: "assistant", text: "düz" })).toEqual({ type: "text", text: "düz" });
    expect(mapSdkMessage({ type: "tool_call", name: "x", status: "completed" })).toEqual({ type: "tool_call", name: "x", status: "completed" });
    expect(mapSdkMessage({ type: "tool_call", tool: { name: "y" } })).toEqual({ type: "tool_call", name: "y", status: "running" });
    expect(mapSdkMessage({ type: "tool_call" })).toEqual({ type: "tool_call", name: "<unknown>", status: "running" });
    expect(mapSdkMessage({ type: "usage", usage: { input_tokens: 5, output_tokens: 2 } })).toEqual({ type: "usage", usage: { inputTokens: 5, outputTokens: 2, cacheReadTokens: 0 } });
    expect(mapSdkMessage({ type: "thinking", text: "x" })).toBeNull();
    expect(mapSdkMessage({ type: "assistant", message: { content: "" } })).toBeNull();
  });
  it("izinli ad eşleşmesi: ön ekler tolere edilir, benzer adlar edilmez", () => {
    const allowed = new Set(["k8s.workload.health"]);
    for (const ok of ["k8s.workload.health", "k8s__workload__health", "custom-user-tools__k8s__workload__health", "mcp:k8s__workload__health"]) expect(isAllowedToolName(ok, allowed)).toBe(true);
    for (const bad of ["shell", "k8s__workload__healthx", "xk8s__workload__health", "<unknown>", "k8s__workload__health_evil"]) expect(isAllowedToolName(bad, allowed)).toBe(false);
  });
});

describe("yetenek bildirimi", () => {
  it("spike geçmeden güvenli SAYILMAZ (tavsiye kipi); geçince ve sandbox varsa güvenli", () => {
    const base = { model: "m", hostArgv: ["/x"], hostRoBinds: [] };
    expect(runtimeIsSafe(new CursorRuntime({ ...base, sandbox: direct() }).capabilities)).toBe(false);
    expect(runtimeIsSafe(new CursorRuntime({ ...base, sandbox: direct(), spikePassed: true }).capabilities)).toBe(false); // none ≠ OS sandbox
    expect(new CursorRuntime({ ...base, sandbox: null, spikePassed: true }).capabilities.osSandboxed).toBe(false);
    if (real) expect(runtimeIsSafe(new CursorRuntime({ ...base, sandbox: real, spikePassed: true }).capabilities)).toBe(true);
  });
  it("sandbox yoksa runTask ÇALIŞMAZ (fail-closed)", async () => {
    const rt = new CursorRuntime({ model: "m", hostArgv: [process.execPath, HOST], hostRoBinds: [], sandbox: null, spikePassed: true });
    const bridge: ToolBridge = { specs: () => [], invoke: async () => ({ text: "", isError: false }) };
    await expect(async () => {
      for await (const _ of rt.runTask({ system: "s", prompt: "p" }, bridge)) void _;
    }).rejects.toMatchObject({ code: "sandbox_unavailable" });
    const none = new CursorRuntime({ model: "m", hostArgv: [process.execPath, HOST], hostRoBinds: [], sandbox: direct(), spikePassed: true });
    await expect(async () => {
      for await (const _ of none.runTask({ system: "s", prompt: "p" }, bridge)) void _;
    }).rejects.toBeInstanceOf(OpsError);
  });
});

// ---- host süreci ile uçtan uca (gerçek bwrap varsa orada; yoksa atlanır) -----------------------

const nodeDir = dirname(process.execPath);
// VM sandbox'ında cursor-host/Node/SDK konukta yoktur (ADR-0011 sınırlar): gerçek testler yalnız yerel bwrap ile
const describeReal = real && real.kind !== "vm" ? describe : describe.skip;

function runtimeFor(sb: Sandbox, scenario: string, extraBinds: string[] = [], extraEnv: Record<string, string> = {}, apiKey?: string, spikePassed = true) {
  return new CursorRuntime({
    sandbox: sb,
    model: "mock-model",
    hostArgv: [process.execPath, HOST],
    hostRoBinds: [nodeDir, dirname(HOST), dirname(MOCK), ...extraBinds],
    hostEnv: { OPS_CURSOR_SDK_MODULE: MOCK, MOCK_SCENARIO: scenario, ...extraEnv },
    ...(apiKey ? { apiKey: async () => apiKey } : {}),
    spikePassed,
    lifetimeMs: 20_000,
  });
}

async function collect(rt: CursorRuntime, bridge: ToolBridge, signal?: AbortSignal): Promise<RuntimeEvent[]> {
  const out: RuntimeEvent[] = [];
  for await (const e of rt.runTask({ system: "sistem istemi", prompt: "soru" }, bridge, signal)) out.push(e);
  return out;
}
const bridgeOf = (names: string[], calls: string[] = []): ToolBridge => ({
  specs: () => names.map((name) => ({ name, description: "d", inputSchema: { type: "object", additionalProperties: false } })),
  invoke: async (name) => {
    calls.push(name);
    return { text: JSON.stringify({ id: `ev-${calls.length}`, tool: name }), isError: false };
  },
});

describeReal("cursor-host gerçek sandbox içinde (S-10)", () => {
  const sb = real as Sandbox;
  const dirs: string[] = [];
  afterEach(async () => {
    for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
  });

  it("(a)(c) host SDK'ya kilitli seçenekleri verir; API anahtarı yalnız stdin ile gider, env'de YOK", async () => {
    const key = makeCanary("cursor-key").value;
    const ev = await collect(runtimeFor(sb, "record", [], {}, key), bridgeOf(["k8s.workload.health"]));
    const text = ev.filter((e) => e.type === "text").map((e) => (e as { text: string }).text).join("");
    const seen = JSON.parse(text) as { opts: { tools: unknown[]; disallowedTools: string[]; local: { sandboxOptions: { enabled: boolean }; customTools: { name: string }[] } }; hasApiKey: boolean };
    expect(seen.hasApiKey).toBe(true);
    expect(seen.opts.tools).toEqual([]);
    expect(seen.opts.disallowedTools).toEqual(expect.arrayContaining(["shell", "edit", "write"]));
    expect(seen.opts.local.sandboxOptions.enabled).toBe(true);
    expect(seen.opts.local.customTools.map((t) => t.name)).toEqual(["k8s__workload__health"]);
    expect(text).not.toContain(key);
  });

  it("(d)(f) host ortamı temiz; kullanıcı ev dizini/kimlik yolları/host ağı görünmez", async () => {
    const home = await mkdtemp(join(tmpdir(), "ops-curhome-"));
    dirs.push(home);
    await mkdir(join(home, ".kube"), { recursive: true });
    const canary = makeCanary("host-kube");
    await writeFile(join(home, ".kube", "config"), `token: ${canary.value}`);
    process.env["OPS_HOST_ENV_CANARY"] = makeCanary("host-env").value;
    const srv = createServer((s) => s.end());
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const port = String((srv.address() as { port: number }).port);
      const ev = await collect(runtimeFor(sb, "probe", [], { PROBE_HOME: home, PROBE_HOME_PARENT: dirname(home), PROBE_PORT: port }), bridgeOf([]));
      const probe = JSON.parse(ev.filter((e) => e.type === "text").map((e) => (e as { text: string }).text).join("")) as { kube: string; home: string; envKeys: string; net: string };
      expect(probe.kube).toBe("yok");
      expect(probe.home).not.toContain(basename(home)); // host /tmp'si görünmez (boş tmpfs)
      expect(probe.envKeys).not.toMatch(/OPS_HOST_ENV_CANARY|AWS_|KUBECONFIG|CURSOR_API_KEY|TOKEN/);
      expect(JSON.stringify(probe)).not.toContain(canary.value);
      // host ağı açık (SDK sağlayıcıya bağlanmalı) ama allowlist YOK: bilinen sınır (STATUS)
      expect(probe.net).toBe("acik");
    } finally {
      delete process.env["OPS_HOST_ENV_CANARY"];
      srv.close();
    }
  });

  it("araç köprüsü: özel araç çağrıları host protokolüyle ana sürece döner; bekçi izinli adlarla susar", async () => {
    const calls: string[] = [];
    const ev = await collect(runtimeFor(sb, "tools"), bridgeOf(["k8s.workload.health", "k8s.events.list"], calls));
    expect(calls).toEqual(["k8s.workload.health", "k8s.events.list"]);
    expect(ev.some((e) => e.type === "alarm")).toBe(false);
    expect(ev.filter((e) => e.type === "tool_call").length).toBe(2);
    const usage = ev.find((e) => e.type === "usage") as Extract<RuntimeEvent, { type: "usage" }>;
    expect(usage.usage).toEqual({ inputTokens: 1200, outputTokens: 90, cacheReadTokens: 300 });
    expect(ev.filter((e) => e.type === "text").map((e) => (e as { text: string }).text).join("")).toContain("OOMKilled");
  });

  it("(b) SDK izinsiz araç (shell) çalıştırırsa: iptal + alarm; sonraki metin iletilmez", async () => {
    const ev = await collect(runtimeFor(sb, "bypass"), bridgeOf(["k8s.workload.health"]));
    expect(ev.at(-1)).toMatchObject({ type: "alarm", code: "provider-shell-bypass" });
    expect(JSON.stringify(ev)).not.toContain("görülmemeli");
  });

  it("tavsiye kipinde (araç yok) SDK'nın her araç çağrısı alarmdır", async () => {
    const ev = await collect(runtimeFor(sb, "bypass"), bridgeOf([]));
    expect(ev.at(-1)).toMatchObject({ type: "alarm" });
  });

  it("host izinli olmayan KÖPRÜ aracı isterse reddedilir ve alarm verilir", async () => {
    const calls: string[] = [];
    const ev = await collect(runtimeFor(sb, "bypass-bridge"), bridgeOf(["k8s.workload.health"], calls));
    expect(ev.at(-1)).toMatchObject({ type: "alarm", code: "provider-shell-bypass" });
    expect(calls).toEqual([]);
  });

  it("SDK çökmesi: hata mesajı secret taşımaz (host stderr/ayrıntı iletilmez ya da kısaltılır)", async () => {
    await expect(collect(runtimeFor(sb, "crash"), bridgeOf([]))).rejects.toMatchObject({ code: "provider_error" });
  });

  it("iptal sinyali host'u sonlandırır", async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 400);
    const t0 = Date.now();
    await collect(runtimeFor(sb, "hang"), bridgeOf([]), ac.signal);
    expect(Date.now() - t0).toBeLessThan(5_000);
  });
});

describeReal("RuntimeOrchestrator + CursorRuntime + PEP (uçtan uca, sahte SDK)", () => {
  let fx: RuntimeFixture;
  beforeEach(async () => {
    fx = await makeFixtureForRuntime();
  });
  afterEach(async () => {
    await fx.cleanup();
  });
  const engine = (scenario: string, spike = true) =>
    new RuntimeOrchestrator({
      runtime: runtimeFor(real as Sandbox, scenario, [], {}, undefined, spike),
      gateway: fx.rt.gateway,
      registry: fx.rt.toolRegistry,
      session: fx.rt.session,
      evidence: fx.rt.evidence,
      policy: fx.rt.policy,
      audit: fx.rt.audit,
      known: fx.rt.known,
      skills: fx.rt.skills,
      preloadSkills: [fx.kubernetesSkill],
    });
  const run = async (e: RuntimeOrchestrator, text: string): Promise<OrchestratorEvent[]> => {
    const out: OrchestratorEvent[] = [];
    for await (const ev of e.send(text)) out.push(ev);
    return out;
  };

  it("araç modu: ajan köprü araçlarını çağırır, her çağrı PEP'ten geçer; cevap atıflı; canary sızmaz", async () => {
    await fx.rt.bindProfile("payments-sbx");
    const ev = await run(engine("tools"), "api neden çöküyor?");
    const final = ev.find((e) => e.type === "final") as Extract<OrchestratorEvent, { type: "final" }>;
    expect(final.citations.invalid).toEqual([]);
    expect(final.citations.valid.length).toBeGreaterThanOrEqual(2);
    const tr = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
    expect(tr.map((r) => [r.name, r.status])).toEqual([["k8s.workload.health", "ok"], ["k8s.events.list", "ok"]]);
    // denetimde sağlayıcı = cursor, bölge = third-party-cloud
    const audit = (await (await import("node:fs/promises")).readFile(fx.rt.paths.auditLog, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(audit.some((r) => r["event"] === "model_call" && r["provider"] === "cursor" && r["trustZone"] === "third-party-cloud")).toBe(true);
    const ui = ev.map((e) => JSON.stringify(e)).join("\n");
    const raw = audit.map((r) => JSON.stringify(r)).join("\n") + ui + fx.rt.evidence.all().map((e) => e.text).join("\n");
    for (const c of fx.all) expect(raw.includes(c.value), c.label).toBe(false);
  });

  it("bekçi alarmı: oturum 'tainted', denetime alarm, çalışma zamanı bu oturumda devre dışı", async () => {
    await fx.rt.bindProfile("payments-sbx");
    const e = engine("bypass");
    const ev = await run(e, "dene");
    expect(ev.some((x) => x.type === "warning" && x.code === "alarm:provider-shell-bypass")).toBe(true);
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "runtime_alarm" });
    expect(fx.rt.session.context.tainted).toBe(true);
    const again = await run(e, "tekrar");
    expect(again.at(-1)).toMatchObject({ type: "error", code: "runtime_disabled" });
    const auditText = await (await import("node:fs/promises")).readFile(fx.rt.paths.auditLog, "utf8");
    expect(auditText).toContain('"event":"alarm"');
  });

  it("spike geçilmediyse TAVSİYE KİPİ: araç yok, uyarı verilir, SDK'nın araç çağrısı alarm olur", async () => {
    const e = engine("bypass", false);
    expect(e.mode).toBe("advisory");
    const ev = await run(e, "dene");
    expect(ev.some((x) => x.type === "warning" && x.code === "advisory_mode")).toBe(true);
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "runtime_alarm" });
  });

  it("egress: secret-adjacent bağlamdan sonra üçüncü taraf Cursor'a gönderim reddedilir (host hiç başlatılmaz)", async () => {
    fx.rt.session.noteResult({ sensitivity: "secret-adjacent", tainted: false });
    const ev = await run(engine("tools"), "devam");
    expect(ev.at(-1)).toMatchObject({ type: "error", code: "no_eligible_provider" });
  });
});
