import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { REASON_CODES } from "@ops/contracts";
import type { ApprovalRequest, CanonicalActionSummary } from "@ops/contracts";
import { explainReason } from "@ops/policy";
import { ScriptedProvider, say } from "@ops/testkit";
import type { OrchestratorEvent } from "@ops/core";
import { CONFIRM_PHRASE, TtyApprovalGate, renderSummary, requiredAnswer, runCli, createRuntime, resolvePaths } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

const summary = (over: Partial<CanonicalActionSummary> = {}): CanonicalActionSummary => ({
  tool: "k8s.scale",
  class: "mutate",
  profile: { id: "stage-eu", environment: "stage", displayName: "Stage EU" },
  target: { profileId: "stage-eu", kind: "k8s", endpoint: "https://k8s.invalid:6443", scopes: ["payments"], refs: ["Deployment/payments/api"] },
  argsRedacted: { namespace: "payments", name: "api", replicas: 3 },
  citedEvidence: [{ id: "ev-3", summary: "api 0/2 hazır" }],
  taintedContext: false,
  why: "approval_required",
  ...over,
});
const req = (s = summary(), expiresInSec = 5): ApprovalRequest => ({ actionHash: "a".repeat(64), summary: s, expiresInSec });

function fakeTty(answers: string[], delayMs = 0): { io: TtyIo; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  output.on("data", (b: Buffer) => chunks.push(b.toString()));
  let i = 0;
  output.on("data", () => {
    // her istemden sonra sıradaki yanıtı yaz
    const a = answers[i];
    if (a !== undefined && /: $|> $/.test(chunks.join("").slice(-12))) {
      i += 1;
      setTimeout(() => input.write(`${a}\n`), delayMs);
    }
  });
  return { io: { input, output }, shown: () => chunks.join("") };
}
const gateWith = (tty: { io: TtyIo } | null, over: Partial<ConstructorParameters<typeof TtyApprovalGate>[0]> = {}) =>
  new TtyApprovalGate({ openTty: async () => (tty ? tty.io : null), sleep: async () => undefined, ...over });

describe("TtyApprovalGate (v0)", () => {
  it("mutate: 'evet' yazılırsa onaylanır; eylem hash'i ve onay kimliği döner", async () => {
    const tty = fakeTty(["evet"]);
    const out = await gateWith(tty).request(req());
    expect(out).toMatchObject({ approved: true, actionHash: "a".repeat(64) });
    const shown = tty.shown();
    expect(shown).toContain("ONAY GEREKİYOR");
    expect(shown).toContain("k8s.scale");
    expect(shown).toContain("Deployment/payments/api");
    expect(shown).toContain("ev-3 — api 0/2 hazır");
  });

  it("Enter = ret; yanlış metin = ret; sessizlik = zaman aşımı (ret)", async () => {
    expect(await gateWith(fakeTty([""])).request(req())).toMatchObject({ approved: false, reason: "kullanıcı reddetti" });
    expect(await gateWith(fakeTty(["evt"])).request(req())).toMatchObject({ approved: false });
    const silent = fakeTty([]);
    expect(await gateWith(silent).request(req(summary(), 0.1))).toMatchObject({ approved: false, reason: expect.stringContaining("zaman aşımı") });
  });

  it("TTY yoksa ret (fail-closed)", async () => {
    expect(await gateWith(null).request(req())).toMatchObject({ approved: false, reason: expect.stringContaining("TTY") });
  });

  it("sınıfa göre artan sürtünme: deploy/prod → ortam adı; destroy → ortam/kaynak adı", () => {
    expect(requiredAnswer(summary())).toBe("evet");
    expect(requiredAnswer(summary({ class: "deploy" }))).toBe("stage");
    expect(requiredAnswer(summary({ profile: { id: "p", environment: "prod", displayName: "P" } }))).toBe("prod");
    expect(requiredAnswer(summary({ class: "destroy" }))).toBe("stage/api");
    expect(requiredAnswer(summary({ class: "read", why: "taint_escalation" }))).toBe("e");
  });

  it("prod mutasyonu 'evet' ile ONAYLANMAZ, ortam adıyla onaylanır", async () => {
    const prod = summary({ profile: { id: "p", environment: "prod", displayName: "P" } });
    expect(await gateWith(fakeTty(["evet"])).request(req(prod))).toMatchObject({ approved: false });
    expect(await gateWith(fakeTty(["prod"])).request(req(prod))).toMatchObject({ approved: true });
  });

  it("onay bütçesi: pencerede N onaydan sonra yazılı ifade + soğuma istenir (T7)", async () => {
    let t = 1_000_000;
    const slept: number[] = [];
    const budget = { maxPerWindow: 2, windowMs: 60_000, cooldownMs: 3_000 };
    const gate = new TtyApprovalGate({ openTty: async () => fakeTty(["evet"]).io, budget, now: () => t, sleep: async (ms) => void slept.push(ms) });
    // iki onay serbest
    for (let k = 0; k < 2; k++) {
      const tty = fakeTty(["evet"]);
      const g = new TtyApprovalGate({ openTty: async () => tty.io, budget, now: () => t, sleep: async (ms) => void slept.push(ms) });
      void g;
    }
    const make = (answers: string[]) => {
      const tty = fakeTty(answers);
      return { tty, gate: new TtyApprovalGate({ openTty: async () => tty.io, budget, now: () => t, sleep: async (ms) => void slept.push(ms) }) };
    };
    // aynı gate nesnesi üzerinde ardışık: TTY'yi her istekte yenile
    let next: ReturnType<typeof fakeTty> = fakeTty(["evet"]);
    const g = new TtyApprovalGate({ openTty: async () => next.io, budget, now: () => t, sleep: async (ms) => void slept.push(ms) });
    void gate; void make;
    expect((await g.request(req())).approved).toBe(true);
    t += 1000;
    next = fakeTty(["evet"]);
    expect((await g.request(req())).approved).toBe(true);
    t += 1000;
    expect(slept).toEqual([]);
    // üçüncü: bütçe aşıldı → önce ifade, yanlışsa ret
    next = fakeTty(["evet"]);
    expect((await g.request(req())).approved).toBe(false);
    expect(slept).toEqual([3_000]);
    expect(next.shown()).toContain(CONFIRM_PHRASE);
    // doğru ifade + sınıf yanıtı
    next = fakeTty([CONFIRM_PHRASE, "evet"]);
    expect((await g.request(req())).approved).toBe(true);
    // pencere geçince sıfırlanır
    t += 61_000;
    slept.length = 0;
    next = fakeTty(["evet"]);
    expect((await g.request(req())).approved).toBe(true);
    expect(slept).toEqual([]);
    expect(g.summaryLine()).toBe("Bu oturumda 4 onay verdiniz.");
  });

  it("eşzamanlı istekler SIRAYLA sorulur: aynı anda tek TTY istemi, bütçe paralel isteklerle atlanamaz", async () => {
    let open = 0;
    let maxOpen = 0;
    const ttys: ReturnType<typeof fakeTty>[] = [];
    const g = new TtyApprovalGate({
      openTty: async () => {
        open += 1;
        maxOpen = Math.max(maxOpen, open);
        const t = fakeTty(["evet"]);
        ttys.push(t);
        return { ...t.io, close: () => void (open -= 1) };
      },
      budget: { maxPerWindow: 1, windowMs: 60_000, cooldownMs: 0 },
      sleep: async () => undefined,
    });
    const [a, b] = await Promise.all([g.request(req()), g.request(req())]);
    expect(maxOpen).toBe(1);
    expect(a.approved).toBe(true);
    // ikinci istek ilki bittikten sonra sorulur ve bütçe aşımını görür: 'evet' doğrulama ifadesi değildir → ret
    expect(b).toMatchObject({ approved: false });
    expect(ttys[1]?.shown()).toContain(CONFIRM_PHRASE);
    // reddedilen/hatalı istek kuyruğu kilitlemez
    ttys.length = 0;
    expect((await gateWith(fakeTty(["evet"])).request(req())).approved).toBe(true);
  });

  it("özet: model/argüman kaynaklı kontrol karakterleri ve ANSI temizlenir; taint uyarısı görünür", () => {
    const evil = summary({ argsRedacted: { x: "\u001b[2J\u001b]8;;http://evil.invalid\u0007gizli\u001b]8;;\u0007 \u202Eters" }, taintedContext: true, citedEvidence: [{ id: "ev-9", summary: "\u001b[31mkırmızı" }] });
    const text = renderSummary(evil, { index: 1, expiresInSec: 300 });
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u202E");
    expect(text).not.toContain("\u0007");
    expect(text).not.toMatch(/\\u001b|\\u0007/); // kaçışlı (JSON) biçimde de kalmaz
    expect(text).toContain("UNTRUSTED");
  });

  it("Faz 2a: özet diff/etki/geri alma/sürüm gösterir; diff kısaltılır ama kısaltma ve hash notu belirtilir; kontrol karakterleri temizlenir", () => {
    const diff = Array.from({ length: 90 }, (_, i) => `${i % 2 ? "+" : "-"} satır ${i}`).join("\n") + "\n+ \u001b[31mkırmızı\u001b[0m";
    const text = renderSummary(summary({ preview: { targetVersion: "rv-42", diff, impact: ["2 replika → 5"], rollback: "kubectl scale deploy/api --replicas=2" } }), { index: 1, expiresInSec: 300 });
    expect(text).toContain("Hedef sürüm: rv-42");
    expect(text).toContain("Etki:      2 replika → 5");
    expect(text).toContain("Geri alma: kubectl scale deploy/api --replicas=2");
    expect(text).toContain("Diff:");
    expect(text).toContain("  - satır 0");
    expect(text).not.toContain("satır 70"); // ilk 60 satır
    expect(text).toMatch(/… \(\d+ satır daha; eylem hash'i diff'in TAMAMINI kapsar\)/);
    expect(text).not.toContain("\u001b");
  });

  it("start/end olayları yayılır (sohbet girdisini duraklatmak için)", async () => {
    const tty = fakeTty(["evet"]);
    const g = gateWith(tty);
    const seen: string[] = [];
    g.events.on("start", () => seen.push("start"));
    g.events.on("end", () => seen.push("end"));
    await g.request(req());
    expect(seen).toEqual(["start", "end"]);
  });
});

describe("onay + PEP + orkestratör (taint yükseltme)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  const toolTurn = (calls: { id: string; name: string; args: unknown }[]) => ({
    message: { content: "", toolCalls: calls },
    usage: { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 },
    stopReason: "tool_use" as const,
  });
  const script = () => [
    toolTurn([{ id: "a", name: "skill.load", args: { name: "kubernetes" } }]),
    toolTurn([{ id: "b", name: "k8s.pods.logs", args: { namespace: "payments", pod: "api-7d9c-a1", since: "30m" } }]),
    // log enjeksiyonu sonrası model daha hassas veriyi (Secret listesi) okumaya kalkar
    toolTurn([{ id: "c", name: "k8s.resources.list", args: { kind: "Secret", namespace: "payments" } }]),
    say("tamam"),
  ];

  async function runWith(answers: string[]) {
    const tty = fakeTty(answers);
    const gate = new TtyApprovalGate({ openTty: async () => tty.io, sleep: async () => undefined });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, approval: gate });
    await rt.bindProfile("payments-sbx");
    const orch = rt.createOrchestrator(new ScriptedProvider(script(), { trustZone: "local" }));
    const ev: OrchestratorEvent[] = [];
    for await (const e of orch.send("logları incele")) ev.push(e);
    await rt.close();
    return { ev, tty, gate };
  }

  it("untrusted log sonrası daha hassas okuma ASK olur; onaylanırsa çalışır ve denetime 'approval' yazılır", async () => {
    const { ev, tty, gate } = await runWith(["e"]);
    const results = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
    expect(results.map((r) => r.status)).toEqual(["ok", "ok", "ok"]);
    expect(tty.shown()).toContain("taint_escalation");
    expect(tty.shown()).toContain("UNTRUSTED");
    expect(gate.summaryLine()).toContain("1 onay");
    const audit = await (await import("node:fs/promises")).readFile(fx.rt.paths.auditLog, "utf8");
    expect(audit).toContain('"event":"approval"');
    expect(audit).toContain('"decision":"allow"');
  });

  it("reddedilirse çağrı ÇALIŞMAZ ve model approval_denied görür", async () => {
    const { ev } = await runWith([""]);
    const last = (ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[]).at(-1)!;
    expect(last).toMatchObject({ status: "denied", reasonCode: "approval_denied" });
    expect(fx.api.requests.some((q) => q.path.includes("/secrets"))).toBe(false);
  });
});

describe("ops explain-policy", () => {
  it("her sebep kodunun açıklaması var", () => {
    for (const c of REASON_CODES) expect(explainReason(c).length, c).toBeGreaterThan(20);
    expect(explainReason("yok-kod")).toContain("Bilinmeyen");
  });

  it("CLI: --code ve --last (denetimden)", async () => {
    const fx = await makeFixture();
    try {
      await fx.rt.bindProfile("payments-sbx");
      const orch = fx.rt.createOrchestrator(new ScriptedProvider([
        { message: { content: "", toolCalls: [{ id: "x", name: "k8s.resources.delete", args: {} }] }, usage: { inputTokens: 0, outputTokens: 1, cacheReadTokens: 0 }, stopReason: "tool_use" },
        say("reddedildi"),
      ], { trustZone: "local" }));
      for await (const _ of orch.send("sil")) void _;
      await fx.rt.close();
      const run = async (argv: string[]) => {
        const o = new PassThrough();
        const chunks: string[] = [];
        o.on("data", (b: Buffer) => chunks.push(b.toString()));
        const code = await runCli({ argv, env: {}, io: { input: new PassThrough(), output: o, error: new PassThrough() }, paths: resolvePaths(fx.rt.paths.home), store: fx.store, sandbox: null });
        return { code, out: chunks.join("") };
      };
      const code = await run(["explain-policy", "--code", "ceiling_exceeded"]);
      expect(code.out).toContain("sınıf tavanını");
      const last = await run(["explain-policy", "--last", "5"]);
      expect(last.out).toContain("k8s.resources.delete");
      expect(last.out).toContain("unknown_tool");
      expect(last.out).toContain("araç seti etkin değil");
    } finally {
      await fx.cleanup();
    }
  });
});
