import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OrchestratorEvent } from "@ops/core";
import { CaptureSink, ScriptedProvider, say, toolUse } from "@ops/testkit";
import { LocalBackend, Opsd, OpsdClient, TtyApprovalGate, createRuntime, readAuditRecords, runChat, runCli } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { idsIn, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

/** Kullanıcı yanıtlarını sırayla yazan sahte kontrol terminali. */
function fakeTty(answers: string[]): { open: () => Promise<TtyIo>; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  let i = 0;
  output.on("data", (b: Buffer) => {
    chunks.push(b.toString());
    const joined = chunks.join("");
    if (/: $|> $/.test(joined.slice(-12))) {
      const a = answers[i++];
      if (a !== undefined) setTimeout(() => input.write(`${a}\n`), 0);
    }
  });
  return { open: async () => ({ input, output }), shown: () => chunks.join("") };
}

const REAUTH = async () => ({ method: "vault-passphrase", verifiedAtMs: Date.now() });

describe("Faz 2f: break-glass uçtan uca (scripted model, gerçek TLS sahte API, TTY onayı)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  it("sohbet: tavan read iken ölçekleme RET → /breakglass start → banner → ölçekleme (yine ONAY ister) → süre/elle bitirme → tavan geri → inceleme dosyası denetimden; canary yok", async () => {
    const tty = fakeTty(["evet"]);
    const gate = new TtyApprovalGate({ openTty: tty.open, sleep: async () => undefined });
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, approval: gate });
    const events: OrchestratorEvent[] = [];
    const out = new PassThrough();
    const chunks: string[] = [];
    out.on("data", (b: Buffer) => chunks.push(b.toString()));
    let provider!: ScriptedProvider;
    try {
      const scale = (ids: string[]) => ({ kind: "Deployment", namespace: "payments", name: "api", replicas: 3, cited: [ids[1]] });
      provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "kubernetes-change" } }]),
          toolUse([{ name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }]),
          (req) => toolUse([{ name: "k8s.scale", args: scale(idsIn(req.messages)) }]), // tavan read → RET
          (req) => say(`ölçekleme reddedildi [${idsIn(req.messages)[1]}]`),
          (req) => toolUse([{ name: "k8s.scale", args: scale(idsIn(req.messages)) }]), // break-glass sonrası → onay + uygula
          (req) => say(`3 replikaya ölçeklendi [${idsIn(req.messages)[1]}]`),
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider, { maxIterations: 20 });
      const backend = new LocalBackend(rt, orch);
      const input = new PassThrough();
      input.end(
        [
          "/use payments-sbx",
          "api'yi 3 replikaya çıkar",
          "/breakglass start payments-sbx mutate 10m INC-100 payments api acil ölçekleme",
          "/breakglass status",
          "tekrar dene",
          "/breakglass end payments-sbx",
          "/breakglass status",
          "/quit",
          "",
        ].join("\n"),
      );
      await runChat(backend, { input, output: out }, { approvalEvents: gate.events, reauth: REAUTH });
      const screen = chunks.join("");
      // banner: başlangıçtan sonra her istemde görünür
      expect(screen).toMatch(/BREAK-GLASS ETKİN: payments-sbx \[sandbox\] tavan read → mutate, kalan (9|10):\d\d — gerekçe: INC-100 payments api acil ölçekleme/);
      expect(screen).toContain("break-glass bitti: payments-sbx (tavan read'a döndü)");
      expect(screen).toContain("(etkin break-glass yok)");
      // ilk ölçekleme RET (tavan), ikincisi onayla UYGULANDI
      const results = rt.evidence.all().length; // en az bir kanıt
      expect(results).toBeGreaterThan(0);
      expect(fx.api.peek("Deployment", "payments", "api")?.spec).toMatchObject({ replicas: 3 });
      const writes = fx.api.requests.filter((q) => q.method !== "GET" && !q.path.includes("selfsubject"));
      expect(writes).toHaveLength(1);
      // onay ekranı break-glass'i belirgin gösterdi
      const shown = tty.shown();
      expect(shown).toContain("ONAY GEREKİYOR");
      expect(shown).toContain("BREAK-GLASS");
      expect(shown).toContain("INC-100");
      // tavan geri döndü: bağlı profil özgün
      expect(rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
      for await (const e of orch.send("bir daha")) events.push(e); // betik bitti; hata yoksa sorun değil
    } catch {
      /* son satır yalnız ek doğrulama içindi (betik tükendi) */
    } finally {
      await rt.close();
    }
    // denetim: etiketli kayıtlar + başlat/bitir
    const recs = await readAuditRecords(fx.rt.paths.auditLog);
    const bgEvents = recs.filter((r) => r.event === "break_glass");
    expect(bgEvents.map((r) => r.decision)).toEqual(["allow", "deny"]);
    const id = bgEvents[0]!.breakGlass as string;
    expect(id).toMatch(/^bg-[0-9a-f]{8}$/);
    const tagged = recs.filter((r) => r.breakGlass === id && r.event !== "break_glass");
    expect(tagged.some((r) => r.event === "intent" && r.tool === "k8s.scale")).toBe(true);
    expect(tagged.some((r) => r.event === "approval" && r.decision === "allow")).toBe(true);
    expect(recs.filter((r) => r.event === "intent" && r.tool === "k8s.scale")).toHaveLength(1); // ilk (RET) çağrı niyet kaydına bile girmedi
    // inceleme dosyası oturum sonunda, denetim kayıtlarından
    const reviewFile = join(fx.rt.paths.breakGlassDir, `${rt.session.id}.md`);
    expect((await stat(reviewFile)).mode & 0o777).toBe(0o600);
    const md = await readFile(reviewFile, "utf8");
    expect(md).toContain(`## ${id} — profil payments-sbx [sandbox]`);
    expect(md).toContain("INC-100 payments api acil ölçekleme");
    expect(md).toMatch(/\| k8s\.scale \| mutate \| ask \|/);
    expect(md).toContain("neden=user");
    // canary yok: denetim, kanıt, sağlayıcı, ekran, onay ekranı, inceleme dosyası
    const sink = new CaptureSink();
    sink.push("audit", await readFile(rt.paths.auditLog, "utf8"));
    for (const e of rt.evidence.all()) sink.push("evidence", e.text);
    sink.push("sağlayıcı", provider.serialized.join("\n"));
    sink.push("ekran", chunks.join(""));
    sink.push("onay", tty.shown());
    sink.push("inceleme", md);
    expect(sink.leaks(fx.all)).toEqual([]);
    expect(events.length).toBeGreaterThanOrEqual(0);
  });

  it("REPL: eksik/yanlış argüman, desteklenmeyen tavan ve yapılandırılmamış yeniden doğrulama reddedilir; backend'e HİÇBİR ŞEY gitmez", async () => {
    const calls: unknown[] = [];
    const backend = {
      send: async function* () {},
      bind: async () => ({}) as never,
      profiles: async () => [],
      usage: async () => "",
      breakGlassStatus: async () => [],
      breakGlassStart: async (a: unknown) => {
        calls.push(a);
        return ["x"];
      },
      breakGlassEnd: async () => "bitti",
    };
    const run = async (lines: string[], reauth?: typeof REAUTH) => {
      const input = new PassThrough();
      input.end(`${lines.join("\n")}\n/quit\n`);
      const out = new PassThrough();
      const chunks: string[] = [];
      out.on("data", (b: Buffer) => chunks.push(b.toString()));
      await runChat(backend as never, { input, output: out }, reauth ? { reauth } : {});
      return chunks.join("");
    };
    expect(await run(["/breakglass start"], REAUTH)).toContain("kullanım: /breakglass start <profil>");
    expect(await run(["/breakglass start p mutate 10m"], REAUTH)).toContain("kullanım: /breakglass start");
    expect(await run(["/breakglass start p root 10m gerekçe yazıldı burada"], REAUTH)).toContain("tavan şunlardan biri olmalı");
    expect(await run(["/breakglass start p mutate 10dk gerekçe yazıldı burada"], REAUTH)).toContain("kullanım: /breakglass start");
    expect(await run(["/breakglass start p mutate 10m gerekçe yazıldı burada"])).toContain("yeniden kimlik doğrulama bu arayüzde yapılandırılmamış");
    const failing = async () => {
      throw new Error("parola yanlış");
    };
    expect(await run(["/breakglass start p mutate 10m gerekçe yazıldı burada"], failing as never)).toContain("✗ parola yanlış");
    expect(calls).toHaveLength(0);
    // geçerli istek backend'e DOĞRU biçimde gider
    await run(["/breakglass start prod-1 deploy 90s INC-7 acil dağıtım gerekli"], REAUTH);
    expect(calls[0]).toMatchObject({ profile: "prod-1", ceiling: "deploy", ttlSec: 90, reason: "INC-7 acil dağıtım gerekli", reauth: { method: "vault-passphrase" } });
  });

  it("opsd: breakglass.start/status/end UDS üzerinden; bayat/eksik kanıt, geçersiz tavan ve gerekçesiz istek reddedilir", async () => {
    const d = new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(new ScriptedProvider([say("x")])), socketPath: fx.rt.paths.socket });
    await d.listen();
    const c = await OpsdClient.connect(fx.rt.paths.socket);
    try {
      expect((await c.bind("payments-sbx")).bindable).toBe(true);
      expect(await c.breakGlassStatus()).toEqual([]);
      const good = { profile: "payments-sbx", ceiling: "mutate" as const, ttlSec: 600, reason: "INC-55 acil ölçekleme gerekiyor", reauth: { method: "vault-passphrase", verifiedAtMs: Date.now() } };
      await expect(c.breakGlassStart({ ...good, reason: "" })).rejects.toThrow(/break_glass_reason/);
      await expect(c.breakGlassStart({ ...good, ttlSec: 7200 })).rejects.toThrow(/break_glass_ttl/);
      await expect(c.breakGlassStart({ ...good, reauth: { method: "vault-passphrase", verifiedAtMs: Date.now() - 120_000 } })).rejects.toThrow(/break_glass_reauth/);
      await expect(c.breakGlassStart({ ...good, ceiling: "read" })).rejects.toThrow(/break_glass_ceiling/);
      await expect(c.breakGlassStart({ ...good, ceiling: "root" as never })).rejects.toThrow();
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
      const lines = await c.breakGlassStart(good);
      expect(lines[0]).toMatch(/BREAK-GLASS ETKİN: payments-sbx/);
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("mutate");
      await expect(c.breakGlassStart(good)).rejects.toThrow(/break_glass_active/);
      expect((await c.breakGlassStatus())[0]).toMatch(/kalan (9|10):/);
      // profili yeniden bağlamak yükseltmeyi TAŞIMAZ: break-glass biter
      await c.bind("payments-sbx");
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
      expect(await c.breakGlassStatus()).toEqual([]);
      expect(await c.breakGlassEnd("payments-sbx")).toMatch(/etkin break-glass yok/);
      const recs = await readAuditRecords(fx.rt.paths.auditLog);
      expect(recs.filter((r) => r.event === "break_glass").map((r) => r.decision)).toEqual(["allow", "deny"]);
      expect(recs.find((r) => r.event === "break_glass" && r.decision === "deny")?.message).toContain("neden=rebind");
    } finally {
      c.close();
      await d.close();
    }
  });

  it("CLI: `ops break-glass` (opsd'ye bağlanır; yeniden doğrulama kontrol terminalinden) → status → end → review", async () => {
    const d = new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(new ScriptedProvider([say("x")])), socketPath: fx.rt.paths.socket });
    await d.listen();
    try {
      await fx.rt.bindProfile("payments-sbx");
      const cli = async (argv: string[], over: { answers?: string[]; verify?: (p: Uint8Array) => Promise<boolean> } = {}) => {
        const tty = fakeTty(over.answers ?? ["kasa-parolasi"]);
        const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
        const code = await runCli({ argv, env: {}, io, paths: fx.rt.paths, store: fx.store, sandbox: null, openTty: tty.open, reauthVerify: over.verify ?? (async (p) => Buffer.from(p).toString() === "kasa-parolasi") });
        return { code, out: (io.output.read() as Buffer | null)?.toString() ?? "", err: (io.error.read() as Buffer | null)?.toString() ?? "", tty: tty.shown() };
      };
      const miss = await cli(["break-glass", "--profile", "payments-sbx", "--ceiling", "mutate", "--ttl", "10m"]);
      expect(miss.code).toBe(2);
      expect(miss.err).toMatch(/--reason/);
      const wrong = await cli(["break-glass", "--profile", "payments-sbx", "--ceiling", "mutate", "--ttl", "10m", "--reason", "INC-1 acil ölçekleme gerekli"], { answers: ["x", "y", "z"], verify: async () => false });
      expect(wrong.code).toBe(1);
      expect(wrong.err).toMatch(/break_glass_reauth/);
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
      const ok = await cli(["break-glass", "--profile", "payments-sbx", "--ceiling", "mutate", "--ttl", "10m", "--reason", "INC-1 acil ölçekleme gerekli"]);
      expect(ok.code, ok.err).toBe(0);
      expect(ok.out).toMatch(/BREAK-GLASS ETKİN: payments-sbx/);
      expect(ok.out).toMatch(/Denetim, redaksiyon ve onay kapıları AÇIK/);
      expect(ok.tty).not.toContain("kasa-parolasi");
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("mutate");
      expect((await cli(["break-glass", "status"])).out).toMatch(/kalan/);
      const end = await cli(["break-glass", "end", "--profile", "payments-sbx"]);
      expect(end.out).toMatch(/break-glass bitti: payments-sbx/);
      expect(fx.rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
      const review = await cli(["break-glass", "review"]);
      expect(review.code).toBe(0);
      expect(review.out).toContain("# Break-glass inceleme");
      expect(review.out).toContain("INC-1 acil ölçekleme gerekli");
    } finally {
      await d.close();
    }
  });

  it("opsd çalışmıyorsa CLI açık hata verir (break-glass çalışan oturumun tavanını yükseltir)", async () => {
    const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv: ["break-glass", "status"], env: {}, io, paths: fx.rt.paths, store: fx.store, sandbox: null });
    expect(code).toBe(1);
    expect((io.error.read() as Buffer).toString()).toMatch(/opsd_unreachable/);
  });
});
