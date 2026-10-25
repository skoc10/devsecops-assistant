import { describe, expect, it } from "vitest";
import type { DoctorReport, Profile } from "@ops/contracts";
import { FakeApprovalGate } from "@ops/testkit";
import { BreakGlassController, breakGlassBanner, renderBreakGlassReview } from "../src/index.ts";
import { makeHarness } from "./harness.ts";

const handlers = { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) };
const scale = { namespace: "payments", name: "api", replicas: 5 };

class Clock {
  t = Date.parse("2026-10-24T12:00:00Z");
  now = (): Date => new Date(this.t);
  advance(sec: number): void {
    this.t += sec * 1000;
  }
}

const okDoctor = async (p: Profile): Promise<DoctorReport> => ({ profileId: p.id, checkedAt: "x", connected: true, pinOk: true, declaredCeiling: p.classCeiling, scopesChecked: [], findings: [], bindable: true });
const badDoctor = async (p: Profile): Promise<DoctorReport> => ({ profileId: p.id, checkedAt: "x", connected: true, pinOk: true, declaredCeiling: p.classCeiling, scopesChecked: [], findings: [{ severity: "error", code: "superuser", message: "x" }], bindable: false });

async function setup(opts: { doctor?: (p: Profile) => Promise<DoctorReport>; gate?: FakeApprovalGate; ceiling?: "read" | "mutate" | "deploy" } = {}) {
  const clock = new Clock();
  const gate = opts.gate ?? new FakeApprovalGate();
  const h = await makeHarness({ profile: { classCeiling: opts.ceiling ?? "read", environment: "stage" }, handlers, approval: gate, now: clock.now });
  const bg = new BreakGlassController({ session: h.session, audit: h.audit, doctor: opts.doctor ?? okDoctor, now: clock.now, newId: () => "bg-test0001" });
  const req = (over: Partial<Parameters<BreakGlassController["start"]>[0]> = {}) => ({
    profileId: "test-k8s",
    ceiling: "mutate" as const,
    reason: "INC-4242 payments api ölçeklenmeli",
    ttlSec: 600,
    reauth: { method: "vault-passphrase", verifiedAt: clock.now() },
    ...over,
  });
  return { h, clock, gate, bg, req };
}

describe("S-11: break-glass", () => {
  it("gerekçesiz, kısa gerekçeli, TTL'siz/aşırı TTL'li, yeniden doğrulamasız ve tavanı yükseltmeyen istek REDDEDİLİR; hiçbir şey değişmez", async () => {
    const { h, bg, req, clock } = await setup();
    const before = h.session.getBound("test-k8s")!.classCeiling;
    await expect(bg.start(req({ reason: "" }))).rejects.toMatchObject({ code: "break_glass_reason" });
    await expect(bg.start(req({ reason: "acil" }))).rejects.toMatchObject({ code: "break_glass_reason" });
    await expect(bg.start(req({ reason: "gerekçe\u001b[31m kırmızı metin buraya" }))).rejects.toMatchObject({ code: "break_glass_reason" });
    for (const ttlSec of [0, 59, 1801, 86_400, 1.5, Number.NaN]) await expect(bg.start(req({ ttlSec })), String(ttlSec)).rejects.toMatchObject({ code: "break_glass_ttl" });
    await expect(bg.start(req({ reauth: { method: "vault-passphrase", verifiedAt: new Date(clock.t - 61_000) } }))).rejects.toMatchObject({ code: "break_glass_reauth" });
    await expect(bg.start(req({ reauth: { method: "vault-passphrase", verifiedAt: new Date(clock.t + 5_000) } }))).rejects.toMatchObject({ code: "break_glass_reauth" });
    await expect(bg.start(req({ reauth: { method: "", verifiedAt: clock.now() } }))).rejects.toMatchObject({ code: "break_glass_reauth" });
    await expect(bg.start(req({ ceiling: "read" }))).rejects.toMatchObject({ code: "break_glass_ceiling" });
    await expect(bg.start(req({ profileId: "nope" }))).rejects.toMatchObject({ code: "profile_not_bound" });
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe(before);
    expect(h.session.breakGlass.size).toBe(0);
    expect((await h.records()).filter((r) => r["event"] === "break_glass")).toHaveLength(0);
  });

  it("doktor yükseltilmiş tavanı fiili yetkiyle bağdaştıramazsa başlamaz", async () => {
    const { h, bg, req } = await setup({ doctor: badDoctor });
    await expect(bg.start(req())).rejects.toMatchObject({ code: "break_glass_doctor" });
    expect(h.session.breakGlass.size).toBe(0);
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe("read");
  });

  it("DENETİM YAZILAMIYORSA break-glass başlamaz (fail-closed) ve tavan yükselmez", async () => {
    const { h, req } = await setup();
    const failing = new BreakGlassController({ session: h.session, audit: { append: async () => Promise.reject(new Error("disk dolu")) }, doctor: okDoctor });
    await expect(failing.start({ ...req(), reauth: { method: "vault-passphrase", verifiedAt: new Date() } })).rejects.toMatchObject({ code: "audit_unavailable" });
    expect(h.session.breakGlass.size).toBe(0);
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe("read");
  });

  it("başlatma: tavan yalnız o profil için yükselir, çağ (epoch) DEĞİŞMEZ, denetime gerekçe+süre+yöntem yazılır; ikinci başlatma ret", async () => {
    const { h, bg, req } = await setup();
    const epoch = h.session.epoch;
    const g = await bg.start(req());
    expect(g).toMatchObject({ id: "bg-test0001", profileId: "test-k8s", reauth: "vault-passphrase" });
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe("mutate");
    expect(h.session.epoch).toBe(epoch);
    const rec = (await h.records()).find((r) => r["event"] === "break_glass");
    expect(rec).toMatchObject({ profile: "test-k8s", breakGlass: "bg-test0001", decision: "allow" });
    expect(String(rec!["message"])).toMatch(/tavan read→mutate süre 600sn yeniden-doğrulama=vault-passphrase.*INC-4242/);
    await expect(bg.start(req())).rejects.toMatchObject({ code: "break_glass_active" });
    expect(bg.status()).toEqual([expect.objectContaining({ profileId: "test-k8s", from: "read", to: "mutate", remainingSec: 600 })]);
    expect(breakGlassBanner(bg.status()[0]!)).toMatch(/BREAK-GLASS ETKİN: test-k8s \[stage\] tavan read → mutate, kalan 10:00/);
  });

  it("etkinken mutasyon çalışır AMA yine onay ister (onay ekranı break-glass'i gösterir); her denetim kaydı etiketlidir; redaksiyon/atıf kuralları sürer", async () => {
    const { h, bg, req, gate } = await setup();
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    // break-glass öncesi: tavan read → mutasyon ret
    expect(await h.call("k8s.scale", scale, { cited: [ev] })).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    await bg.start(req());
    // atıfsız çağrı hâlâ reddedilir (break-glass atıf kuralını kapatmaz)
    expect(await h.call("k8s.scale", scale)).toMatchObject({ status: "denied", reasonCode: "citation_missing" });
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(gate.requests).toHaveLength(1);
    expect(gate.requests[0]!.summary.breakGlass).toMatchObject({ id: "bg-test0001", originalCeiling: "read", reason: expect.stringContaining("INC-4242") });
    // yine de 'deploy' (> yükseltilmiş tavan) reddedilir
    expect(await h.call("k8s.resources.delete", { namespace: "payments", kind: "Deployment", name: "api" }, { cited: [ev] })).toMatchObject({ reasonCode: "ceiling_exceeded" });
    const recs = await h.records();
    const tagged = recs.filter((x) => x["breakGlass"] === "bg-test0001" && x["event"] !== "break_glass");
    expect(tagged.some((x) => x["event"] === "intent" && x["tool"] === "k8s.scale")).toBe(true);
    expect(tagged.some((x) => x["event"] === "approval")).toBe(true);
    expect(tagged.some((x) => x["event"] === "result" && x["tool"] === "k8s.scale" && x["exitStatus"] === "ok")).toBe(true);
    expect(tagged.some((x) => x["event"] === "lease")).toBe(true);
    // break-glass ÖNCESİ kayıtlar etiketsiz
    const first = recs.find((x) => x["tool"] === "k8s.resources.list");
    expect(first!["breakGlass"]).toBeUndefined();
  });

  it("TTL dolunca tavan OTOMATİK düşer (PEP'te, ilk çağrıda): denetime 'expired' yazılır, sonraki mutasyon yine reddedilir", async () => {
    const { h, bg, req, clock } = await setup();
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    await bg.start(req({ ttlSec: 120 }));
    expect((await h.call("k8s.scale", scale, { cited: [ev] })).status).toBe("ok");
    clock.advance(121);
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(h.session.breakGlass.size).toBe(0);
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe("read");
    const ends = (await h.records()).filter((x) => x["event"] === "break_glass" && x["decision"] === "deny");
    expect(ends).toHaveLength(1);
    expect(String(ends[0]!["message"])).toContain("expired");
  });

  it("onay beklenirken süre dolarsa çağrı ÇALIŞMAZ (yükseltilmiş tavanla verilen karar geçersiz)", async () => {
    const clock = new Clock();
    let bgRef: BreakGlassController | undefined;
    const gate = new FakeApprovalGate(() => {
      clock.advance(700); // kullanıcı onay verene dek süre doldu
      return true;
    });
    const h = await makeHarness({ profile: { classCeiling: "read", environment: "stage" }, handlers, approval: gate, now: clock.now });
    bgRef = new BreakGlassController({ session: h.session, audit: h.audit, doctor: okDoctor, now: clock.now });
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    await bgRef.start({ profileId: "test-k8s", ceiling: "mutate", reason: "INC-9 acil ölçekleme gerekiyor", ttlSec: 600, reauth: { method: "vault-passphrase", verifiedAt: clock.now() } });
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });

  it("elle bitirme ve oturum sonu: tavan geri döner, bitiş denetlenir; bitiş denetimi yazılamasa bile tavan düşer (fail-safe)", async () => {
    const { h, bg, req } = await setup();
    await bg.start(req());
    const ended = await bg.end("test-k8s", "user");
    expect(ended?.id).toBe("bg-test0001");
    expect(h.session.getBound("test-k8s")!.classCeiling).toBe("read");
    expect(await bg.end("test-k8s")).toBeUndefined();
    // denetim bozuk: yine de düşer
    const s2 = await setup();
    await s2.bg.start(s2.req());
    const broken = new BreakGlassController({ session: s2.h.session, audit: { append: async () => Promise.reject(new Error("x")) }, doctor: okDoctor });
    await broken.endAll();
    expect(s2.h.session.getBound("test-k8s")!.classCeiling).toBe("read");
  });

  it("inceleme dosyası DENETİM KAYITLARINDAN üretilir: gerekçe, süre, etiketli çağrılar, reddedilenler", async () => {
    const { h, bg, req } = await setup();
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    expect(renderBreakGlassReview(await h.records() as never, h.session.id)).toBeNull();
    await bg.start(req());
    await h.call("k8s.scale", scale, { cited: [ev] });
    await h.call("k8s.resources.delete", { namespace: "payments", kind: "Deployment", name: "api" }, { cited: [ev] });
    await bg.end("test-k8s", "user");
    const md = renderBreakGlassReview(await h.records() as never, h.session.id)!;
    expect(md).toContain("# Break-glass inceleme");
    expect(md).toContain("## bg-test0001 — profil test-k8s [stage]");
    expect(md).toContain("INC-4242");
    expect(md).toMatch(/\| k8s\.scale \| mutate \| ask \|/);
    expect(md).toMatch(/ceiling_exceeded/);
    expect(md).toContain("neden=user");
    expect(md).toContain("İnceleme listesi");
    // başka oturumun kayıtları karışmaz
    expect(renderBreakGlassReview(await h.records() as never, "baska-oturum")).toBeNull();
  });
});
