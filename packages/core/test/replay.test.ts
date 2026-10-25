import { describe, expect, it } from "vitest";
import { AuditRecordSchema } from "@ops/contracts";
import type { AuditRecord, PolicyDecision } from "@ops/contracts";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import type { PolicyDocument } from "@ops/policy";
import { FakeApprovalGate } from "@ops/testkit";
import { buildReplay, lastSessionId, renderReplay } from "../src/index.ts";
import type { WhatIfDeps } from "../src/index.ts";
import { makeHarness } from "./harness.ts";
import type { Harness } from "./harness.ts";

const handlers = {
  "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }),
  "k8s.pods.logs": () => ({ data: "2026-01-01T00:00:00Z ERROR x" }),
};

const parsed = async (h: Harness): Promise<AuditRecord[]> => (await h.records()).map((r) => AuditRecordSchema.parse(r));

const depsFor = (h: Harness, doc: PolicyDocument): WhatIfDeps => {
  let at = new Date();
  const engine = new PolicyEngine(doc, { now: () => at });
  return {
    policyHash: engine.versionHash,
    decide: (input, when): PolicyDecision => {
      at = when;
      return engine.decide(input);
    },
    tool: (n) => h.registry.get(n)?.def.descriptor,
    profile: (id) => (id === h.profile.id ? h.profile : id === h.dbProfile.id ? h.dbProfile : undefined),
  };
};

/** Karışık bir oturum: okuma, onaylı mutasyon, tavan reddi, untrusted log sonrası başka profil okuması (taint → ask). */
async function mixedSession(): Promise<Harness> {
  const h = await makeHarness({ handlers, profile: { classCeiling: "mutate" }, approval: new FakeApprovalGate() });
  const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
  await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 2 }, { cited: [ev] }); // ask → onay → ok
  await h.call("k8s.resources.delete", { namespace: "payments", kind: "Deployment", name: "api" }, { cited: [ev] }); // ceiling_exceeded
  await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" }); // untrusted → bağlam tainted
  h.session.bind(h.dbProfile);
  await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db" }); // taint sonrası başka profile okuma → ask (onay)
  return h;
}

describe("replay: denetimden eylem zaman çizelgesi", () => {
  it("çizelge, istatistik ve sorunsuz tutarlılık denetimi", async () => {
    const h = await mixedSession();
    const rep = buildReplay(await parsed(h), { sessionId: h.session.id });
    expect(rep.sessionId).toBe("s-test");
    const lines = rep.timeline.map((e) => e.line).join("\n");
    expect(lines).toContain("→ k8s.resources.list [read]");
    expect(lines).toContain("→ k8s.scale [mutate]");
    expect(lines).toContain("onay VERİLDİ");
    expect(lines).toContain("REDDEDİLDİ [ceiling_exceeded]");
    expect(rep.stats.calls).toBe(5);
    expect(rep.stats.approvals).toEqual({ allow: 2, deny: 0 });
    expect(rep.stats.deniedByReason).toEqual({ ceiling_exceeded: 1 });
    expect(rep.stats.byDecision).toMatchObject({ allow: 2, ask: 2, deny: 1 });
    expect(rep.anomalies).toEqual([]);
    const text = renderReplay(rep, { chain: "DOĞRU (n kayıt)" });
    expect(text).toContain("Araçlar yeniden ÇAĞRILMADI");
    expect(text).toContain("sorun yok");
  });

  it("lastSessionId ve oturum süzme: başka oturumun kayıtları karışmaz", async () => {
    const a = await mixedSession();
    const recs = await parsed(a);
    const other = recs.map((r) => ({ ...r, sessionId: "baska", seq: r.seq + 1000 }));
    expect(lastSessionId([...recs, ...other])).toBe("baska");
    expect(buildReplay([...recs, ...other], { sessionId: "s-test" }).records).toBe(recs.length);
  });

  it("tutarlılık denetimleri: intent'siz sonuç, onaysız çalışan 'ask', local-only'de okuma dışı, prod'da onaysız izin, yarım kalan intent", () => {
    const base = { principal: "local-user", ts: "2026-03-01T10:00:00.000Z", sessionId: "x", prevHash: "0".repeat(64), hash: "1".repeat(64) };
    let seq = 0;
    const r = (o: Record<string, unknown>): AuditRecord => AuditRecordSchema.parse({ ...base, seq: seq++, ...o });
    const recs = [
      r({ event: "session_start", message: "egress=local-only sandbox=bwrap" }),
      r({ event: "result", callId: "c1", tool: "k8s.scale", exitStatus: "ok" }), // intent yok
      r({ event: "intent", callId: "c2", tool: "k8s.scale", class: "mutate", decision: "ask", reasonCode: "approval_required", profile: "p", environment: "stage" }),
      r({ event: "result", callId: "c2", tool: "k8s.scale", exitStatus: "ok" }), // onay kaydı yok
      r({ event: "intent", callId: "c3", tool: "k8s.apply", class: "deploy", decision: "allow", reasonCode: "allowed", profile: "p", environment: "prod" }),
      r({ event: "result", callId: "c3", tool: "k8s.apply", exitStatus: "ok" }),
      r({ event: "intent", callId: "c4", tool: "k8s.resources.list", class: "read", decision: "allow", reasonCode: "allowed" }), // sonuç yok
    ];
    const codes = buildReplay(recs, { sessionId: "x" }).anomalies.map((a) => a.code);
    expect(codes).toEqual(expect.arrayContaining(["result_without_intent", "ask_ran_without_approval", "non_read_in_local_only", "prod_allow_without_approval", "intent_without_result"]));
    expect(buildReplay(recs, { sessionId: "x" }).anomalies.filter((a) => a.severity === "high").length).toBeGreaterThanOrEqual(4);
  });
});

describe("replay --policy: kayıtlı kararların aday politikayla yeniden değerlendirilmesi", () => {
  it("AYNI politika kararları birebir yeniden üretir (karar girdisi eksiksiz kaydedilmiş)", async () => {
    const h = await mixedSession();
    const rep = buildReplay(await parsed(h), { sessionId: "s-test", whatIf: depsFor(h, DEFAULT_POLICY) });
    expect(rep.whatIf!.compared).toBe(5);
    expect(rep.whatIf!.changed).toEqual([]);
    expect(rep.whatIf!.skipped).toEqual([]);
  });

  it("daha sıkı aday politika: okuma çağrısı 'deny' olur → 'stricter'", async () => {
    const h = await mixedSession();
    const strict: PolicyDocument = { ...DEFAULT_POLICY, rules: [{ id: "no-list", effect: "deny", when: { tool: "k8s.resources.list" } }] };
    const rep = buildReplay(await parsed(h), { sessionId: "s-test", whatIf: depsFor(h, strict) });
    const ch = rep.whatIf!.changed.find((c) => c.tool === "k8s.resources.list")!;
    expect(ch).toMatchObject({ direction: "stricter", recorded: { effect: "allow" }, candidate: { effect: "deny", reasonCode: "policy_deny" } });
    expect(renderReplay(rep)).toContain("▲ sıkılaşır");
  });

  it("daha gevşek aday politika: dar allow kuralı mutasyonu 'ask'tan 'allow'a çeker → 'looser' (riskli yön vurgulanır)", async () => {
    const h = await makeHarness({ handlers, profile: { classCeiling: "mutate", environment: "sandbox" }, approval: new FakeApprovalGate() });
    const ev = (await h.call("k8s.resources.list", { kind: "Deployment", namespace: "payments" })).evidenceId!;
    await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 2 }, { cited: [ev] });
    const loose: PolicyDocument = { ...DEFAULT_POLICY, rules: [{ id: "allow-scale", effect: "allow", when: { tool: "k8s.scale", profile: "test-k8s", class: ["mutate"] } }] };
    const rep = buildReplay(await parsed(h), { sessionId: "s-test", whatIf: depsFor(h, loose) });
    const ch = rep.whatIf!.changed.find((c) => c.tool === "k8s.scale")!;
    expect(ch).toMatchObject({ direction: "looser", recorded: { effect: "ask" }, candidate: { effect: "allow" } });
    expect(renderReplay(rep)).toContain("⚠ GEVŞER");
  });

  it("aday politika tavan/araç/profil kaybını sezer: kayıtlı olmayan araç veya profil 'atlandı' olur", async () => {
    const h = await mixedSession();
    const deps: WhatIfDeps = { ...depsFor(h, DEFAULT_POLICY), tool: (n) => (n === "k8s.scale" ? undefined : h.registry.get(n)?.def.descriptor), profile: () => undefined };
    const rep = buildReplay(await parsed(h), { sessionId: "s-test", whatIf: deps });
    expect(rep.whatIf!.skipped.length).toBeGreaterThan(0);
    expect(rep.whatIf!.skipped.some((s) => s.why.includes("araç artık kayıtlı değil"))).toBe(true);
    expect(rep.whatIf!.skipped.some((s) => s.why.includes("profil artık kayıtlı değil"))).toBe(true);
  });

  it("politika dışı retler (egress, atıf) karar girdisi taşımaz ve what-if'te sahte fark üretmez", async () => {
    const h = await makeHarness({ handlers, profile: { classCeiling: "mutate" }, approval: new FakeApprovalGate() });
    const r = await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 2 }); // atıf yok → citation_missing
    expect(r.reasonCode).toBe("citation_missing");
    const recs = await parsed(h);
    expect(recs.find((x) => x.reasonCode === "citation_missing")?.decisionContext).toBeUndefined();
  });
});
