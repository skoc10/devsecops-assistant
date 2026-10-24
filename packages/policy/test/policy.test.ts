import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool, emptyContextLabel } from "@ops/contracts";
import type { ContextLabel, RiskClass, ToolDescriptor, ToolDescriptorMeta } from "@ops/contracts";
import { makeTestProfile } from "@ops/testkit";
import { DEFAULT_POLICY, PolicyEngine, parsePolicy } from "../src/index.ts";
import type { PolicyDocument, PolicyInput } from "../src/index.ts";

function tool(over: Partial<ToolDescriptorMeta> = {}): ToolDescriptor {
  return defineTool(
    {
      name: "k8s.resources.list",
      description: "Listeler.",
      class: "read",
      profileKind: "k8s",
      sensitivity: "internal",
      idempotent: true,
      limits: { timeoutMs: 1000, maxBytes: 1000, maxItems: 10, maxOutputTokens: 1500 },
      untrustedOutput: false,
      toolset: "k8s-core",
      typicalOutputTokens: 100,
      ...over,
    },
    z.strictObject({}),
  ).descriptor;
}

const ctx = (over: Partial<ContextLabel> = {}): ContextLabel => ({ ...emptyContextLabel(), ...over });

function input(over: Partial<PolicyInput> = {}): PolicyInput {
  const profile = over.profile === undefined ? makeTestProfile({ classCeiling: "read" }) : over.profile;
  return {
    tool: tool(),
    effectiveClass: "read",
    unclassified: false,
    profile,
    target: profile ? { profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes: ["payments"], refs: [] } : null,
    context: ctx(),
    ...over,
  };
}

const engine = (rules: PolicyDocument["rules"] = [], now?: () => Date) =>
  new PolicyEngine({ ...DEFAULT_POLICY, rules }, now ? { now } : {});

describe("policy.yaml şeması", () => {
  it("depodaki örnek policy.yaml geçerli ve DEFAULT_POLICY ile tutarlı", async () => {
    const text = await readFile(new URL("../../../policies/policy.yaml", import.meta.url), "utf8");
    expect(parsePolicy(text)).toEqual(DEFAULT_POLICY);
  });

  it.each([
    ["süresiz allow", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 1, hardSessionTokens: 2}\nrules:\n  - {id: a, when: {tool: "k8s.scale", profile: "p"}, effect: allow}`, /expires/],
    ["deploy için allow", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 1, hardSessionTokens: 2}\nrules:\n  - {id: a, when: {tool: "k8s.apply", profile: "p", class: [deploy]}, effect: allow, expires: "2099-01-01T00:00:00Z"}`, /deploy\/destroy/],
    ["geniş allow (profilsiz)", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 1, hardSessionTokens: 2}\nrules:\n  - {id: a, when: {tool: "*"}, effect: allow, expires: "2099-01-01T00:00:00Z"}`, /daraltılmalı/],
    ["soft > hard", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 5, hardSessionTokens: 2}\nrules: []`, /soft/],
    ["yinelenen id", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 1, hardSessionTokens: 2}\nrules:\n  - {id: a, when: {}, effect: deny}\n  - {id: a, when: {}, effect: deny}`, /yinelenen/],
    ["bilinmeyen alan", `version: 1\nbudgets: {maxToolCalls: 1, maxResultTokens: 1, softSessionTokens: 1, hardSessionTokens: 2}\nrules: []\nextra: 1`, /geçersiz/],
    ["bozuk yaml", "version: [", /okunamadı/],
  ])("%s reddedilir", (_n, text, msg) => {
    expect(() => parsePolicy(text)).toThrow(msg);
  });
});

describe("temel kararlar", () => {
  it("okuma serbest", () => {
    expect(engine().decide(input())).toMatchObject({ effect: "allow", reasonCode: "allowed", class: "read" });
  });

  it("mutate+ sınıf profil tavanını aşarsa deny (tavan sert)", () => {
    const d = engine().decide(input({ effectiveClass: "mutate" }));
    expect(d).toMatchObject({ effect: "deny", reasonCode: "ceiling_exceeded" });
  });

  it("tavan izin veriyorsa mutate/deploy/destroy onay ister", () => {
    for (const [cls, ceiling] of [["mutate", "mutate"], ["deploy", "deploy"], ["destroy", "destroy"]] as const) {
      const profile = makeTestProfile({ classCeiling: ceiling });
      expect(engine().decide(input({ profile, effectiveClass: cls }))).toMatchObject({ effect: "ask", reasonCode: "approval_required" });
    }
  });

  it("sınıflanamayan işlem destroy sayılır: read-tavanlı profilde unclassified deny", () => {
    expect(engine().decide(input({ unclassified: true }))).toMatchObject({ effect: "deny", reasonCode: "unclassified", class: "destroy" });
  });

  it("requiresCeiling karşılanmazsa deny", () => {
    const t = tool({ name: "k8s.apply.diff", requiresCeiling: "mutate" });
    expect(engine().decide(input({ tool: t }))).toMatchObject({ effect: "deny", reasonCode: "ceiling_requirement" });
    const ok = makeTestProfile({ classCeiling: "mutate" });
    expect(engine().decide(input({ tool: t, profile: ok }))).toMatchObject({ effect: "allow" });
  });

  it("profilsiz hedef araç reddedilir; yerel okuma serbest, yerel yazma onay ister", () => {
    expect(engine().decide(input({ profile: null, target: null }))).toMatchObject({ effect: "deny", reasonCode: "kind_mismatch" });
    const local = tool({ name: "evidence.get", scope: "local", profileKind: null, sensitivity: "none" });
    expect(engine().decide(input({ tool: local, profile: null, target: null }))).toMatchObject({ effect: "allow" });
    const w = tool({ name: "fs.write", scope: "local", localWrite: true, profileKind: null, sensitivity: "none" });
    expect(engine().decide(input({ tool: w, profile: null, target: null }))).toMatchObject({ effect: "ask", reasonCode: "approval_required" });
  });
});

describe("kurallar", () => {
  it("deny kuralı kazanır", () => {
    const e = engine([{ id: "no-prod", when: { environment: ["sandbox"], tool: "k8s.*" }, effect: "deny" }]);
    expect(e.decide(input())).toMatchObject({ effect: "deny", reasonCode: "policy_deny", detail: "kural: no-prod" });
  });

  it("ask kuralı okumayı sıkılaştırır", () => {
    const e = engine([{ id: "sor", when: { class: ["read"] }, effect: "ask" }]);
    expect(e.decide(input())).toMatchObject({ effect: "ask", reasonCode: "policy_ask" });
  });

  it("scope koşulu hedef kapsamlarıyla eşleşir", () => {
    const e = engine([{ id: "pay", when: { scope: ["pay*"] }, effect: "deny" }]);
    expect(e.decide(input()).effect).toBe("deny");
    const other = input();
    expect(e.decide({ ...other, target: { ...other.target!, scopes: ["default"] } }).effect).toBe("allow");
  });

  const allow = (over: Partial<PolicyDocument["rules"][number]> = {}): PolicyDocument["rules"] => [
    { id: "scale-ok", when: { tool: "k8s.scale", profile: "test-k8s" }, effect: "allow", expires: "2099-01-01T00:00:00Z", ...over },
  ];
  const scale = tool({ name: "k8s.scale", class: "mutate" });
  const mut = (over: Partial<PolicyInput> = {}): PolicyInput =>
    input({ tool: scale, effectiveClass: "mutate", profile: makeTestProfile({ classCeiling: "mutate" }), ...over });

  it("dar allow kuralı mutate için taban onayı gevşetir", () => {
    expect(engine(allow()).decide(mut())).toMatchObject({ effect: "allow", detail: "kural: scale-ok" });
  });

  it("süresi dolmuş allow kuralı uygulanmaz", () => {
    const e = engine(allow({ expires: "2020-01-01T00:00:00Z" }), () => new Date("2026-01-01T00:00:00Z"));
    expect(e.decide(mut())).toMatchObject({ effect: "ask" });
  });

  it("allow kuralı taint yükseltmesini ve tavanı gevşetemez", () => {
    const tainted = mut({ context: ctx({ tainted: true, profilesTouched: ["test-k8s"] }) });
    expect(engine(allow()).decide(tainted)).toMatchObject({ effect: "ask" });
    const noCeiling = mut({ profile: makeTestProfile({ classCeiling: "read" }) });
    expect(engine(allow()).decide(noCeiling)).toMatchObject({ effect: "deny", reasonCode: "ceiling_exceeded" });
  });

  it("deploy için allow kuralı etkisiz (şema da engeller, motor da gevşetmez)", () => {
    const rules = allow({ when: { tool: "k8s.apply", profile: "test-k8s" } });
    const t = tool({ name: "k8s.apply", class: "deploy" });
    const i = input({ tool: t, effectiveClass: "deploy", profile: makeTestProfile({ classCeiling: "deploy" }) });
    expect(engine(rules).decide(i)).toMatchObject({ effect: "ask" });
  });
});

describe("taint yükseltme (T2)", () => {
  const tainted = (over: Partial<ContextLabel> = {}): ContextLabel => ctx({ tainted: true, profilesTouched: ["test-k8s"], maxSensitivity: "internal", ...over });

  it("taint yokken okuma serbest; aynı profil + aynı hassasiyet taint'te de serbest", () => {
    expect(engine().decide(input({ context: tainted() })).effect).toBe("allow");
  });

  it("taint + başka profile okuma → ask", () => {
    const other = makeTestProfile({ id: "prod-db", kind: "db", classCeiling: "read" });
    const t = tool({ name: "db.query.read", profileKind: "db" });
    expect(engine().decide(input({ tool: t, profile: other, context: tainted() }))).toMatchObject({ effect: "ask", reasonCode: "taint_escalation" });
  });

  it("taint + daha hassas veriye okuma → ask", () => {
    const t = tool({ sensitivity: "pii" });
    expect(engine().decide(input({ tool: t, context: tainted() }))).toMatchObject({ effect: "ask", reasonCode: "taint_escalation" });
  });

  it("taint + dış ağ çıkışı → ask; taint + mutasyon → ask (tavan izin veriyorsa)", () => {
    const open = tool({ name: "scm.pr.create", network: "open", class: "mutate" });
    const profile = makeTestProfile({ classCeiling: "mutate" });
    expect(engine().decide(input({ tool: open, effectiveClass: "mutate", profile, context: tainted() })).reasonCode).toBe("approval_required");
    const readOpen = tool({ name: "web.fetch.get", network: "allowlisted" });
    expect(engine().decide(input({ tool: readOpen, context: tainted() })).effect).toBe("allow");
  });

  it("taint olmadan başka profile okuma serbest", () => {
    const other = makeTestProfile({ id: "prod-db", kind: "db" });
    const t = tool({ name: "db.query.read", profileKind: "db" });
    expect(engine().decide(input({ tool: t, profile: other, context: ctx({ profilesTouched: ["test-k8s"] }) })).effect).toBe("allow");
  });
});

describe("determinizm, sürüm ve bütçe", () => {
  it("aynı girdi aynı karar; sürüm hash'i belge değişince değişir", () => {
    const a = engine();
    expect(a.decide(input())).toEqual(a.decide(input()));
    const b = engine([{ id: "x", when: {}, effect: "deny" }]);
    expect(a.versionHash).toMatch(/^[a-f0-9]{64}$/);
    expect(a.versionHash).not.toBe(b.versionHash);
    expect(a.versionHash).toBe(engine().versionHash);
  });

  it("bütçe denetimi: çağrı sayısı, sert/yumuşak token eşiği", () => {
    const e = engine();
    expect(e.checkBudget({ toolCalls: 0, sessionTokens: 0 })).toEqual({ ok: true, soft: false });
    expect(e.checkBudget({ toolCalls: 0, sessionTokens: 150_000 })).toEqual({ ok: true, soft: true });
    expect(e.checkBudget({ toolCalls: 0, sessionTokens: 400_000 })).toEqual({ ok: false, reason: "token_budget_exceeded" });
    expect(e.checkBudget({ toolCalls: 60, sessionTokens: 0 })).toEqual({ ok: false, reason: "call_budget_exceeded" });
  });

  it("sonuç token tavanı araç ve politika tavanının küçüğü", () => {
    const e = engine();
    expect(e.resultTokenCap(tool())).toBe(1500);
    expect(e.resultTokenCap(tool({ limits: { timeoutMs: 1, maxBytes: 1, maxItems: 1, maxOutputTokens: 300 } }))).toBe(300);
  });

  it("tüm risk sınıfları için karar tanımlı (kapsamlılık)", () => {
    for (const cls of ["read", "mutate", "deploy", "destroy"] as RiskClass[]) {
      const profile = makeTestProfile({ classCeiling: "destroy" });
      expect(["allow", "ask", "deny"]).toContain(engine().decide(input({ profile, effectiveClass: cls })).effect);
    }
  });
});

describe("çağrıya özgü hassasiyet (effectiveSensitivity)", () => {
  const engine = new PolicyEngine(DEFAULT_POLICY);
  it("untrusted bağlamda araç tanımı 'internal' olsa bile çağrı 'secret-adjacent' ise ask", () => {
    const c = ctx({ tainted: true, maxSensitivity: "internal", profilesTouched: ["test-k8s"] });
    expect(engine.decide(input({ context: c })).effect).toBe("allow");
    const d = engine.decide(input({ context: c, effectiveSensitivity: "secret-adjacent" }));
    expect(d).toMatchObject({ effect: "ask", reasonCode: "taint_escalation" });
    expect(d.detail).toMatch(/daha hassas/);
  });
  it("temiz bağlamda yükseltme yok", () => {
    expect(engine.decide(input({ context: ctx({ tainted: false }), effectiveSensitivity: "secret-adjacent" })).effect).toBe("allow");
  });
});
