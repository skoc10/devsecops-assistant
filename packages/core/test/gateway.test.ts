import { describe, expect, it } from "vitest";
import { verifyAudit } from "@ops/audit";
import { FakeApprovalGate, makeCanary, makeTestProfile } from "@ops/testkit";
import { DEFAULT_POLICY } from "@ops/policy";
import { AUDIT_KEY, collect, makeHarness } from "./harness.ts";

const ns = { kind: "Pod", namespace: "payments" };

describe("PEP temel akış", () => {
  it("izinli okuma: kompakt görünüm, kanıt kimliği, lease bırakıldı, denetim zinciri geçerli", async () => {
    const h = await makeHarness();
    const r = await h.call("k8s.resources.list", ns);
    expect(r.status).toBe("ok");
    expect(r.evidenceId).toBe("ev-1");
    expect(r.view).toEqual({ columns: ["metadata", "status"], rows: [[{ name: "api-1" }, { phase: "Running" }], [{ name: "api-2" }, { phase: "Failed" }]] });
    expect(h.broker.acquired).toHaveLength(1);
    expect(h.broker.active).toBe(0);
    expect(h.k8s.calls[0]?.handle).toMatchObject({ kind: "credential-handle", profileId: "test-k8s" });

    const recs = await h.records();
    expect(recs.map((x) => `${x["event"]}${x["message"] ? `:${x["message"]}` : ""}`)).toEqual(["intent", "lease:acquired", "lease:released", "result"]);
    expect(recs[0]).toMatchObject({ tool: "k8s.resources.list", class: "read", decision: "allow", profile: "test-k8s", environment: "sandbox" });
    expect(typeof recs[0]?.["policyVersionHash"]).toBe("string");
    expect(typeof recs[0]?.["actionHash"]).toBe("string");
    expect(recs[3]).toMatchObject({ exitStatus: "ok" });
    expect((await verifyAudit(h.storage, AUDIT_KEY, h.anchor)).ok).toBe(true);
  });

  it("select yalnız selectable projeksiyonda alan kümesini genişletir", async () => {
    const h = await makeHarness({
      handlers: { "k8s.resources.list": () => ({ data: [{ metadata: { name: "a", uid: "u1" }, status: { phase: "Running", podIP: "10.0.0.1" } }] }) },
    });
    const wide = await h.call("k8s.resources.list", { ...ns, select: ["metadata.name", "status.podIP"] });
    expect(JSON.stringify(wide.view)).toContain("10.0.0.1");
    const narrow = await h.call("k8s.resources.list", ns);
    expect(JSON.stringify(narrow.view)).not.toContain("10.0.0.1");
  });
});

describe("S-03: sınıf tavanı (sert)", () => {
  it("read-tavanlı profil mutate/destroy aracını çağıramaz; adapter ve broker'a dokunulmaz", async () => {
    const h = await makeHarness();
    const a = await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 0 });
    const b = await h.call("k8s.resources.delete", { namespace: "payments", kind: "Deployment", name: "api" });
    expect(a).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(b).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
    expect(h.k8s.calls).toHaveLength(0);
    expect(h.broker.acquired).toHaveLength(0);
    const recs = await h.records();
    expect(recs.every((r) => r["decision"] === "deny")).toBe(true);
    expect(recs.map((r) => r["class"])).toEqual(["mutate", "destroy"]);
  });

  it("sınıflayıcı sınıfı yükseltirse (read araç → mutate komut) tavan yine reddeder", async () => {
    const h = await makeHarness({ classifiers: [() => "mutate"] });
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ status: "denied", reasonCode: "ceiling_exceeded" });
  });

  it("sınıflanamayan komut destroy muamelesi görür", async () => {
    const h = await makeHarness({ classifiers: [() => "unclassified"] });
    const r = await h.call("k8s.resources.list", ns);
    expect(r).toMatchObject({ status: "denied", reasonCode: "unclassified" });
    expect((await h.records())[0]).toMatchObject({ class: "destroy" });
  });
});

describe("mutasyon: atıf + onay (Faz 2 yolu, kapı sahteyle)", () => {
  const profile = { classCeiling: "mutate" as const };
  const handlers = { "k8s.resources.list": () => ({ data: [{ metadata: { name: "api" } }], subjects: ["Deployment/payments/api"] }) };
  const scale = { namespace: "payments", name: "api", replicas: 3 };

  it("kanıt atfı yoksa reddedilir (citation_missing)", async () => {
    const h = await makeHarness({ profile, handlers, approval: new FakeApprovalGate() });
    expect(await h.call("k8s.scale", scale)).toMatchObject({ status: "denied", reasonCode: "citation_missing" });
  });

  it("onay kapısı yoksa ask reddedilir (Faz 0 davranışı)", async () => {
    const h = await makeHarness({ profile, handlers });
    const ev = (await h.call("k8s.resources.list", ns)).evidenceId!;
    expect(await h.call("k8s.scale", scale, { cited: [ev] })).toMatchObject({ status: "denied", reasonCode: "approval_unavailable" });
    expect(h.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });

  it("atıf + onay ile çalışır; onay kanonik özet ve eylem hash'i taşır", async () => {
    const gate = new FakeApprovalGate();
    const h = await makeHarness({ profile, handlers, approval: gate });
    const ev = (await h.call("k8s.resources.list", ns)).evidenceId!;
    const r = await h.call("k8s.scale", scale, { cited: [ev] });
    expect(r.status).toBe("ok");
    expect(gate.requests).toHaveLength(1);
    const req = gate.requests[0]!;
    expect(req.summary).toMatchObject({ tool: "k8s.scale", class: "mutate", why: "approval_required", taintedContext: false });
    expect(req.summary.profile).toMatchObject({ id: "test-k8s", environment: "sandbox" });
    expect(req.summary.citedEvidence[0]?.id).toBe(ev);
    const intent = (await h.records()).find((x) => x["tool"] === "k8s.scale" && x["event"] === "intent")!;
    expect(intent).toMatchObject({ decision: "ask", approvalId: "appr-1", actionHash: req.actionHash });
  });

  it("onay reddi veya yanlış eylem hash'i çalıştırmaz", async () => {
    const no = await makeHarness({ profile, handlers, approval: new FakeApprovalGate(() => false) });
    const ev1 = (await no.call("k8s.resources.list", ns)).evidenceId!;
    expect(await no.call("k8s.scale", scale, { cited: [ev1] })).toMatchObject({ reasonCode: "approval_denied" });

    const wrong = await makeHarness({ profile, handlers, approval: new FakeApprovalGate((r) => ({ approved: true, approvalId: "x", actionHash: `${r.actionHash.slice(1)}0` })) });
    const ev2 = (await wrong.call("k8s.resources.list", ns)).evidenceId!;
    const r = await wrong.call("k8s.scale", scale, { cited: [ev2] });
    expect(r).toMatchObject({ status: "denied", reasonCode: "approval_denied" });
    expect(wrong.k8s.calls.filter((c) => c.tool === "k8s.scale")).toHaveLength(0);
  });

  it("farklı hedefe ait kanıt veya eski çağ atıf olarak geçmez (S-05 çekirdeği)", async () => {
    const h = await makeHarness({ profile, handlers, approval: new FakeApprovalGate() });
    const ev = (await h.call("k8s.resources.list", ns)).evidenceId!;
    // başka kaynağa mutasyon: atıf subject'i kapsamıyor
    expect(await h.call("k8s.scale", { ...scale, name: "baska" }, { cited: [ev] })).toMatchObject({ reasonCode: "citation_missing" });
    // profil çağı değişti: eski kanıt kullanılamaz
    h.session.bind(makeTestProfile({ id: "stage-k8s", classCeiling: "mutate" }), { replace: true });
    expect(h.session.epoch).toBe(1);
    const again = await h.call("k8s.scale", scale, { cited: [ev], profile: "stage-k8s" });
    expect(again).toMatchObject({ reasonCode: "citation_missing" });
  });

  it("kanıt tazelik penceresi dışında kalırsa geçmez", async () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const h = await makeHarness({ profile, handlers, approval: new FakeApprovalGate() });
    // gateway'in saatini ilerletmek için yeni bir gateway kur
    const { ToolGateway } = await import("../src/index.ts");
    const gw = new ToolGateway({ registry: h.registry, session: h.session, policy: h.policy, audit: h.audit, broker: h.broker, evidence: h.evidence, known: h.known, approval: new FakeApprovalGate(), now: () => now, citationMaxAgeMs: 60_000 });
    const list = await gw.invoke({ tool: "k8s.resources.list", profile: "test-k8s", args: ns, providerZone: "local" });
    now = new Date("2026-01-01T00:05:00Z");
    const r = await gw.invoke({ tool: "k8s.scale", profile: "test-k8s", args: scale, citedEvidence: [list.evidenceId!], providerZone: "local" });
    expect(r).toMatchObject({ reasonCode: "citation_missing" });
  });
});

describe("S-04: yanlış hedef / profil reddi", () => {
  it("profil belirtilmemiş, bilinmeyen veya bağlı olmayan", async () => {
    const h = await makeHarness();
    expect(await h.gateway.invoke({ tool: "k8s.resources.list", args: ns, providerZone: "local" })).toMatchObject({ reasonCode: "profile_unknown" });
    expect(await h.call("k8s.resources.list", ns, { profile: "yok" })).toMatchObject({ reasonCode: "profile_not_bound" });
    expect(h.k8s.calls).toHaveLength(0);
  });

  it("araç türü ile profil türü uyuşmuyor (db aracı + k8s profili ve tersi)", async () => {
    const h = await makeHarness();
    h.session.bind(h.dbProfile);
    expect(await h.call("k8s.resources.list", ns, { profile: "orders-db" })).toMatchObject({ reasonCode: "kind_mismatch" });
    expect(await h.call("db.query.read", { sql: "select 1" }, { profile: "test-k8s" })).toMatchObject({ reasonCode: "kind_mismatch" });
  });

  it("adapter'ın çözdüğü uç nokta profilin pininden farklıysa reddedilir; normalleştirme uygulanır", async () => {
    const h = await makeHarness();
    h.k8s.endpointOverride = "https://baska-kume.invalid:6443";
    const r = await h.call("k8s.resources.list", ns);
    expect(r).toMatchObject({ status: "denied", reasonCode: "target_pin_mismatch" });
    expect(h.broker.acquired).toHaveLength(0);
    h.k8s.endpointOverride = "HTTPS://K8S.TEST.INVALID:6443/";
    expect((await h.call("k8s.resources.list", ns)).status).toBe("ok");
  });

  it("kapsam dışı namespace ve kapsamı belirtilmeyen küme-genişi sorgu reddedilir", async () => {
    const h = await makeHarness();
    expect(await h.call("k8s.resources.list", { kind: "Pod", namespace: "kube-system" })).toMatchObject({ reasonCode: "scope_violation" });
    expect(await h.call("k8s.nodes.list", {})).toMatchObject({ reasonCode: "scope_violation" });
    const wide = await makeHarness({ profile: { allowedScopes: ["*"] } });
    expect((await wide.call("k8s.nodes.list", {})).status).toBe("ok");
  });
});

describe("S-12: argüman enjeksiyonu / şema", () => {
  it("fazladan alan (server, kubeconfig, __proto__), yanlış tür ve eksik alan reddedilir", async () => {
    const h = await makeHarness();
    const bad: unknown[] = [
      { ...ns, server: "https://evil.invalid" },
      { ...ns, kubeconfig: "/tmp/x" },
      JSON.parse('{"kind":"Pod","namespace":"payments","__proto__":{"x":1}}'),
      { kind: 5 },
      {},
      "metin",
      null,
    ];
    for (const args of bad) {
      expect(await h.call("k8s.resources.list", args)).toMatchObject({ status: "denied", reasonCode: "schema_invalid" });
    }
    expect(h.k8s.calls).toHaveLength(0);
    expect(h.broker.acquired).toHaveLength(0);
  });

  it("bilinmeyen araç", async () => {
    const h = await makeHarness();
    expect(await h.call("k8s.shell.exec", {})).toMatchObject({ reasonCode: "unknown_tool" });
  });
});

describe("S-08: denetim fail-closed", () => {
  it("intent yazılamazsa çağrı çalıştırılmaz ve lease alınmaz; günlük bozuk kalır", async () => {
    const h = await makeHarness();
    h.storage.failNext = true;
    const r = await h.call("k8s.resources.list", ns);
    expect(r).toMatchObject({ status: "denied", reasonCode: "audit_unavailable" });
    expect(h.k8s.calls).toHaveLength(0);
    expect(h.broker.acquired).toHaveLength(0);
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ reasonCode: "audit_unavailable" });
    expect(h.k8s.calls).toHaveLength(0);
  });

  it("result yazılamazsa sonuç modele verilmez (kanıt yerelde kalır); sonraki çağrılar reddedilir", async () => {
    const h = await makeHarness({
      handlers: { "k8s.resources.list": () => { h2.storage.failNext = true; return { data: [{ metadata: { name: "x" } }] }; } },
    });
    const h2 = h;
    const r = await h.call("k8s.resources.list", ns);
    expect(r).toMatchObject({ status: "denied", reasonCode: "audit_unavailable" });
    expect(r.view).toBeUndefined();
    expect(r.evidenceId).toBeDefined();
    expect(h.broker.active).toBe(0);
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ reasonCode: "audit_unavailable" });
  });

  it("reddedilen çağrılar da denetlenir (gerekçe koduyla)", async () => {
    const h = await makeHarness();
    await h.call("k8s.resources.list", { kind: "Pod", namespace: "kube-system" });
    const recs = await h.records();
    expect(recs).toHaveLength(1);
    expect(recs[0]).toMatchObject({ event: "result", decision: "deny", reasonCode: "scope_violation", exitStatus: "denied" });
  });
});

describe("S-13: politika kararı sağlayıcıdan bağımsız", () => {
  const sequence = async (zone: "local" | "tenant-cloud" | "third-party-cloud") => {
    const h = await makeHarness();
    const out: string[] = [];
    const add = (r: { status: string; reasonCode?: string }): void => void out.push(`${r.status}:${r.reasonCode ?? "-"}`);
    add(await h.call("k8s.resources.list", ns, { zone }));
    add(await h.call("k8s.scale", { namespace: "payments", name: "api", replicas: 1 }, { zone }));
    add(await h.call("k8s.resources.list", { kind: "Pod", namespace: "kube-system" }, { zone }));
    add(await h.call("evidence.get", { id: "ev-1" }, { zone }));
    const recs = (await h.records()).map((r) => `${String(r["event"])}|${String(r["tool"])}|${String(r["decision"])}|${String(r["reasonCode"])}|${String(r["class"])}`);
    return { out, recs };
  };

  it("farklı sağlayıcı bölgeleriyle aynı çağrı dizisi aynı kararları ve aynı denetim alanlarını üretir", async () => {
    const a = await sequence("local");
    const b = await sequence("third-party-cloud");
    const c = await sequence("tenant-cloud");
    expect(b).toEqual(a);
    expect(c).toEqual(a);
    expect(a.out).toEqual(["ok:-", "denied:ceiling_exceeded", "denied:scope_violation", "ok:-"]);
  });
});

describe("taint / bağlam etiketi (T2)", () => {
  it("log okuması bağlamı kirletir; ardından başka profile okuma ask → onay yok → reddedilir", async () => {
    const h = await makeHarness();
    h.session.bind(h.dbProfile);
    const logs = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    expect(logs.taint).toBe("untrusted");
    expect(h.session.context.tainted).toBe(true);
    const db = await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db" });
    expect(db).toMatchObject({ status: "denied", reasonCode: "approval_unavailable" });
    expect(h.dbAdapter.calls).toHaveLength(0);
  });

  it("aynı profile okuma taint altında da serbest; onay verilirse başka profil de çalışır ve özet taint'i gösterir", async () => {
    const gate = new FakeApprovalGate();
    const h = await makeHarness({ approval: gate });
    h.session.bind(h.dbProfile);
    await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    expect((await h.call("k8s.resources.list", ns)).status).toBe("ok");
    expect(gate.requests).toHaveLength(0);
    const db = await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db" });
    expect(db.status).toBe("ok");
    expect(gate.requests[0]?.summary).toMatchObject({ why: "taint_escalation", taintedContext: true });
  });

  it("taint olmadan başka profile okuma serbest", async () => {
    const h = await makeHarness();
    h.session.bind(h.dbProfile);
    await h.call("k8s.resources.list", ns);
    expect((await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db" })).status).toBe("ok");
  });

  it("untrusted kanıtı evidence.get ile yeniden okumak taint'i taşır", async () => {
    const h = await makeHarness();
    const logs = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    const again = await h.call("evidence.get", { id: logs.evidenceId! });
    expect(again.taint).toBe("untrusted");
    expect(h.formatForModel(again)).toContain("<untrusted nonce=");
  });
});

describe("bütçeler", () => {
  it("araç çağrısı sayısı aşılırsa reddedilir", async () => {
    const h = await makeHarness({ policy: { ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, maxToolCalls: 2 } } });
    expect((await h.call("k8s.resources.list", ns)).status).toBe("ok");
    expect((await h.call("k8s.resources.list", ns)).status).toBe("ok");
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ reasonCode: "call_budget_exceeded" });
  });

  it("oturum token sert eşiği aşılırsa reddedilir", async () => {
    const h = await makeHarness();
    h.session.addModelUsage({ inputTokens: 390_000, outputTokens: 20_000, cacheReadTokens: 0 });
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ reasonCode: "token_budget_exceeded" });
  });
});

describe("egress (T14)", () => {
  it("verinin gidebileceği en uzak bölge sağlayıcıdan yakınsa çağrı hiç çalıştırılmaz", async () => {
    const h = await makeHarness();
    h.session.bind(h.dbProfile); // egressClass: tenant-cloud, tool: pii
    const r = await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db", zone: "third-party-cloud" });
    expect(r).toMatchObject({ status: "denied", reasonCode: "no_eligible_provider" });
    expect(h.dbAdapter.calls).toHaveLength(0);
    expect((await h.call("db.query.read", { sql: "select 1" }, { profile: "orders-db", zone: "tenant-cloud" })).status).toBe("ok");
  });

  it("adapter hassasiyeti çalışma anında yükseltirse sonuç modele verilmez, kanıt yerelde kalır", async () => {
    const h = await makeHarness({ handlers: { "k8s.resources.list": () => ({ data: [{ metadata: { name: "x" } }], sensitivity: "secret-adjacent" }) } });
    const r = await h.call("k8s.resources.list", ns, { zone: "third-party-cloud" });
    expect(r).toMatchObject({ status: "denied", reasonCode: "no_eligible_provider" });
    expect(r.view).toBeUndefined();
    expect(h.evidence.get(r.evidenceId!)).toBeDefined();
    expect(h.session.context.zoneCap).toBe("local");
    // sonraki çağrılar yalnız yerel sağlayıcıya gidebilir
    expect(await h.call("k8s.resources.list", ns, { zone: "third-party-cloud" })).toMatchObject({ reasonCode: "no_eligible_provider" });
  });
});

describe("S-06: broker secret'ı hiçbir kanala sızmaz", () => {
  it("ham/base64/url biçimleri; hata mesajı ve ilk çağrının argümanları dahil", async () => {
    const canary = makeCanary("broker");
    const b64 = Buffer.from(`x${canary.value}y`).toString("base64");
    const h = await makeHarness({
      providerSecret: canary.value,
      handlers: {
        "k8s.resources.list": () => ({
          data: { env: [{ k: "A", v: canary.value }], blob: b64, url: `https://x.invalid/?t=${encodeURIComponent(canary.value)}` },
          summary: `özet ${canary.value}`,
        }),
        "k8s.pods.logs": () => { throw new Error(`bağlantı hatası: ${canary.value}`); },
      },
    });
    const formatted: string[] = [];
    // ilk çağrının ARGÜMANINDA secret var (kullanıcı yapıştırması): prime sayesinde maskelenmeli
    const r1 = await h.call("k8s.resources.list", { ...ns, kind: `Pod-${canary.value}` });
    formatted.push(h.formatForModel(r1));
    const r2 = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    formatted.push(h.formatForModel(r2));
    expect(r2.status).toBe("error");
    const sink = await collect(h, { formatted });
    sink.push("model-summary", [r1.summary, r2.summary].join("\n"));
    expect(sink.leaks([canary])).toEqual([]);
    expect(h.broker.primed).toEqual(["test-k8s"]);
  });
});

describe("lease yaşam döngüsü", () => {
  it("adapter hatasında ve iptalde lease bırakılır; hata redakte edilir", async () => {
    const h = await makeHarness({
      handlers: {
        "k8s.resources.list": () => { throw new Error("patladı"); },
        "k8s.pods.logs": () => new Promise(() => undefined),
      },
    });
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ status: "error", reasonCode: "adapter_error" });
    expect(h.broker.active).toBe(0);

    const ac = new AbortController();
    const p = h.gateway.invoke({ tool: "k8s.pods.logs", profile: "test-k8s", args: { namespace: "payments", pod: "x" }, providerZone: "local", signal: ac.signal });
    setTimeout(() => ac.abort(), 20);
    expect(await p).toMatchObject({ status: "error", reasonCode: "timeout" });
    expect(h.broker.active).toBe(0);
    expect(h.broker.released).toBe(2);
  });

  it("lease alınamazsa çağrı çalışmaz", async () => {
    const h = await makeHarness();
    h.broker.failNext = true;
    expect(await h.call("k8s.resources.list", ns)).toMatchObject({ status: "error", reasonCode: "adapter_error" });
    expect(h.k8s.calls).toHaveLength(0);
  });
});
