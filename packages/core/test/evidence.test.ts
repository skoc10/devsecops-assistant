import { describe, expect, it } from "vitest";
import { Session, EvidenceStore, ToolRegistry, formatForModel, normalizeEndpoint, createLocalAdapter } from "../src/index.ts";
import { FakeAdapter, makeTestProfile } from "@ops/testkit";
import { listTool, makeHarness } from "./harness.ts";

describe("B-03: referansla taşıma + evidence.get dilimleme", () => {
  it("token tavanını aşan görünüm kırpılır; tam (maxItems sınırlı) kanıt korunur ve dilimlenebilir", async () => {
    const big = Array.from({ length: 300 }, (_, i) => ({
      metadata: { name: `workload-${i}`, namespace: "payments", uid: `uid-${i}-${"x".repeat(12)}` },
      status: { phase: i % 50 === 0 ? "Failed" : "Running", podIP: `10.1.${i % 250}.${i % 200}` },
    }));
    const wide = ["metadata.name", "metadata.namespace", "metadata.uid", "status.phase", "status.podIP"];
    const h = await makeHarness({ profile: { allowedScopes: ["*"] }, handlers: { "k8s.resources.list": () => ({ data: big }) } });
    const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments", select: wide });
    expect(r.status).toBe("ok");
    expect(r.tokens.estimate).toBeLessThanOrEqual(1500);
    expect(r.truncated).toBe(true);
    expect(JSON.stringify(r.view)).not.toContain("workload-99");
    // kanıt = aracın maxItems (100) sınırına kadar tam, toplam sayı bildirilir
    const ev = h.evidence.get(r.evidenceId!)!;
    expect(ev.text).toContain("workload-99");
    expect(ev.text).toContain('"_total":300');
    expect(ev.tokens).toBeGreaterThan(r.tokens.estimate);

    const slice = await h.call("evidence.get", { id: r.evidenceId!, offset: 90, limit: 5 });
    expect(slice.status).toBe("ok");
    const text = JSON.stringify(slice.view);
    expect(text).toContain("workload-90");
    expect(text).toContain("workload-94");
    expect(text).not.toContain("workload-95");
  });

  it("sığmayan sonuç yalnız referansla döner; select ile alan alınır", async () => {
    const hostile = Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`anahtar${i}`, `deger-${i}`]));
    const h = await makeHarness({ handlers: { "k8s.pods.logs": () => ({ data: hostile }) } });
    const r = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    expect(r.byReference).toBe(true);
    expect(r.view).toBeUndefined();
    const text = formatForModel(r);
    expect(text).toContain("byReference");
    expect(text).toContain("evidence.get");
    const got = await h.call("evidence.get", { id: r.evidenceId!, select: ["anahtar5", "anahtar6"] });
    expect(JSON.stringify(got.view)).toContain("deger-5");
    expect(JSON.stringify(got.view)).not.toContain("deger-7");
  });

  it("evidence.search kanıtları bulur; var olmayan kanıt hata verir", async () => {
    const h = await makeHarness();
    await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
    const s = await h.call("evidence.search", { query: "api-2" });
    expect(JSON.stringify(s.view)).toContain("ev-1");
    expect(await h.call("evidence.get", { id: "ev-99" })).toMatchObject({ status: "error", reasonCode: "adapter_error" });
    expect(await h.call("evidence.get", { id: "gecersiz" })).toMatchObject({ reasonCode: "schema_invalid" });
  });
});

describe("formatForModel", () => {
  const base = {
    callId: "c", tool: "k8s.resources.list", status: "ok" as const, summary: "özet", byReference: false, truncated: false,
    redactions: [], provenance: { source: "x", observedAt: "t" }, sensitivity: "none" as const, taint: "trusted" as const, subjects: [], tokens: { estimate: 5 },
  };
  it("güvenilir sonuç düz JSON; untrusted sonuç nonce'lu zarfta; reddedilen sebep kodu taşır", () => {
    expect(formatForModel({ ...base, view: { a: 1 }, evidenceId: "ev-1" })).toBe('{"id":"ev-1","tool":"k8s.resources.list","status":"ok","summary":"özet","view":{"a":1}}');
    expect(formatForModel({ ...base, taint: "untrusted", view: 1 })).toMatch(/^<untrusted nonce="[0-9a-f]+"/);
    expect(formatForModel({ ...base, status: "denied", reasonCode: "ceiling_exceeded", summary: "tavan" })).toBe("REDDEDİLDİ [ceiling_exceeded]: tavan");
  });
});

describe("ToolRegistry", () => {
  it("manifest ile tanım uyuşmazlığını ve yinelenen aracı reddeder", () => {
    const reg = new ToolRegistry();
    const a = new FakeAdapter("a", "kubernetes", "k8s", [{ def: listTool, handler: () => ({ data: 1 }) }]);
    expect(() => reg.register(a, [])).toThrow(/tanımı olmayan/);
    reg.register(a, [listTool]);
    const dup = new FakeAdapter("b", "kubernetes", "k8s", [{ def: listTool, handler: () => ({ data: 1 }) }]);
    expect(() => reg.register(dup, [listTool])).toThrow(/zaten kayıtlı/);
  });

  it("specsFor yalnız etkin araç setlerini ve deterministik sırayla döndürür (B-05)", async () => {
    const h = await makeHarness();
    const names = (sets: string[]): string[] => h.registry.specsFor(sets).map((s) => s.name);
    expect(names(["core"])).toEqual(["evidence.get", "evidence.search", "timeline.build"]);
    const k8s = names(["core", "k8s-core"]);
    // araç setleri etkinleşme sırasıyla, her set içinde ada göre; yeni set yalnız SONA eklenir
    expect(k8s.slice(0, 3)).toEqual(["evidence.get", "evidence.search", "timeline.build"]);
    const rest = k8s.slice(3);
    expect(rest).toEqual([...rest].sort((x, y) => x.localeCompare(y)));
    expect(k8s).not.toContain("db.query.read");
    expect(names(["core", "k8s-core"])).toEqual(k8s);
    expect(names(["core", "k8s-core", "db"]).slice(0, k8s.length)).toEqual(k8s);
    expect(names(["k8s-core", "core"])).not.toEqual(k8s);
  });
});

describe("Session", () => {
  it("tür başına tek profil; replace çağı artırır; unbind çağı artırır", () => {
    const s = new Session("x");
    const a = makeTestProfile({ id: "a" });
    const b = makeTestProfile({ id: "b" });
    s.bind(a);
    expect(() => s.bind(b)).toThrow(/zaten bağlı/);
    s.bind(a); // aynı profil tekrar bağlanabilir
    expect(s.epoch).toBe(0);
    s.bind(b, { replace: true });
    expect(s.epoch).toBe(1);
    expect(s.getBound("a")).toBeUndefined();
    s.unbind("k8s");
    expect(s.epoch).toBe(2);
  });

  it("noteResult bağlam etiketini günceller (taint kalıcı, zoneCap yalnız sıkılaşır)", () => {
    const s = new Session("x");
    const prod = makeTestProfile({ id: "p", egressClass: "tenant-cloud" });
    s.noteResult({ profile: prod, sensitivity: "internal", tainted: false });
    expect(s.context).toMatchObject({ tainted: false, zoneCap: "tenant-cloud", maxSensitivity: "internal", profilesTouched: ["p"] });
    s.noteResult({ sensitivity: "secret-adjacent", tainted: true });
    expect(s.context).toMatchObject({ tainted: true, zoneCap: "local", maxSensitivity: "secret-adjacent" });
    s.noteResult({ sensitivity: "none", tainted: false });
    expect(s.context.tainted).toBe(true);
    expect(s.context.zoneCap).toBe("local");
    s.resetContext();
    expect(s.context).toMatchObject({ tainted: false, zoneCap: "third-party-cloud" });
  });
});

describe("EvidenceStore / normalizeEndpoint", () => {
  it("normalizeEndpoint: büyük/küçük harf, varsayılan port, sondaki /; host:port URL sanılmaz", () => {
    expect(normalizeEndpoint("HTTPS://Host.Example:443/")).toBe("https://host.example");
    expect(normalizeEndpoint("https://h.example:6443/api/")).toBe("https://h.example:6443/api");
    expect(normalizeEndpoint("DB.Example.invalid:5432")).toBe("db.example.invalid:5432");
    expect(normalizeEndpoint("https://a.invalid")).not.toBe(normalizeEndpoint("https://b.invalid"));
  });

  it("slice: dizi, items ve tablo biçimleri; ara", () => {
    const st = new EvidenceStore();
    const mk = (text: string) => st.put({ callId: "c", tool: "t", profileId: "p", epoch: 0, observedAt: new Date().toISOString(), subjects: [], sensitivity: "none", taint: "trusted", summary: "s", text });
    const arr = mk(JSON.stringify([1, 2, 3, 4, 5]));
    expect(st.slice(arr.id, { offset: 1, limit: 2 })).toMatchObject({ data: [2, 3], total: 5, shown: 2, offset: 1 });
    const tbl = mk(JSON.stringify({ columns: ["a"], rows: [[1], [2], [3]] }));
    expect(st.slice(tbl.id, { limit: 2 })?.data).toMatchObject({ rows: [[1], [2]] });
    expect(st.slice("ev-yok", {})).toBeNull();
    expect(st.search("columns")).toHaveLength(1);
  });

  it("createLocalAdapter manifesti geçerli ve yerel araçlar kimliksiz", () => {
    const { adapter } = createLocalAdapter(new EvidenceStore());
    expect(adapter.manifest.tools.every((t) => t.scope === "local" && t.profileKind === null)).toBe(true);
  });
});
