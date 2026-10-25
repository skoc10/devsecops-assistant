import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool } from "@ops/contracts";
import { Session, ToolRegistry } from "@ops/core";
import { FakeAdapter } from "@ops/testkit";
import { RUNBOOK_LIMITS, RunbookRegistry, buildPlan, parseRunbook, substituteArgs } from "../src/index.ts";

const RB = `---
title: Payments API CrashLoop
description: payments api CrashLoopBackOff olduğunda
params: { namespace: payments, name: api }
---
# Adımlar
1. Workload sağlığına bak. \`k8s.workload.health {"kind":"Deployment","name":"{{name}}","namespace":"{{namespace}}"}\`
2. Uyarı olaylarını oku.
   \`k8s.events.list {"namespace":"{{namespace}}","since":"2h","type":"Warning"}\`
3) Bellek sınırını gözden geçir ve öneri yaz.
4. Gerekirse ölçekle. \`k8s.scale {"namespace":"{{namespace}}","name":"{{name}}","replicas":3}\`
`;

describe("parseRunbook", () => {
  it("ön bilgi, numaralı adımlar (1. ve 1)), çok satırlı adım, araç çağrısı ve elle adımlar", () => {
    const rb = parseRunbook("payments-crashloop", RB);
    expect(rb).toMatchObject({ name: "payments-crashloop", title: "Payments API CrashLoop", params: { namespace: "payments", name: "api" } });
    expect(rb.steps.map((s) => [s.n, s.tool ?? null])).toEqual([[1, "k8s.workload.health"], [2, "k8s.events.list"], [3, null], [4, "k8s.scale"]]);
    expect(rb.steps[0]!.args).toEqual({ kind: "Deployment", name: "{{name}}", namespace: "{{namespace}}" });
    expect(rb.steps[0]!.text).toBe("Workload sağlığına bak.");
    expect(rb.steps[2]!.text).toBe("Bellek sınırını gözden geçir ve öneri yaz.");
    expect(rb.tokens).toBeGreaterThan(0);
  });

  it("ön bilgisiz runbook da geçerli: başlık = ad", () => {
    const rb = parseRunbook("basit", "1. Bir şey yap.\n2. Başka şey.\n");
    expect(rb.title).toBe("basit");
    expect(rb.steps).toHaveLength(2);
  });

  it("katı reddedilenler: ad, boyut, görünmez Unicode, adım yok, bozuk JSON, dizi argüman, bilinmeyen ön bilgi, parametre", () => {
    const bad = (name: string, text: string, re: RegExp): void => expect(() => parseRunbook(name, text), text.slice(0, 30)).toThrow(re);
    bad("Büyük_Ad", "1. x", /dosya adı/);
    bad("a", "1. x\n".repeat(1) + "y".repeat(RUNBOOK_LIMITS.chars), /karakteri aşıyor/);
    bad("a", "1. normal‮ gizli", /Trojan/);
    bad("a", "başlık\nadım yok", /numaralı adım/);
    bad("a", '1. x `k8s.workload.health {bozuk}`', /geçerli JSON/);
    bad("a", '1. x `k8s.workload.health ["a"]`', /JSON nesnesi/);
    bad("a", "---\nfoo: 1\n---\n1. x", /bilinmeyen anahtar/);
    bad("a", "---\nparams: { 'Büyük': 1 }\n---\n1. x", /parametre adı/);
    bad("a", "---\nparams: { a: [1] }\n---\n1. x", /skaler/);
    bad("a", "---\ntitle: [\n---\n1. x", /YAML/);
    bad("a", Array.from({ length: RUNBOOK_LIMITS.steps + 1 }, (_, i) => `${(i % 99) + 1}. adım`).join("\n"), /en çok 30 adım/);
    bad("a", `1. ${"u".repeat(RUNBOOK_LIMITS.stepText + 1)}`, /açıklama/);
  });
});

describe("substituteArgs: yer tutucu YALNIZ string değerlerde", () => {
  it("iç içe yapılarda yerine koyar; anahtarlar ve türler değişmez; eksikleri bildirir", () => {
    const r = substituteArgs({ a: "{{x}}-{{ y }}", n: 3, nested: { list: ["{{x}}", 1], "{{x}}": "anahtar değişmez" } }, { x: "A", y: "B" });
    expect(r.args).toEqual({ a: "A-B", n: 3, nested: { list: ["A", 1], "{{x}}": "anahtar değişmez" } });
    expect(r.missing).toEqual([]);
    expect(substituteArgs({ a: "{{yok}}", b: "{{yok}}{{yok2}}" }, {}).missing.sort()).toEqual(["yok", "yok2"]);
  });
  it("parametre değeri yapı ENJEKTE edemez (JSON kaçışı gerekmez, çünkü yalnız string yaprağa girer)", () => {
    const r = substituteArgs({ ns: "{{p}}" }, { p: '","replicas":0,"x":"' });
    expect(r.args).toEqual({ ns: '","replicas":0,"x":"' });
    expect(Object.keys(r.args)).toEqual(["ns"]);
  });
});

describe("RunbookRegistry", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-rb-"));
    await mkdir(join(dir, "runbooks"));
    await writeFile(join(dir, "runbooks", "iyi.md"), RB);
    await writeFile(join(dir, "runbooks", "kotu.md"), "adım yok");
    await writeFile(join(dir, "runbooks", "Buyuk.md"), "1. x");
    await writeFile(join(dir, "runbooks", "not.txt"), "yok sayılır");
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  it("geçerli olanlar yüklenir, geçersizlerin sebebi issues'ta; olmayan dizin boş", async () => {
    const reg = await RunbookRegistry.load(join(dir, "runbooks"));
    expect(reg.all().map((r) => r.name)).toEqual(["iyi"]);
    expect(reg.issues.map((i) => i.file).sort()).toEqual(["Buyuk.md", "kotu.md"]);
    expect(reg.count).toBe(1);
    expect((await RunbookRegistry.load(join(dir, "yok"))).count).toBe(0);
  });
});

describe("buildPlan: adım durumları", () => {
  const lim = { timeoutMs: 1000, maxBytes: 1000, maxItems: 10, maxOutputTokens: 100 };
  const meta = { scope: "target", profileKind: "k8s", sensitivity: "none", idempotent: true, limits: lim, untrustedOutput: false, typicalOutputTokens: 10 } as const;
  const health = defineTool({ ...meta, name: "k8s.workload.health", description: "x", class: "read", toolset: "k8s" }, z.strictObject({ kind: z.string(), name: z.string(), namespace: z.string() }));
  const events = defineTool({ ...meta, name: "k8s.events.list", description: "x", class: "read", toolset: "k8s" }, z.strictObject({ namespace: z.string(), since: z.string(), type: z.enum(["Normal", "Warning"]).optional() }));
  const scale = defineTool({ ...meta, name: "k8s.scale", description: "x", class: "mutate", toolset: "k8s-change", idempotent: false }, z.strictObject({ namespace: z.string(), name: z.string(), replicas: z.number().int() }));
  const mk = () => {
    const reg = new ToolRegistry();
    reg.register(new FakeAdapter("kubernetes", "kubernetes", "k8s", [health, events, scale].map((d) => ({ def: d, handler: () => ({ data: {} }) }))), [health, events, scale]);
    return { reg, session: new Session("s") };
  };
  const rb = parseRunbook("payments-crashloop", RB);

  it("araç seti kapalıyken 'toolset_inactive'; açılınca profil yoksa 'profile_unbound'", () => {
    const { reg, session } = mk();
    expect(buildPlan(rb, {}, session, reg).steps.map((s) => s.status)).toEqual(["toolset_inactive", "toolset_inactive", "manual", "toolset_inactive"]);
    session.activeToolsets.add("k8s");
    session.activeToolsets.add("k8s-change");
    expect(buildPlan(rb, {}, session, reg).steps.map((s) => s.status)).toEqual(["profile_unbound", "profile_unbound", "manual", "profile_unbound"]);
  });

  it("parametreler: varsayılanlar ve geçersiz kılma; eksik parametre; geçersiz argüman; bilinmeyen araç; yasak (runbook.*) adım", () => {
    const { reg, session } = mk();
    session.activeToolsets.add("k8s");
    const p = buildPlan(rb, { namespace: "orders" }, session, reg);
    expect(p.params).toEqual({ namespace: "orders", name: "api" });
    expect(p.steps[0]!.args).toEqual({ kind: "Deployment", name: "api", namespace: "orders" });
    expect(p.steps[0]).toMatchObject({ class: "read" });
    const miss = parseRunbook("m", '1. x `k8s.workload.health {"kind":"Deployment","name":"{{a}}","namespace":"{{b}}"}`');
    expect(buildPlan(miss, { a: "x" }, session, reg).steps[0]).toMatchObject({ status: "missing_param", problems: ["parametre eksik: b (runbook.plan params ile verin)"] });
    const inv = parseRunbook("i", '1. x `k8s.events.list {"namespace":"a","since":"2h","type":"Bozuk"}`');
    expect(buildPlan(inv, {}, session, reg).steps[0]!.status).toBe("invalid_args");
    expect(buildPlan(parseRunbook("u", "1. x `k8s.yok.araci {}`"), {}, session, reg).steps[0]!.status).toBe("unknown_tool");
    expect(buildPlan(parseRunbook("r", "1. x `runbook.run {}`"), {}, session, reg).steps[0]!.status).toBe("not_allowed");
  });
});
