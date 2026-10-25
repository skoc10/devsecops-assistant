import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider, say } from "@ops/testkit";
import type { ScriptStep } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

const usage = { inputTokens: 0, outputTokens: 5, cacheReadTokens: 0 };
const call = (id: string, name: string, args: unknown): ScriptStep => ({ message: { content: "", toolCalls: [{ id, name, args }] }, usage, stopReason: "tool_use" });

const RUNBOOK = `---
title: Payments API CrashLoop
description: payments api CrashLoopBackOff olduğunda
params: { namespace: payments, name: api }
---
1. Workload sağlığına bak. \`k8s.workload.health {"kind":"Deployment","name":"{{name}}","namespace":"{{namespace}}"}\`
2. Uyarı olaylarını oku. \`k8s.events.list {"namespace":"{{namespace}}","since":"2h","type":"Warning"}\`
3. Önceki kapsayıcı logunu oku. \`k8s.pods.logs {"namespace":"{{namespace}}","pod":"api-7d9c-a1","previous":true,"since":"1h","tailLines":50}\`
4. Bellek sınırını gözden geçir ve öneri yaz.
5. Gerekirse ölçekle. \`k8s.scale {"kind":"Deployment","namespace":"{{namespace}}","name":"{{name}}","replicas":3}\`
`;

describe("runbook → plan → runbook.run (CLI uçtan uca, sahte küme)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
    await mkdir(fx.rt.paths.runbooksDir, { recursive: true });
    await writeFile(join(fx.rt.paths.runbooksDir, "payments-crashloop.md"), RUNBOOK);
  });
  afterEach(async () => {
    await fx.cleanup().catch(() => undefined);
  });

  const run = async (argv: string[], input: string, provider?: ScriptedProvider) => {
    const stdin = new PassThrough();
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    const done = runCli({ argv, env: {}, io: { input: stdin, output, error }, paths: fx.rt.paths, store: fx.store, sandbox: null, ...(provider ? { provider } : {}) });
    stdin.write(input);
    stdin.end();
    const code = await done;
    return { code, out: o.join(""), err: e.join("") };
  };

  const script = (): ScriptStep[] => [
    call("a", "runbook.list", {}),
    call("b", "runbook.plan", { name: "payments-crashloop" }), // araç seti henüz kapalı
    call("c", "skill.load", { name: "kubernetes" }),
    call("c2", "skill.load", { name: "kubernetes-change" }), // scale adımının araç seti açılsın: yine de runbook.run onu ÇALIŞTIRMAZ
    call("d", "runbook.plan", { name: "payments-crashloop" }),
    call("e", "runbook.run", { name: "payments-crashloop" }),
    (req) => {
      const last = (req.messages.filter((m) => m.role === "tool").at(-1) as { content: string }).content;
      // satırlar tablo biçiminde gelir; ilk eşleşme üst çağrının kendi kimliği
      const ids = [...new Set([...last.matchAll(/"(ev-\d+)"/g)].map((m) => m[1]))].slice(1);
      return say(`Runbook koştu; kanıtlar ${ids.map((i) => `[${i}]`).join(" ")}. Ölçekleme adımı çalıştırılmadı; öneri: bellek sınırını artırın.`);
    },
  ];

  it("liste → plan (kullanıcıya gösterilir) → run: okuma adımları PEP'ten geçerek koşar, okuma dışı atlanır; denetim iç çağrıları üst çağrıya bağlar", async () => {
    const provider = new ScriptedProvider(script(), { trustZone: "third-party-cloud" });
    const r = await run(["chat", "--embedded"], "/use payments-sbx\npayments crashloop runbook'unu koştur\n/quit\n", provider);
    expect(r.code, r.err).toBe(0);

    // plan kullanıcıya gösterildi (iki kez: araç seti kapalıyken ve açıkken)
    expect(r.out).toContain("Runbook planı: Payments API CrashLoop (payments-crashloop) — namespace=payments, name=api");
    expect(r.out).toContain("araç seti kapalı");
    expect(r.out).toMatch(/k8s\.workload\.health \[read\][^\n]*\(otomatik\)/);
    expect(r.out).toMatch(/k8s\.scale \[mutate\][^\n]*\(ayrıca onay\/çağrı\)/);
    expect(r.out).toContain("4. elle —");

    // run: 3 okuma adımı koştu; scale çalışmadı (araç seti açık olsa bile okuma dışı)
    const runMsg = provider.requests.at(-1)!.messages.find((m) => m.role === "tool" && m.name === "runbook.run") as { content: string };
    const runView = (JSON.parse(runMsg.content) as { view: { executed: number; steps: { columns: string[]; rows: unknown[][] } } }).view;
    expect(runView.executed).toBe(3);
    const col = (name: string): number => runView.steps.columns.indexOf(name);
    expect(runView.steps.rows.map((row) => [row[col("n")], row[col("status")], row[col("reason")]])).toEqual([[1, "ok", null], [2, "ok", null], [3, "ok", null], [5, "skipped", "not_read"]]);
    expect(r.out).toContain("Ölçekleme adımı çalıştırılmadı");
    expect(r.out).not.toContain("⚠ Doğrulanamayan");
    expect(r.out).not.toContain("kanıt kimliği içermiyor");
    // sahte kümeye yalnız okuma istekleri gitti (scale yok)
    expect(fx.api.requests.some((q) => q.method !== "GET" && !q.path.includes("selfsubject"))).toBe(false);

    const audit = (await readFile(fx.rt.paths.auditLog, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
    const outer = audit.find((x) => x["event"] === "intent" && x["tool"] === "runbook.run")!;
    expect(outer).toBeDefined();
    const nested = audit.filter((x) => x["event"] === "intent" && typeof x["message"] === "string" && (x["message"] as string).includes(`iç çağrı (üst: ${String(outer["callId"])})`));
    expect(nested.map((x) => x["tool"])).toEqual(["k8s.workload.health", "k8s.events.list", "k8s.pods.logs"]);
    expect(audit.some((x) => x["event"] === "intent" && x["tool"] === "k8s.scale")).toBe(false);
    // session_start özeti runbook sayısını içerir
    expect(audit.find((x) => x["event"] === "session_start" && String(x["message"]).includes("runbooks=1"))).toBeDefined();

    // canary'ler hiçbir kanalda yok
    const bytes = provider.serialized.join("\n") + r.out + JSON.stringify(audit);
    for (const c of fx.all) expect(bytes.includes(c.value), c.label).toBe(false);
  });

  it("log adımı untrusted: runbook.run bağlamı kirletir ama log gövdesi satır içi DÖNMEZ (yalnız kanıt kimliği + özet)", async () => {
    const provider = new ScriptedProvider(script(), { trustZone: "third-party-cloud" });
    await run(["chat", "--embedded"], "/use payments-sbx\nkoştur\n/quit\n", provider);
    const all = provider.serialized.join("\n");
    expect(all).not.toContain("IGNORE ALL PREVIOUS INSTRUCTIONS");
    expect(all).not.toContain("db connection refused host=10.0.0.7");
  });

  it("runbook yokken: araçlar kayıtlı değil, sistem istemi değişmez; runbook list/lint CLI geçersizleri bildirir", async () => {
    await writeFile(join(fx.rt.paths.runbooksDir, "bozuk.md"), "adım yok");
    const l = await run(["runbook", "list"], "");
    expect(l.code).toBe(1);
    expect(l.out).toContain("payments-crashloop\t5 adım (4 araç)\tPayments API CrashLoop");
    expect(l.out).toContain("bozuk.md");
    // runbook dizini boşken araçlar yok
    await writeFile(join(fx.rt.paths.runbooksDir, "payments-crashloop.md"), "adım yok");
    const p = new ScriptedProvider([call("x", "runbook.list", {}), (req) => say(`araç sonucu: ${(req.messages.at(-1) as { content: string }).content.slice(0, 80)}`)], { trustZone: "local" });
    const r = await run(["chat", "--embedded"], "merhaba\n/quit\n", p);
    expect(r.out).toContain("REDDEDİLDİ [unknown_tool]");
    expect(p.requests[0]!.system).not.toContain("Runbook'lar var");
  });
});
