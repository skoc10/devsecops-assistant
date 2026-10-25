import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { e01Script, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

describe("ops replay (denetimden inceleme + politika what-if)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup().catch(() => undefined);
  });

  const run = async (argv: string[], input = "", provider?: ScriptedProvider) => {
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

  const chat = async (): Promise<void> => {
    const r = await run(["chat", "--embedded"], "/use payments-sbx\npayments ns'inde api neden çöküyor?\n/quit\n", new ScriptedProvider(e01Script(), { trustZone: "third-party-cloud" }));
    expect(r.code, r.err).toBe(0);
  };

  it("son oturumu zaman çizelgesi + özet + tutarlılık denetimiyle gösterir; araç/model ÇAĞRILMAZ; zincir doğrulanır", async () => {
    await chat();
    const apiBefore = fx.api.requests.length;
    const r = await run(["replay"]);
    expect(r.code, r.err + r.out).toBe(0);
    expect(r.out).toContain("Denetim zinciri: DOĞRU");
    expect(r.out).toContain("→ k8s.workload.health [read]");
    expect(r.out).toContain("→ k8s.pods.logs [read]");
    expect(r.out).toContain("model scripted/");
    expect(r.out).toContain("sorun yok");
    expect(r.out).toContain("Araçlar yeniden ÇAĞRILMADI");
    expect(fx.api.requests.length).toBe(apiBefore); // sahte kümeye TEK istek gitmedi
    // replay'in kendi oturumu hedef değil: çıktıdaki oturum, sohbet oturumu
    expect(r.out).not.toContain("replay");
    // canary'ler çizelgede yok
    for (const c of fx.all) expect(r.out.includes(c.value), c.label).toBe(false);
  });

  it("--policy current: aynı politika → 0 değişiklik; sıkı aday dosya → 'sıkılaşır' ve çıkış 0", async () => {
    await chat();
    const same = await run(["replay", "--policy", "current"]);
    expect(same.code, same.err + same.out).toBe(0);
    expect(same.out).toMatch(/\d+ karar yeniden değerlendirildi; 0 değişti/);

    const strict = join(fx.home, "strict.yaml");
    await writeFile(
      strict,
      `version: 1\nbudgets: {maxToolCalls: 60, maxResultTokens: 1500, softSessionTokens: 150000, hardSessionTokens: 400000}\nrules:\n  - {id: no-logs, when: {tool: "k8s.pods.logs"}, effect: deny}\n`,
    );
    const r = await run(["replay", "--policy", strict]);
    expect(r.code, r.err + r.out).toBe(0);
    expect(r.out).toContain("▲ sıkılaşır");
    expect(r.out).toContain("k8s.pods.logs");
    expect(r.out).toMatch(/1 değişti/);
  });

  it("--json: makine okunur rapor (zincir + zaman çizelgesi + istatistik)", async () => {
    await chat();
    const r = await run(["replay", "--json"]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out) as { chain: { ok: boolean }; stats: { calls: number }; timeline: unknown[]; anomalies: unknown[] };
    expect(j.chain.ok).toBe(true);
    expect(j.stats.calls).toBe(4);
    expect(j.timeline.length).toBeGreaterThan(8);
    expect(j.anomalies).toEqual([]);
  });

  it("denetim dosyası bozulmuşsa BOZUK der, çıkış 1 (zaman çizelgesine güvenme uyarısı)", async () => {
    await chat();
    const path = fx.rt.paths.auditLog;
    const text = await readFile(path, "utf8");
    const lines = text.split("\n");
    lines[3] = (lines[3] ?? "").replace("intent", "intenT").replace("session", "sessioN");
    await writeFile(path, lines.join("\n"));
    const r = await run(["replay"]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("BOZUK");
    expect(r.out).toContain("GÜVENMEYİN");
  });

  it("incelenecek oturum yoksa / kimlik bilinmiyorsa açık hata (çıkış 2)", async () => {
    const empty = await run(["replay"]);
    expect(empty.code).toBe(2);
    expect(empty.err).toContain("önceki oturum yok");
    await chat();
    const unknown = await run(["replay", "--session", "yok-boyle-oturum"]);
    expect(unknown.code).toBe(2);
    expect(unknown.err).toContain("oturum bulunamadı");
  });
});
