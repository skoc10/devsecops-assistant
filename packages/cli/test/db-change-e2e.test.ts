import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemorySecretStore } from "@ops/broker";
import { initSqlClassifier } from "@ops/classifiers";
import type { OrchestratorEvent } from "@ops/core";
import { CaptureSink, ScriptedProvider, makeCanary, say, toolUse } from "@ops/testkit";
import { SHOP_ROLES, seedShop, startTestPostgres } from "@ops/testkit/postgres";
import type { TestPostgres } from "@ops/testkit/postgres";
import { TtyApprovalGate, createRuntime, readAuditRecords, renderEvent, resolvePaths, runCli } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { idsIn } from "./fixture.ts";

await initSqlClassifier();
const pg: TestPostgres | null = await startTestPostgres().catch(() => null);
const canaries = { readerPw: makeCanary("reader-pw"), otherPw: makeCanary("other-pw"), vaultToken: makeCanary("vault-token") };

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

let home = "";
beforeAll(async () => {
  home = await mkdtemp(join(tmpdir(), "ops-dbchg-"));
  if (pg) await seedShop(pg, { readerPassword: canaries.readerPw.value, otherPassword: canaries.otherPw.value, vaultToken: canaries.vaultToken.value });
});
afterAll(async () => {
  await pg?.stop();
  await rm(home, { recursive: true, force: true });
});

const io = () => ({ input: new PassThrough(), output: new PassThrough(), error: new PassThrough() });
const text = (s: PassThrough): string => (s.read() as Buffer | null)?.toString("utf8") ?? "";
const admin = (sql: string): Promise<string> => pg!.admin(sql, "shop");

describe.skipIf(!pg)("Faz 2d: PostgreSQL değişikliği uçtan uca (scripted model, gerçek PostgreSQL, TTY onayı)", () => {
  const paths = resolvePaths(join(tmpdir(), `ops-dbchg-home-${process.pid}`));
  const store = new MemorySecretStore();

  async function cli(argv: string[], env: Record<string, string> = {}) {
    const i = io();
    const code = await runCli({ argv, env, io: i, paths, store, sandbox: null });
    return { code, out: text(i.output), err: text(i.error) };
  }
  async function pwFile(pw: string): Promise<string> {
    const f = join(home, `pw-${Math.random().toString(36).slice(2)}`);
    await writeFile(f, `${pw}\n`, { mode: 0o600 });
    return f;
  }

  it("profile add db --ceiling mutate = writer; doktor bağlanabilir der; fazla yetkili rol bağlanamaz", async () => {
    await writeFile(join(home, "ca.pem"), pg!.pki.caPem);
    const base = (id: string, role: string, ceiling: string): string[] => [
      "profile", "add", "db", "--id", id, "--env", "sandbox", "--host", pg!.host, "--port", String(pg!.port), "--database", "shop", "--user", role,
      "--scope", "public", "--ca-file", join(home, "ca.pem"), "--datasource", "shop", "--ceiling", ceiling,
    ];
    const add = await cli(base("shop-w", SHOP_ROLES.writer, "mutate"), { OPS_DB_PASSWORD_FILE: await pwFile(canaries.otherPw.value) });
    expect(add.code, add.err).toBe(0);
    expect(add.out).toMatch(/Profil eklendi: shop-w \(sandbox, writer,/);
    expect(add.out).toMatch(/AYRI/);
    expect(add.out + add.err).not.toContain(canaries.otherPw.value);
    const list = await cli(["profile", "list"]);
    expect(list.out).toMatch(/shop-w\tdb\tsandbox\ttavan mutate/);
    const doc = await cli(["profile", "doctor", "shop-w"]);
    expect(doc.code, doc.out).toBe(0);
    expect(doc.out).toMatch(/BAĞLANABİLİR/);
    expect(doc.out).toContain("ops_writer@shop");
    // tablo sahibi rol mutate tavanıyla bağlanamaz
    await cli(base("shop-own", SHOP_ROLES.ddl, "mutate"), { OPS_DB_PASSWORD_FILE: await pwFile(canaries.otherPw.value) });
    const bad = await cli(["profile", "doctor", "shop-own"]);
    expect(bad.code).toBe(1);
    expect(bad.out).toMatch(/BAĞLANAMAZ/);
    expect(bad.out).toMatch(/ceiling_exceeded_by_grants/);
  });

  it("scripted sohbet: skill → şema → propose → apply (TTY 'evet') → doğrula; ikinci apply RET; satır üst sınırı aşımı ROLLBACK; canary yok; denetim zinciri", async () => {
    await admin("TRUNCATE public.orders; INSERT INTO public.orders SELECT g, 1 + (g % 2), CASE WHEN g % 3 = 0 THEN 'failed' ELSE 'paid' END, g * 10.5, now() - (g || ' minutes')::interval FROM generate_series(1, 30) g");
    const tty = fakeTty(["evet", "", "evet"]); // 1: refund onayı, 2: ikinci apply reddedilir (Enter), 3: üst sınır aşan apply onayı
    const gate = new TtyApprovalGate({ openTty: tty.open, sleep: async () => undefined });
    const rt = await createRuntime({ paths, store, sandbox: null, approval: gate });
    const ev: OrchestratorEvent[] = [];
    let provider!: ScriptedProvider;
    try {
      expect((await rt.bindProfile("shop-w")).bindable).toBe(true);
      const failedBefore = Number(await admin("SELECT count(*) FROM public.orders WHERE status = 'failed'"));
      const refund = "UPDATE public.orders SET status = 'refunded' WHERE status = 'failed'";
      provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "database-change" } }]),
          toolUse([{ name: "db.schema.describe", args: { schema: "public" } }]),
          toolUse([{ name: "db.change.propose", args: { sql: refund, maxRows: 50 } }]),
          (req) => toolUse([{ name: "db.change.apply", args: { sql: refund, maxRows: 50, cited: [idsIn(req.messages).at(-1)] } }]),
          (req) => toolUse([{ name: "db.change.apply", args: { sql: "UPDATE public.orders SET status = 'x' WHERE id = 1", maxRows: 5, cited: [idsIn(req.messages).at(-2)] } }]),
          (req) => toolUse([{ name: "db.change.apply", args: { sql: "UPDATE public.orders SET total = total + 1 WHERE id <= 20", maxRows: 5, cited: [idsIn(req.messages).at(-3)] } }]),
          toolUse([{ name: "db.query.read", args: { sql: "SELECT status, count(*) AS n FROM public.orders GROUP BY status ORDER BY status" } }]),
          (req) => say(`failed siparişler refunded yapıldı [${idsIn(req.messages).at(-1)}]; ikinci değişiklik reddedildi; üst sınırı aşan değişiklik geri alındı.`),
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider, { maxIterations: 20 });
      for await (const e of orch.send("failed siparişleri refunded yap")) ev.push(e);
      const results = ev.filter((e): e is Extract<OrchestratorEvent, { type: "tool_result" }> => e.type === "tool_result");
      expect(results.map((r) => `${r.name}:${r.status}${r.reasonCode ? `/${r.reasonCode}` : ""}`)).toEqual([
        "skill.load:ok",
        "db.schema.describe:ok",
        "db.change.propose:ok",
        "db.change.apply:ok",
        "db.change.apply:denied/approval_denied",
        "db.change.apply:error/adapter_error",
        "db.query.read:ok",
      ]);
      // değişiklik uygulandı; reddedilen ve geri alınan uygulanmadı
      expect(await admin("SELECT count(*) FROM public.orders WHERE status = 'refunded'")).toBe(String(failedBefore));
      expect(await admin("SELECT status FROM public.orders WHERE id = 1")).toBe("paid");
      expect(await admin("SELECT count(*) FROM public.orders WHERE total = id * 10.5")).toBe("30"); // total + 1 geri alındı
      // onay ekranı: ifade, etki, sürüm, geri alma
      const shown = tty.shown();
      expect(shown).toContain("ONAY GEREKİYOR");
      expect(shown).toContain("db.change.apply");
      expect(shown).toContain(refund);
      expect(shown).toMatch(/tahmini etkilenen satır/);
      expect(shown).toMatch(/Hedef sürüm: pgchg1:/);
      expect(shown).toMatch(/ROLLBACK/);
      const final = ev.find((e) => e.type === "final");
      if (final?.type === "final") expect(final.citations.invalid).toEqual([]);
      // canary yok: denetim, kanıt, sağlayıcı, arayüz, onay ekranı
      const sink = new CaptureSink();
      sink.push("audit", await readFile(rt.paths.auditLog, "utf8"));
      for (const e of rt.evidence.all()) sink.push("evidence", e.text);
      sink.push("sağlayıcı", provider.serialized.join("\n"));
      sink.push("ui", ev.map((e) => renderEvent(e) ?? "").join("\n"));
      sink.push("onay", shown);
      expect(sink.leaks([canaries.readerPw, canaries.otherPw, canaries.vaultToken])).toEqual([]);
      const recs = await readAuditRecords(rt.paths.auditLog);
      expect(recs.filter((r) => r.event === "approval").map((r) => r.decision)).toEqual(["allow", "deny", "allow"]);
      expect(recs.some((r) => r.event === "intent" && r.tool === "db.change.apply" && typeof r.message === "string" && r.message.startsWith("atıf: ev-"))).toBe(true);
    } finally {
      await rt.close();
    }
    const v = await cli(["audit", "verify"]);
    expect(v.code, v.out + v.err).toBe(0);
  });
});
