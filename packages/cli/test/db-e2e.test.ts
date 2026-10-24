import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import { createRuntime, readAuditRecords, renderEvent, resolvePaths, runCli } from "../src/index.ts";
import { idsIn } from "./fixture.ts";

await initSqlClassifier();
const pg: TestPostgres | null = await startTestPostgres().catch(() => null);
const canaries = { readerPw: makeCanary("reader-pw"), otherPw: makeCanary("other-pw"), vaultToken: makeCanary("vault-token") };

let home = "";
beforeAll(async () => {
  home = await mkdtemp(join(tmpdir(), "ops-dbe2e-"));
  if (pg) await seedShop(pg, { readerPassword: canaries.readerPw.value, otherPassword: canaries.otherPw.value, vaultToken: canaries.vaultToken.value });
});
afterAll(async () => {
  await pg?.stop();
  await rm(home, { recursive: true, force: true });
});

const io = () => ({ input: new PassThrough(), output: new PassThrough(), error: new PassThrough() });
const text = (s: PassThrough): string => (s.read() as Buffer | null)?.toString("utf8") ?? "";

describe.skipIf(!pg)("Faz 1: PostgreSQL reader — CLI uçtan uca (gerçek PostgreSQL)", () => {
  const paths = resolvePaths(join(tmpdir(), `ops-dbe2e-home-${process.pid}`));
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
  const addArgs = (id: string, role: string, extra: string[] = []): string[] => [
    "profile", "add", "db", "--id", id, "--env", "sandbox", "--host", pg!.host, "--port", String(pg!.port), "--database", "shop", "--user", role,
    "--scope", "public,sales", "--ca-file", join(home, "ca.pem"), "--datasource", "shop", ...extra,
  ];

  it("profile add db: parola dosyadan, çıktıda parola/bağlantı dizesi YOK; list/doctor çalışır", async () => {
    await writeFile(join(home, "ca.pem"), pg!.pki.caPem);
    const add = await cli(addArgs("shop", SHOP_ROLES.reader), { OPS_DB_PASSWORD_FILE: await pwFile(canaries.readerPw.value) });
    expect(add.code, add.err).toBe(0);
    expect(add.out).toContain("Profil eklendi: shop");
    expect(add.out + add.err).not.toContain(canaries.readerPw.value);
    const list = await cli(["profile", "list"]);
    expect(list.out).toMatch(/shop\tdb\tsandbox\ttavan read\tkapsam public\|sales/);
    const doc = await cli(["profile", "doctor", "shop"]);
    expect(doc.code, doc.out).toBe(0);
    expect(doc.out).toMatch(/BAĞLANABİLİR/);
    expect(doc.out).toContain("ops_reader@shop");
    expect(doc.out + doc.err).not.toContain(canaries.readerPw.value);
  });

  it("yazma yetkili rolün profili eklenir ama doktor BAĞLANAMAZ der (çıkış kodu 1)", async () => {
    const add = await cli(addArgs("shop-w", SHOP_ROLES.writerLike), { OPS_DB_PASSWORD_FILE: await pwFile(canaries.otherPw.value) });
    expect(add.code, add.err).toBe(0);
    const doc = await cli(["profile", "doctor", "shop-w"]);
    expect(doc.code).toBe(1);
    expect(doc.out).toMatch(/BAĞLANAMAZ/);
    expect(doc.out).toMatch(/write_privilege/);
  });

  it("geçersiz girdiler: bağlantı dizesi host olarak, parola dosyası izni, kapsam", async () => {
    const pf = await pwFile("x1234567");
    const bad1 = await cli(addArgs("bad1", "u", []).map((a) => (a === pg!.host ? "postgres://u:p@h/db" : a)), { OPS_DB_PASSWORD_FILE: pf });
    expect(bad1.code).toBe(1);
    expect(bad1.err).toMatch(/host geçersiz/);
    const open = join(home, "open-pw");
    await writeFile(open, "x1234567\n", { mode: 0o644 });
    await chmod(open, 0o644);
    const bad2 = await cli(addArgs("bad2", "u"), { OPS_DB_PASSWORD_FILE: open });
    expect(bad2.code).toBe(1);
    expect(bad2.err).toMatch(/chmod 600|izin/);
    const bad3 = await cli(addArgs("bad3", "u", ["--tls", "off"]), { OPS_DB_PASSWORD_FILE: pf });
    expect(bad3.code).toBe(2);
    expect(bad3.err).toMatch(/--tls/);
    const bad4 = await cli(["profile", "add", "db", "--id", "bad4", "--env", "sandbox", "--host", "h", "--database", "d", "--user", "u"], { OPS_DB_PASSWORD_FILE: pf });
    expect(bad4.code).toBe(2);
    expect(bad4.err).toMatch(/--scope/);
  });

  it("scripted sohbet: skill.load database → schema → query → atıflı cevap; maskeli sütun; kanıt/denetim/sağlayıcı baytlarında canary YOK", async () => {
    await writeFile(paths.maskingFile, ["version: 1", "profiles:", "  '*':", "    maskedColumns:", "      customers: [email, phone]", ""].join("\n"));
    const rt = await createRuntime({ paths, store, sandbox: null });
    try {
      const report = await rt.bindProfile("shop");
      expect(report).toMatchObject({ bindable: true, connected: true });
      const provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "database" } }]),
          toolUse([{ name: "db.schema.describe", args: { schema: "public" } }]),
          toolUse([
            { name: "db.query.read", args: { sql: "SELECT status, count(*) AS n FROM public.orders GROUP BY status ORDER BY status" } },
            { name: "db.query.read", args: { sql: "SELECT id, email FROM public.customers ORDER BY id" } },
            { name: "db.query.read", args: { sql: "SELECT * FROM public.customers" } },
            { name: "db.query.read", args: { sql: "SELECT id, note FROM public.customers ORDER BY id" } },
            { name: "db.query.read", args: { sql: "DELETE FROM public.orders" } },
          ]),
          (req) => {
            const ids = idsIn(req.messages);
            return say(`Siparişler: failed ve paid sayıları [${ids.at(-4) ?? ids.at(-1)}]. Müşteri e-postaları maskeli geldi. DELETE ve SELECT * reddedildi.`);
          },
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider);
      const ev: OrchestratorEvent[] = [];
      for await (const e of orch.send("Kaç sipariş failed? Müşteri e-postalarına da bak.")) ev.push(e);
      const results = ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[];
      expect(results.map((r) => `${r.name}:${r.status}`)).toEqual([
        "skill.load:ok",
        "db.schema.describe:ok",
        "db.query.read:ok",
        "db.query.read:ok",
        "db.query.read:denied",
        "db.query.read:ok",
        "db.query.read:denied",
      ]);
      const final = ev.find((e) => e.type === "final") as Extract<OrchestratorEvent, { type: "final" }>;
      expect(final.citations.invalid).toEqual([]);

      // grup sayımı doğru
      const counts = rt.evidence.all().find((e) => e.text.includes('"columns":["status","n"]'));
      expect(counts?.text).toContain('["failed","10"]');
      // e-posta/telefon/parola ham haliyle hiçbir kanalda yok
      const ui = ev.map((e) => renderEvent(e) ?? "").join("\n");
      const sink = new CaptureSink();
      sink.push("audit", await readFile(paths.auditLog, "utf8"));
      for (const e of rt.evidence.all()) sink.push("evidence", e.text);
      sink.push("sağlayıcı-baytları", provider.serialized.join("\n"));
      sink.push("ui", ui);
      expect(sink.leaks([canaries.readerPw, canaries.otherPw, canaries.vaultToken])).toEqual([]);
      for (const raw of ["ayse@example.invalid", "mehmet@example.invalid", "555 111 22 33", "555 222 33 44"]) {
        expect(sink.text("sağlayıcı-baytları"), raw).not.toContain(raw);
        expect(sink.text("evidence"), raw).not.toContain(raw);
        expect(sink.text("audit"), raw).not.toContain(raw);
      }
      // SELECT * ve DELETE nedeniyle kimliğe/bağlantıya gidilmedi ve denetimde ret kaydı var
      const recs = await readAuditRecords(paths.auditLog);
      expect(recs.filter((r) => r.event === "result" && r.decision === "deny" && r.reasonCode === "target_unresolved").length).toBe(2);
      // bağlam: DB hücresi untrusted → taint
      expect(rt.session.context.tainted).toBe(true);
    } finally {
      await rt.close();
    }
  });

  it("prod profili: çıktı bölgesi 'local'; uzak sağlayıcıyla db.query.read çağrı ÖNCESİ reddedilir (egress)", async () => {
    const add = await cli(addArgs("shop-prod", SHOP_ROLES.reader, []).map((a) => (a === "sandbox" ? "prod" : a)), { OPS_DB_PASSWORD_FILE: await pwFile(canaries.readerPw.value) });
    expect(add.code, add.err).toBe(0);
    expect(add.out).toContain("çıktı bölgesi local");
    const rt = await createRuntime({ paths, store, sandbox: null });
    try {
      expect((await rt.bindProfile("shop-prod")).bindable).toBe(true);
      const script = () => [
        toolUse([{ name: "skill.load", args: { name: "database" } }]),
        toolUse([{ name: "db.query.read", args: { sql: "SELECT id FROM public.orders LIMIT 1" } }]),
        say("tamam"),
      ];
      const queryResult = async (zone: "third-party-cloud" | "local") => {
        const ev: OrchestratorEvent[] = [];
        for await (const e of rt.createOrchestrator(new ScriptedProvider(script(), { trustZone: zone })).send("q")) ev.push(e);
        return (ev.filter((e) => e.type === "tool_result") as Extract<OrchestratorEvent, { type: "tool_result" }>[]).find((r) => r.name === "db.query.read")!;
      };
      const remote = await queryResult("third-party-cloud");
      expect(remote, JSON.stringify(remote)).toMatchObject({ status: "denied" });
      expect(remote.reasonCode).toMatch(/egress|eligible|sensitivity/);
      // aynı çağrı yerel sağlayıcıyla serbest
      expect(await queryResult("local")).toMatchObject({ status: "ok" });
      // uzak sağlayıcıya HİÇBİR satır gitmedi
      const recs = await readAuditRecords(paths.auditLog);
      expect(recs.some((r) => r.event === "result" && r.tool === "db.query.read" && r.decision === "deny" && /egress|eligible|sensitivity/.test(String(r.reasonCode)))).toBe(true);
    } finally {
      await rt.close();
    }
  });
});
