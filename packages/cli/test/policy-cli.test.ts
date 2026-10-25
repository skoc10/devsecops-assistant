import { readFile, stat } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parsePolicy } from "@ops/policy";
import { readAuditRecords, runCli } from "../src/index.ts";
import type { TtyIo } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

function fakeTty(answers: string[]): { open: () => Promise<TtyIo>; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  let i = 0;
  output.on("data", (b: Buffer) => {
    chunks.push(b.toString());
    if (/: $/.test(chunks.join("").slice(-14))) {
      const a = answers[i++];
      if (a !== undefined) setTimeout(() => input.write(`${a}\n`), 0);
    }
  });
  return { open: async () => ({ input, output }), shown: () => chunks.join("") };
}

describe("Faz 2f: politika düzenleme akışı (ops policy)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.profiles.addKubeconfig({ id: "payments-sbx", environment: "sandbox", kubeconfigText: fx.kubeconfigText, allowedScopes: ["payments"], displayName: "Payments sandbox", classCeiling: "mutate", replace: true });
    await fx.rt.profiles.addKubeconfig({ id: "payments-prod", environment: "prod", kubeconfigText: fx.kubeconfigText, allowedScopes: ["payments"], displayName: "Payments prod", classCeiling: "mutate" });
    await fx.rt.profiles.addKubeconfig({ id: "payments-ro", environment: "stage", kubeconfigText: fx.kubeconfigText, allowedScopes: ["payments"], displayName: "Payments ro", classCeiling: "read" });
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  const cli = async (argv: string[], answers: string[] = ["evet"]) => {
    const tty = fakeTty(answers);
    const io = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv, env: {}, io, paths: fx.rt.paths, store: fx.store, sandbox: null, openTty: tty.open });
    return { code, out: (io.output.read() as Buffer | null)?.toString() ?? "", err: (io.error.read() as Buffer | null)?.toString() ?? "", tty: tty.shown() };
  };
  const policyText = (): Promise<string> => readFile(fx.rt.paths.policyFile, "utf8");

  it("list: kullanıcı dosyası yokken yerleşik varsayılanı gösterir", async () => {
    const r = await cli(["policy", "list"]);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toMatch(/yerleşik varsayılan/);
    expect(r.out).toMatch(/kural yok/);
  });

  it("allow: DIFF gösterilir, TTY'de 'evet' ile yazılır (0600), denetime policy_change düşer, politika sürümü değişir; yorumlar korunur; ikinci düzenlemede .bak oluşur", async () => {
    const r = await cli(["policy", "allow", "--tool", "k8s.scale", "--profile", "payments-sbx", "--scope", "payments", "--ttl", "4h"]);
    expect(r.code, r.err + r.out).toBe(0);
    expect(r.out).toContain("+++ b/policy.yaml");
    expect(r.out).toMatch(/\+\s+- id: izin-k8s-scale-payments-sbx-\d{8}-[0-9a-f]{4}/);
    expect(r.out).toMatch(/Politika sürümü [0-9a-f]{12} → [0-9a-f]{12}\. Değişiklik YALNIZ yeni oturumda/);
    expect(r.tty).toContain("Bu değişiklik uygulansın mı?");
    expect((await stat(fx.rt.paths.policyFile)).mode & 0o777).toBe(0o600);
    const text = await policyText();
    expect(text).toContain("# ops-assistant erişim politikası"); // yerleşik dosyanın yorumları korundu
    const doc = parsePolicy(text);
    expect(doc.rules).toHaveLength(1);
    const rule = doc.rules[0]!;
    expect(rule).toMatchObject({ effect: "allow", when: { tool: "k8s.scale", profile: "payments-sbx", class: ["mutate"], scope: ["payments"] } });
    const ttl = Date.parse(rule.expires as string) - Date.now();
    expect(ttl).toBeGreaterThan(3.9 * 3600_000);
    expect(ttl).toBeLessThan(4.1 * 3600_000);
    const recs = await readAuditRecords(fx.rt.paths.auditLog);
    const ch = recs.filter((x) => x.event === "policy_change");
    expect(ch).toHaveLength(1);
    expect(ch[0]!.message).toMatch(/ekle izin-k8s-scale-payments-sbx.*sürüm [0-9a-f]{12}→[0-9a-f]{12}/);
    // list artık kuralı gösterir
    expect((await cli(["policy", "list"])).out).toContain(rule.id);
    // ikinci düzenleme: .bak = birincinin sonucu
    const before = await policyText();
    const r2 = await cli(["policy", "add", "--effect", "ask", "--id", "prod-okuma-sor", "--environment", "prod", "--class", "read"]);
    expect(r2.code, r2.err + r2.out).toBe(0);
    expect(await readFile(`${fx.rt.paths.policyFile}.bak`, "utf8")).toBe(before);
    expect(parsePolicy(await policyText()).rules.map((x) => x.id)).toEqual([rule.id, "prod-okuma-sor"]);
    // rm
    const r3 = await cli(["policy", "rm", rule.id]);
    expect(r3.code, r3.err).toBe(0);
    expect(parsePolicy(await policyText()).rules.map((x) => x.id)).toEqual(["prod-okuma-sor"]);
    expect((await readAuditRecords(fx.rt.paths.auditLog)).filter((x) => x.event === "policy_change")).toHaveLength(3);
  });

  it("onay verilmezse (Enter / yanlış metin) veya kontrol terminali yoksa dosya DEĞİŞMEZ ve denetime yazılmaz", async () => {
    for (const answers of [[""], ["hayır"], ["EVET"]]) {
      const r = await cli(["policy", "allow", "--tool", "k8s.scale", "--profile", "payments-sbx"], answers);
      expect(r.code).toBe(1);
      expect(r.out).toMatch(/Uygulanmadı/);
    }
    await expect(stat(fx.rt.paths.policyFile)).rejects.toThrow();
    const none = { input: new PassThrough(), output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv: ["policy", "allow", "--tool", "k8s.scale", "--profile", "payments-sbx"], env: {}, io: none, paths: fx.rt.paths, store: fx.store, sandbox: null, openTty: async () => null });
    expect(code).toBe(1);
    expect((none.error.read() as Buffer).toString()).toMatch(/tty_required/);
    await expect(stat(fx.rt.paths.policyFile)).rejects.toThrow();
    expect((await readAuditRecords(fx.rt.paths.auditLog)).filter((x) => x.event === "policy_change")).toHaveLength(0);
  });

  it("geniş/yanlış 'hep izin' REDDEDİLİR: joker, prod, kayıtsız profil, okuma tavanlı profil, süresiz/aşırı süre, geçersiz araç adı", async () => {
    const cases: [string[], RegExp][] = [
      [["--tool", "k8s.*", "--profile", "payments-sbx"], /TAM ve geçerli/],
      [["--tool", "k8s.scale", "--profile", "*"], /TAM ve geçerli/],
      [["--tool", "k8s.scale", "--profile", "payments-prod"], /prod profili için 'hep izin'/],
      [["--tool", "k8s.scale", "--profile", "yok-boyle"], /profil kayıtlı değil/],
      [["--tool", "k8s.scale", "--profile", "payments-ro"], /tavanı 'read'/],
      [["--tool", "k8s.scale", "--profile", "payments-sbx", "--ttl", "90d"], /süre 1 dakika/],
      [["--tool", "k8s.scale", "--profile", "payments-sbx", "--ttl", "0m"], /süre 1 dakika/],
      [["--tool", "k8s.scale", "--profile", "payments-sbx", "--ttl", "sonsuz"], /süre geçersiz/],
      [["--tool", "Bad Tool", "--profile", "payments-sbx"], /TAM ve geçerli/],
      [["--tool", "k8s.scale"], /--tool ve --profile gerekli/],
    ];
    for (const [args, why] of cases) {
      const r = await cli(["policy", "allow", ...args]);
      expect(r.code, args.join(" ")).not.toBe(0);
      expect(r.err, args.join(" ")).toMatch(why);
    }
    await expect(stat(fx.rt.paths.policyFile)).rejects.toThrow();
  });

  it("add/rm: koşulsuz kural, 'allow' etkisi (ayrı komut), yinelenen kimlik ve olmayan kural reddedilir", async () => {
    expect((await cli(["policy", "add", "--effect", "deny", "--id", "hepsi"])).err).toMatch(/en az bir koşul/);
    expect((await cli(["policy", "add", "--effect", "allow", "--id", "x", "--tool", "k8s.scale"])).err).toMatch(/--effect ask\|deny/);
    expect((await cli(["policy", "rm", "yok"])).err).toMatch(/kural bulunamadı/);
    expect((await cli(["policy", "add", "--effect", "deny", "--id", "prod-sil", "--tool", "k8s.resources.delete", "--environment", "prod"])).code).toBe(0);
    const dup = await cli(["policy", "add", "--effect", "ask", "--id", "prod-sil", "--tool", "k8s.scale"]);
    expect(dup.code).toBe(1);
    expect(dup.err).toMatch(/zaten var/);
  });
});
