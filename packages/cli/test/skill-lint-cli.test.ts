import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MemorySecretStore } from "@ops/broker";
import { resolvePaths, runCli } from "../src/index.ts";

describe("ops skill lint", () => {
  let home: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "ops-skill-cli-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });
  const run = async (argv: string[]) => {
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    const code = await runCli({ argv, env: {}, io: { input: new PassThrough(), output, error }, paths: resolvePaths(join(home, "ops")), store: new MemorySecretStore(), sandbox: null });
    return { code, out: o.join(""), err: e.join("") };
  };
  const mk = async (root: string, name: string, body: string) => {
    await mkdir(join(root, name), { recursive: true });
    await writeFile(join(root, name, "SKILL.md"), `---\nname: ${name}\ndescription: Bu skill bir şeyi yapar; ne zaman kullanılacağını da anlatır.\n---\n${body}\n`);
  };

  it("yerleşik skill'ler: hatasız, çıkış 0", async () => {
    const r = await run(["skill", "lint", "--builtin"]);
    expect(r.code, r.err + r.out).toBe(0);
    expect(r.out).toMatch(/\d+ skill, 0 hatalı/);
  });

  it("hatalı skill çıkış 1; uyarı yalnız --strict ile çıkışı bozar; --json makine okunur", async () => {
    const root = join(home, "benim-skiller");
    await mk(root, "iyi", "Kısa.");
    await mk(root, "uyarili", "Detay: https://ornek.example.invalid/dok");
    await mk(root, "trojan", "Normal\u202E gizli");
    const bad = await run(["skill", "lint", root]);
    expect(bad.code).toBe(1);
    expect(bad.out).toContain("hidden_unicode");
    expect(bad.out).toContain("external_url");

    const ok = join(home, "sadece-uyari");
    await mk(ok, "uyarili", "Detay: https://ornek.example.invalid/dok");
    expect((await run(["skill", "lint", ok])).code).toBe(0);
    expect((await run(["skill", "lint", ok, "--strict"])).code).toBe(1);

    const j = await run(["skill", "lint", ok, "--json"]);
    expect(JSON.parse(j.out)[0]).toMatchObject({ dirName: "uyarili", ok: true });
  });

  it("varsayılan: OPS_HOME/skills; yoksa 'bulunamadı' ve çıkış 0; bilinmeyen alt komut kullanım hatası", async () => {
    const r = await run(["skill", "lint"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("skill bulunamadı");
    expect((await run(["skill", "foo"])).code).toBe(2);
  });
});
