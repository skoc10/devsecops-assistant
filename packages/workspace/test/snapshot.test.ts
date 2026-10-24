import { existsSync } from "node:fs";
import { lstat, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { detectSandbox } from "@ops/sandbox";
import { WorkspaceRegistry, createSnapshot } from "../src/index.ts";
import { SECRET_TFVARS, makeRepo } from "./repo.ts";
import type { TestRepo } from "./repo.ts";

const sandbox = await detectSandbox();
const P = { writePaths: ["**"], denyPaths: [] as string[] };

describe.skipIf(!sandbox)("anlık kopya (gerçek git + gerçek bubblewrap)", () => {
  let repo: TestRepo;
  let out = "";
  beforeAll(async () => {
    repo = await makeRepo();
    out = await mkdtemp(join(tmpdir(), "ops-snap-"));
  });
  afterAll(async () => {
    await repo.cleanup();
    await rm(out, { recursive: true, force: true });
  });

  it("HEAD içeriği kopyalanır; gizli/yasak/büyük/sembolik/alt modül atlanır; .git yok; kipler 0600", async () => {
    const snap = await createSnapshot({ repoPath: repo.dir, destDir: join(out, "a"), sandbox: sandbox!, policy: P });
    const files = Object.keys(snap.manifest.files).sort();
    // CI tanımı OKUNABİLİR (yazma yasak), bu yüzden anlık kopyada vardır
    expect(files).toEqual([".gitattributes", ".github/workflows/ci.yml", "README.md", "main.tf", "modules/vpc/main.tf", "run.sh", "variables.tf"].sort());
    expect(await readFile(join(snap.workDir, "main.tf"), "utf8")).toContain('resource "terraform_data" "x"');
    expect(await readFile(join(snap.baseDir, "main.tf"), "utf8")).toBe(await readFile(join(snap.workDir, "main.tf"), "utf8"));
    expect(existsSync(join(snap.workDir, ".git"))).toBe(false);
    for (const hidden of ["prod.tfvars", ".env", "terraform.tfstate", "deploy/key.pem", "big.bin", "link"]) expect(existsSync(join(snap.workDir, hidden)), hidden).toBe(false);
    // çalıştırılabilir bit atıldı
    expect((await stat(join(snap.workDir, "run.sh"))).mode & 0o777).toBe(0o600);
    expect((await stat(snap.workDir)).mode & 0o077).toBe(0);
    const reasons = Object.fromEntries(snap.manifest.skipped.map((s) => [s.path, s.reason]));
    expect(reasons["prod.tfvars"]).toMatch(/gizli dosya deseni/);
    expect(reasons[".env"]).toMatch(/gizli dosya deseni/);
    expect(reasons["terraform.tfstate"]).toMatch(/gizli dosya deseni/);
    expect(reasons["deploy/key.pem"]).toMatch(/gizli dosya deseni/);
    expect(reasons["big.bin"]).toMatch(/çok büyük/);
    expect(reasons["link"]).toMatch(/sembolik bağ/);
    expect(Object.values(reasons).join()).toMatch(/yol yalnız harf/); // unicode ad
    // gizli içerik hiçbir yerde değil
    const all = JSON.stringify(snap.manifest);
    expect(all).not.toContain(SECRET_TFVARS.trim());
    expect(snap.manifest.head).toMatch(/^[0-9a-f]{40}$/);
  });

  it("kötü niyetli git yapılandırması (smudge süzgeci, fsmonitor, kancalar) HİÇBİR şey çalıştırmaz", async () => {
    await createSnapshot({ repoPath: repo.dir, destDir: join(out, "b"), sandbox: sandbox!, policy: P });
    expect(existsSync(repo.markers.smudge)).toBe(false);
    expect(existsSync(repo.markers.fsmonitor)).toBe(false);
    expect(existsSync(repo.markers.hook)).toBe(false);
  });

  it("depo çalışma kopyası değişmez (salt okunur bağlama): index/ref/dosya zaman damgaları aynı", async () => {
    const before = (await lstat(join(repo.dir, ".git", "index"))).mtimeMs;
    await createSnapshot({ repoPath: repo.dir, destDir: join(out, "c"), sandbox: sandbox!, policy: P });
    expect((await lstat(join(repo.dir, ".git", "index"))).mtimeMs).toBe(before);
    expect(existsSync(join(repo.dir, ".git", "index.lock"))).toBe(false);
  });

  it("denyPaths ve dosya sayısı sınırı; sandbox yoksa çalışmaz", async () => {
    const snap = await createSnapshot({ repoPath: repo.dir, destDir: join(out, "d"), sandbox: sandbox!, policy: { writePaths: ["**"], denyPaths: ["modules/**"] } });
    expect(Object.keys(snap.manifest.files)).not.toContain("modules/vpc/main.tf");
    await expect(createSnapshot({ repoPath: repo.dir, destDir: join(out, "e"), sandbox: sandbox!, policy: P, limits: { maxFiles: 2, maxFileBytes: 1_000_000, maxTotalBytes: 10_000_000 } })).rejects.toThrow(/dosya var/);
    await expect(createSnapshot({ repoPath: repo.dir, destDir: join(out, "f"), sandbox: { kind: "none", run: async () => { throw new Error("x"); }, spawn: async () => { throw new Error("x"); } }, policy: P })).rejects.toThrow(/sandbox gerekir/);
    await expect(createSnapshot({ repoPath: join(out, "yok"), destDir: join(out, "g"), sandbox: sandbox!, policy: P })).rejects.toThrow();
  });
});

describe("WorkspaceRegistry", () => {
  it("git deposunun kökü olmalı; ev dizini/kök reddedilir; kopya/replace; kalıcı 0600", async () => {
    const repo = await makeRepo();
    const home = await mkdtemp(join(tmpdir(), "ops-wsreg-"));
    try {
      const file = join(home, "workspaces.json");
      const reg = await WorkspaceRegistry.open(file);
      const ws = await reg.add({ id: "infra", path: repo.dir, engine: "opentofu", writePaths: ["**/*.tf"] });
      expect(ws).toMatchObject({ id: "infra", engine: "opentofu", writePaths: ["**/*.tf"], denyPaths: [] });
      expect(((await stat(file)).mode & 0o777)).toBe(0o600);
      await expect(reg.add({ id: "infra", path: repo.dir, engine: "terraform" })).rejects.toThrow(/zaten kayıtlı/);
      expect((await reg.add({ id: "infra", path: repo.dir, engine: "terraform" }, { replace: true })).engine).toBe("terraform");
      await expect(reg.add({ id: "x", path: join(repo.dir, "modules"), engine: "terraform" })).rejects.toThrow(/git deposunun kökü/);
      await expect(reg.add({ id: "x", path: "/", engine: "terraform" })).rejects.toThrow(/ev dizini|kök/);
      await expect(reg.add({ id: "x", path: repo.dir, engine: "terraform" }, { home: repo.dir })).rejects.toThrow(/ev dizini|kök/);
      await expect(reg.add({ id: "Bad ID", path: repo.dir, engine: "terraform" })).rejects.toThrow();
      await expect(reg.add({ id: "x", path: "relative/path", engine: "terraform" })).rejects.toThrow(/mutlak/);
      const again = await WorkspaceRegistry.open(file);
      expect(again.list().map((w) => w.id)).toEqual(["infra"]);
      expect(await again.remove("infra")).toBe(true);
      expect(await again.remove("infra")).toBe(false);
    } finally {
      await repo.cleanup();
      await rm(home, { recursive: true, force: true });
    }
  });
});
