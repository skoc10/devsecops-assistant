import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { detectSandbox } from "@ops/sandbox";
import { makeCanary } from "@ops/testkit";
import { WorktreeFs, createSnapshot } from "../src/index.ts";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";

const run = promisify(execFile);
const sandbox = await detectSandbox();
const P = { writePaths: ["**"], denyPaths: [] as string[] };

describe.skipIf(!sandbox)("WorktreeFs (S-20: worktree izolasyonu)", () => {
  let repo: TestRepo;
  let out = "";
  let n = 0;
  beforeAll(async () => {
    repo = await makeRepo();
    out = await mkdtemp(join(tmpdir(), "ops-fs-"));
  });
  afterAll(async () => {
    await repo.cleanup();
    await rm(out, { recursive: true, force: true });
  });
  const fresh = async (policy = P) => {
    const snap = await createSnapshot({ repoPath: repo.dir, destDir: join(out, `s${++n}`), sandbox: sandbox!, policy });
    return new WorktreeFs(snap, policy);
  };

  it("okuma: satır aralığı, toplam satır, kesilme işareti; gizli/bilinmeyen yollar reddedilir", async () => {
    const fs = await fresh();
    const all = await fs.read("variables.tf");
    expect(all).toMatchObject({ path: "variables.tf", totalLines: 4, startLine: 1, shownLines: 4, truncated: false });
    expect(all.content).toContain('variable "name"');
    const part = await fs.read("variables.tf", { startLine: 2, maxLines: 1 });
    expect(part).toMatchObject({ startLine: 2, shownLines: 1, truncated: true, content: "  type    = string" });
    await expect(fs.read("prod.tfvars")).rejects.toThrow(/yol reddedildi: gizli dosya deseni/);
    await expect(fs.read("yok.tf")).rejects.toThrow(/dosya yok/);
    await expect(fs.read("modules")).rejects.toThrow(/bir dizin/);
    await expect(fs.read("../etc/passwd")).rejects.toThrow(/yol reddedildi/);
    await expect(fs.read("/etc/passwd")).rejects.toThrow(/göreli/);
    // snapshot'a girmeyen dosya (anlık kopyada hiç yok) okunamaz
    await expect(fs.read("link")).rejects.toThrow(/dosya yok/);
  });

  it("yazma: oluştur/güncelle, 0600, çalıştırılabilir bit yok, üst dizin otomatik", async () => {
    const fs = await fresh();
    const a = await fs.write("modules/net/main.tf", 'resource "terraform_data" "n" {\n  input = "x"\n}\n');
    expect(a).toMatchObject({ path: "modules/net/main.tf", created: true, lines: 3 });
    const b = await fs.write("modules/net/main.tf", '# yeni\n');
    expect(b.created).toBe(false);
    const st = await stat(join(fs.root, "modules/net/main.tf"));
    expect(st.mode & 0o777).toBe(0o600);
    expect((await stat(join(fs.root, "modules/net"))).mode & 0o077).toBe(0);
    expect(await readFile(join(fs.root, "modules/net/main.tf"), "utf8")).toBe("# yeni\n");
    // geçici dosya kalmadı
    const l = await fs.list("modules/net");
    expect(l.entries.map((e) => e.name)).toEqual(["modules/net/main.tf"]);
  });

  it.each([
    ".github/workflows/ci.yml", ".github/workflows/new.yml", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", "terraform.tfvars", "x.auto.tfvars", "terraform.tfstate", ".env",
    "key.pem", ".git/config", ".git/hooks/pre-commit", ".terraform/x", "ansible.cfg", "library/x.py", ".tflint.hcl", "a b.tf", "çalışma.tf", "../escape.tf", "/abs.tf", "a/../../b.tf",
  ])("yazma reddedilir: %s", async (p) => {
    const fs = await fresh();
    await expect(fs.write(p, "# x\n")).rejects.toThrow(/yol reddedildi/);
  });

  it("S-20: sembolik bağ kaçışı — yazma ve okuma (dosya, dizin, ara bölüm)", async () => {
    const fs = await fresh();
    const outside = await mkdtemp(join(tmpdir(), "ops-outside-"));
    await writeFile(join(outside, "secret.txt"), "dışarıdaki-içerik\n");
    try {
      // anlık kopyaya sonradan eklenen sembolik bağlar (ör. sandbox'lı bir aracın bıraktığı)
      await symlink(join(outside, "secret.txt"), join(fs.root, "evil-file.tf"));
      await symlink(outside, join(fs.root, "evil-dir"));
      await mkdir(join(fs.root, "real"));
      await symlink(outside, join(fs.root, "real", "inner"));
      await expect(fs.read("evil-file.tf")).rejects.toThrow(/sembolik bağ/);
      await expect(fs.write("evil-file.tf", "# x\n")).rejects.toThrow(/sembolik bağ/);
      await expect(fs.write("evil-dir/new.tf", "# x\n")).rejects.toThrow(/sembolik bağ/);
      await expect(fs.read("evil-dir/secret.txt")).rejects.toThrow(/sembolik bağ/);
      await expect(fs.write("real/inner/new.tf", "# x\n")).rejects.toThrow(/sembolik bağ/);
      await expect(fs.list("evil-dir")).rejects.toThrow(/sembolik bağ/);
      // dışarıdaki dosya değişmedi, yeni dosya oluşmadı
      expect(await readFile(join(outside, "secret.txt"), "utf8")).toBe("dışarıdaki-içerik\n");
      expect(await fs.list(".").then((l) => l.entries.map((e) => e.name))).not.toContain("evil-dir");
      const diff = await fs.changes();
      expect(diff.changes).toEqual([]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("gömülü secret içeren yazım REDDEDİLİR (değer yankılanmaz); sayısız kural; entropisiz bayat yanlış pozitif yok", async () => {
    const fs = await fresh();
    const aws = `AKIA${"A1B2C3D4E5F6G7H8"}`;
    const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----\n";
    const tok = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;
    for (const [what, content] of [["aws", `provider "aws" {\n  access_key = "${aws}"\n}\n`], ["pem", key], ["token", `token = "${tok}"\n`]] as const) {
      const err = await fs.write("bad.tf", content).then(() => null, (e: Error) => e);
      expect(err, what).not.toBeNull();
      expect(err?.message).toMatch(/gömülü secret benzeri değer/);
      expect(err?.message).not.toContain(aws);
      expect(err?.message).not.toContain(tok);
    }
    await expect(readFile(join(fs.root, "bad.tf"))).rejects.toThrow();
    // meşru içerik: değişken adı, SHA, kilit dosyası hash'i
    await fs.write("ok.tf", 'variable "db_password" {\n  type      = string\n  sensitive = true\n}\n# commit 9f2c1ab7d3e84f5a6b7c8d9e0f1a2b3c4d5e6f70\n');
    await fs.write("lock-like.tf", '# h1:abcdEFGHijklMNOPqrstUVWXyz0123456789abcdefg=\n');
    // M3: bilinen secret
    const k = makeCanary("known");
    const { KnownSecrets } = await import("@ops/redaction");
    const known = new KnownSecrets();
    known.add("t", k.value);
    const snap = fs.snapshot;
    const withKnown = new WorktreeFs(snap, P, { known });
    await expect(withKnown.write("known.tf", `x = "${k.value}"\n`)).rejects.toThrow(/gömülü secret/);
  });

  it("boyut/ikili/NUL sınırları", async () => {
    const fs = await fresh();
    await expect(fs.write("big.tf", "x".repeat(262_145))).rejects.toThrow(/çok büyük/);
    await expect(fs.write("nul.tf", "a\0b")).rejects.toThrow(/NUL/);
    await writeFile(join(fs.root, "bin.dat"), Buffer.from([1, 2, 0, 3]));
    await expect(fs.read("bin.dat")).rejects.toThrow(/ikili/);
    await writeFile(join(fs.root, "huge.txt"), "y".repeat(1_100_000));
    await expect(fs.read("huge.txt")).rejects.toThrow(/çok büyük/);
  });

  it("dosya sayısı sınırı", async () => {
    const policy = P;
    const snap = await createSnapshot({ repoPath: repo.dir, destDir: join(out, `lim${++n}`), sandbox: sandbox!, policy });
    const fs = new WorktreeFs(snap, policy, { limits: { maxReadBytes: 1_000_000, maxWriteBytes: 10_000, maxFiles: Object.keys(snap.manifest.files).length + 1, maxListEntries: 50 } });
    await fs.write("one.tf", "# 1\n");
    await expect(fs.write("two.tf", "# 2\n")).rejects.toThrow(/dosya sayısı sınırı/);
    await fs.write("one.tf", "# güncelleme serbest\n");
  });

  it("list: derinlik, gizli/atlanan adlar görünmez", async () => {
    const fs = await fresh();
    const l1 = await fs.list(".");
    expect(l1.entries.map((e) => e.name)).toEqual(expect.arrayContaining(["main.tf", "modules", "README.md", ".github"]));
    for (const hidden of ["prod.tfvars", ".env", "terraform.tfstate", "key.pem", ".git", "link"]) expect(l1.entries.map((e) => e.name)).not.toContain(hidden);
    const l2 = await fs.list(".", 2);
    expect(l2.entries.map((e) => e.name)).toContain("modules/vpc");
    expect(l2.entries.map((e) => e.name)).not.toContain("modules/vpc/main.tf");
    const l3 = await fs.list("modules", 3);
    expect(l3.entries.map((e) => e.name)).toContain("modules/vpc/main.tf");
  });

  it("changes/patch: yalnız değişenler; patch ÖZGÜN depoya `git apply` ile uygulanınca çalışma kopyasıyla aynı sonuç", async () => {
    const fs = await fresh();
    expect((await fs.changes()).changes).toEqual([]);
    await fs.write("main.tf", 'terraform {\n  required_version = ">= 1.6"\n}\n\nresource "terraform_data" "x" {\n  input = "hello"\n}\n');
    await fs.write("modules/net/main.tf", 'output "x" {\n  value = 1\n}\n');
    await fs.write("README.md", "# demo\n\nHello.\n"); // aynı içerik → değişiklik sayılmaz
    const { changes, patch } = await fs.changes();
    expect(changes.map((c) => [c.path, c.status])).toEqual([["main.tf", "modified"], ["modules/net/main.tf", "added"]]);
    expect(patch).toContain("+++ b/modules/net/main.tf");
    expect((await fs.changes("modules")).changes.map((c) => c.path)).toEqual(["modules/net/main.tf"]);
    // depoyu klonla, patch'i uygula, çalışma kopyasıyla karşılaştır
    const clone = join(out, `clone${++n}`);
    await run("git", ["clone", "-q", "--no-hardlinks", repo.dir, clone], { env: { PATH: process.env["PATH"] ?? "", HOME: out } });
    await writeFile(join(out, "p.patch"), patch);
    await run("git", ["apply", "--whitespace=nowarn", join(out, "p.patch")], { cwd: clone });
    expect(await readFile(join(clone, "main.tf"), "utf8")).toBe(await readFile(join(fs.root, "main.tf"), "utf8"));
    expect(await readFile(join(clone, "modules/net/main.tf"), "utf8")).toBe(await readFile(join(fs.root, "modules/net/main.tf"), "utf8"));
    // kullanıcının depo çalışma kopyası HİÇ değişmedi
    expect(await readFile(join(repo.dir, "main.tf"), "utf8")).toContain('">= 1.5"');
    await expect(readFile(join(repo.dir, "modules/net/main.tf"))).rejects.toThrow();
    void chmod;
  });
});
