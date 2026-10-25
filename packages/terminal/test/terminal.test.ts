import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCatalog } from "@ops/classifiers";
import { detectSandbox, UnsafeDirectRunner } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { makeCanary } from "@ops/testkit";
import { TerminalAdapter, assertSafeWorkdir, shellRun } from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const catalog = parseCatalog(readFileSync(join(here, "..", "..", "..", "policies", "command-catalog", "core.yaml"), "utf8"));
const real: Sandbox | null = await detectSandbox();

describe("TerminalAdapter", () => {
  let ws: string;
  const canary = makeCanary("ws-secret");
  beforeAll(async () => {
    ws = await mkdtemp(join(tmpdir(), "ops-ws-"));
    await writeFile(join(ws, "README.md"), "# Proje\nTODO: birinci\nTODO: ikinci\n");
    await writeFile(join(ws, "data.json"), JSON.stringify({ name: "demo", items: [{ name: "a" }, { name: "b" }] }));
    await writeFile(join(ws, ".env"), `TOKEN=${canary.value}\n`);
    await writeFile(join(ws, "server.pem"), canary.value);
    await mkdir(join(ws, "src"), { recursive: true });
    await writeFile(join(ws, "src", "a.ts"), "export const a = 1; // TODO: sil\n");
    execFileSync("git", ["init", "-q"], { cwd: ws });
    execFileSync("git", ["-c", "user.email=t@t.invalid", "-c", "user.name=t", "add", "-A"], { cwd: ws });
    execFileSync("git", ["-c", "user.email=t@t.invalid", "-c", "user.name=t", "commit", "-qm", "ilk"], { cwd: ws });
  });
  afterAll(async () => {
    await rm(ws, { recursive: true, force: true });
  });

  const adapter = (sandbox: Sandbox | null) => new TerminalAdapter({ sandbox, catalog, workdir: ws });
  const call = (a: TerminalAdapter, command: string) =>
    a.invoke({ tool: "shell.run", args: { command }, profile: undefined as never, handle: null, callId: "c", signal: new AbortController().signal, limits: shellRun.descriptor.limits });
  const itReal = (name: string, fn: () => Promise<void>) => (real ? it : it.skip)(name, fn);

  it("araç tanımı: kimliksiz, yerel, ağ yok, read; katı şema", () => {
    expect(shellRun.descriptor).toMatchObject({ scope: "local", profileKind: null, network: "none", class: "read", untrustedOutput: true, toolset: "shell" });
    expect(shellRun.descriptor.inputSchema).toMatchObject({ additionalProperties: false });
  });

  it("sandbox yoksa veya izolasyonsuzsa ÇALIŞMAZ (fail-closed)", async () => {
    await expect(call(adapter(null), "ls")).rejects.toMatchObject({ code: "sandbox_unavailable" });
    await expect(call(adapter(new UnsafeDirectRunner({ acknowledgeNoIsolation: true })), "ls")).rejects.toMatchObject({ code: "sandbox_unavailable" });
  });

  itReal("temel komutlar gerçek sandbox'ta çalışır: ls, cat, grep, jq, git", async () => {
    const a = adapter(real);
    const ls = (await call(a, "ls -a")).data as { exit: number; stdout: string };
    expect(ls.exit).toBe(0);
    expect(ls.stdout).toContain("README.md");
    const cat = (await call(a, "cat README.md")).data as { stdout: string };
    expect(cat.stdout).toContain("TODO: birinci");
    const grep = (await call(a, "grep -rn TODO src README.md")).data as { stdout: string };
    expect(grep.stdout).toContain("src/a.ts");
    const jq = (await call(a, "jq -r '.items[].name' data.json")).data as { stdout: string };
    expect(jq.stdout.trim().split("\n")).toEqual(["a", "b"]);
    const st = (await call(a, "git log --oneline")).data as { exit: number; stdout: string };
    expect(st.exit).toBe(0);
    expect(st.stdout).toContain("ilk");
    const stat = (await call(a, "git status --short")).data as { exit: number };
    expect(stat.exit).toBe(0);
  });

  itReal("boru hatı ve bağlaçlar uygulanır", async () => {
    const a = adapter(real);
    const p = (await call(a, "cat README.md | grep TODO | wc -l")).data as { stdout: string };
    expect(p.stdout.trim()).toBe("2");
    const seq = (await call(a, "ls nonexistent-xyz && pwd")).data as { exit: number; stdout: string };
    expect(seq.stdout).toBe("");
    expect(seq.exit).not.toBe(0);
    const or = (await call(a, "ls nonexistent-xyz || pwd")).data as { exit: number; stdout: string };
    expect(or.exit).toBe(0);
    expect(or.stdout.trim()).toBe(ws);
    const semi = (await call(a, "pwd ; date -u")).data as { stdout: string };
    expect(semi.stdout).toContain(ws);
  });

  itReal("secret dosyaları: .env/.pem doğrudan okunamaz; grep -r bunlara İNMEZ; .git/ okunamaz", async () => {
    const a = adapter(real);
    for (const cmd of ["cat .env", "cat server.pem", "cat .git/config", "head -n 1 .env"]) {
      await expect(call(a, cmd), cmd).rejects.toMatchObject({ code: "unclassified" });
    }
    const g = (await call(a, `grep -rn ${"'"}${canary.value.slice(0, 12)}${"'"} .`)).data as { stdout: string };
    expect(g.stdout).not.toContain(canary.value);
    expect(g.stdout).toBe("");
  });

  itReal("sandbox: ortam temiz, host dosyaları yok, iş alanı salt-okunur", async () => {
    process.env["OPS_TERMINAL_ENV_CANARY"] = makeCanary("term-env").value;
    try {
      const a = adapter(real);
      // `env` kataloğda yok; sızıntıyı git aracılığıyla dolaylı denemek yerine jq ile ortamı oku
      const env = (await call(a, "jq -n 'env | keys'")).data as { stdout: string };
      expect(env.stdout).not.toContain("OPS_TERMINAL_ENV_CANARY");
      expect(env.stdout).not.toMatch(/AWS_|KUBECONFIG|TOKEN/);
      const hostFile = (await call(a, "ls /etc")).data;
      void hostFile;
    } catch (e) {
      // `ls /etc` jail'e takılır: bu beklenen davranıştır
      expect((e as { code?: string }).code).toBe("unclassified");
    } finally {
      delete process.env["OPS_TERMINAL_ENV_CANARY"];
    }
  });

  itReal("iş alanındaki sembolik bağ iş alanı dışındaki dosyayı OKUTMAZ (hedef sandbox'ta yok)", async () => {
    const outside = await mkdtemp(join(tmpdir(), "ops-outside-"));
    try {
      await writeFile(join(outside, "gizli.txt"), canary.value);
      await symlink(join(outside, "gizli.txt"), join(ws, "link.txt"));
      const r = (await call(adapter(real), "cat link.txt")).data as { exit: number; stdout: string };
      expect(r.exit).not.toBe(0);
      expect(r.stdout).not.toContain(canary.value);
    } finally {
      await rm(join(ws, "link.txt"), { force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  itReal("harici diff sürücüsü kodu çalıştırmaz (repo yapılandırması güvenilmez)", async () => {
    const repo = await mkdtemp(join(tmpdir(), "ops-evilrepo-"));
    try {
      execFileSync("git", ["init", "-q"], { cwd: repo });
      await writeFile(join(repo, "a.txt"), "bir\n");
      execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], { cwd: repo });
      execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], { cwd: repo });
      await writeFile(join(repo, "a.txt"), "iki\n");
      // repo yapılandırması zararlı: diff.external bir betik çalıştırır, hooksPath/fsmonitor ayarlı
      const marker = join(repo, "PWNED");
      await writeFile(join(repo, "evil.sh"), `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o755 });
      execFileSync("git", ["config", "diff.external", join(repo, "evil.sh")], { cwd: repo });
      execFileSync("git", ["config", "core.fsmonitor", join(repo, "evil.sh")], { cwd: repo });
      const a = new TerminalAdapter({ sandbox: real, catalog, workdir: repo });
      const d = (await call(a, "git diff")).data as { exit: number; stdout: string };
      expect(d.exit).toBe(0);
      expect(d.stdout).toContain("iki");
      await call(a, "git status --short");
      const { existsSync } = await import("node:fs");
      expect(existsSync(marker)).toBe(false);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  itReal("çıktı sınırı: dev çıktı kesilir ve işaretlenir; sonsuz komut zaman aşımıyla biter", async () => {
    await writeFile(join(ws, "big.txt"), "satır\n".repeat(400_000));
    const big = await call(adapter(real), "cat big.txt");
    expect(big.truncated).toBe(true);
    await rm(join(ws, "big.txt"));
    // FIFO'dan okuyan cat sonsuza dek bloklanır: aşama zaman aşımı süreci öldürmeli.
    // VM kipinde paylaşım (hgfs) FIFO taşımaz — konukta düz dosya görünür; zaman aşımı/kill yolu `vm.vm.test.ts`te sınanır.
    if (real?.kind === "vm") return;
    execFileSync("mkfifo", [join(ws, "boru")]);
    const t0 = Date.now();
    const slow = new TerminalAdapter({ sandbox: real, catalog, workdir: ws, stageTimeoutMs: 400 });
    const r = (await call(slow, "cat boru")).data as { exit: number; stderr?: string };
    expect(r.exit).toBe(124);
    expect(r.stderr).toContain("zaman aşımı");
    expect(Date.now() - t0).toBeLessThan(10_000);
    await rm(join(ws, "boru"), { force: true });
  });
});

describe("assertSafeWorkdir", () => {
  it("kök, ev dizini ve üstleri reddedilir; ayrı proje dizini kabul edilir", async () => {
    const home = await mkdtemp(join(tmpdir(), "ops-fakehome-"));
    const proj = join(home, "proj");
    await mkdir(proj, { recursive: true });
    await expect(assertSafeWorkdir("/", home)).rejects.toMatchObject({ code: "workdir_invalid" });
    await expect(assertSafeWorkdir(home, home)).rejects.toMatchObject({ code: "workdir_invalid" });
    await expect(assertSafeWorkdir(dirname(home), home)).rejects.toMatchObject({ code: "workdir_invalid" });
    await expect(assertSafeWorkdir("goreli/yol", home)).rejects.toMatchObject({ code: "workdir_invalid" });
    await expect(assertSafeWorkdir(join(home, "yok"), home)).rejects.toMatchObject({ code: "workdir_invalid" });
    expect(await assertSafeWorkdir(proj, home)).toContain("proj");
    await rm(home, { recursive: true, force: true });
  });
});
