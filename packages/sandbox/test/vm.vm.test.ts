// VM gerektiren testler (ADR-0011): `pnpm test:vm` ile, `OPS_TEST_VM=1` ve açık bir sandbox VM'i ile koşar.
// Varsayılan vitest yapılandırmasının DIŞINDADIR (CI'da atlanan test sayılmaz).
import { createServer } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { GUEST_NODE, VmSandbox, detectSandboxDetailed } from "../src/index.ts";
import type { SandboxSpec } from "../src/index.ts";

if (process.env["OPS_TEST_VM"] !== "1") throw new Error("vm.vm.test.ts yalnız OPS_TEST_VM=1 ile koşar (pnpm test:vm)");
const det = await detectSandboxDetailed({ env: { ...process.env, OPS_SANDBOX: "vm" } });
if (!(det.sandbox instanceof VmSandbox)) throw new Error(`VM sandbox yok: ${det.reason}`);
const vm: VmSandbox = det.sandbox;

const sh = (script: string, extra: Partial<SandboxSpec> = {}): SandboxSpec => ({ argv: ["/bin/sh", "-c", script], env: {}, timeoutMs: 20_000, maxOutputBytes: 100_000, ...extra });

describe("VmSandbox gerçek VM ile", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  it("gecikme bütçesi: sıcak bağlantıda çağrı başına p50 ≤ 250 ms, p95 ≤ 1 s", async () => {
    await vm.run(sh("true")); // ısıt
    const t: number[] = [];
    for (let i = 0; i < 20; i++) {
      const t0 = Date.now();
      const r = await vm.run(sh("true"));
      t.push(Date.now() - t0);
      expect(r.code).toBe(0);
    }
    t.sort((a, b) => a - b);
    const p50 = t[Math.floor(t.length * 0.5)] as number;
    const p95 = t[Math.floor(t.length * 0.95)] as number;
    console.log(`[vm] gecikme ms: p50=${p50} p95=${p95} min=${t[0]} max=${t.at(-1)}`);
    expect(p50).toBeLessThanOrEqual(250);
    expect(p95).toBeLessThanOrEqual(1000);
  });

  it("konuk düzeni kullanılır: /bin symlink, ld.so.cache bağlı; host'un /Users'ı görünmez", async () => {
    const r = await vm.run(sh("readlink /bin; ls /etc/ld.so.cache; ls /Users 2>&1; uname -s"));
    const out = r.stdout.toString();
    expect(out).toContain("usr/bin");
    expect(out).toContain("/etc/ld.so.cache");
    expect(out).toContain("No such file");
    expect(out).toContain("Linux");
  });

  it("paylaşım: TMPDIR paylaşım altında → rw bağ host'a yansır; paylaşılmamış yol komut ÇALIŞMADAN reddedilir", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-vmrw-"));
    dirs.push(d);
    const r = await vm.run(sh(`echo konuk > ${d}/w.txt; cat ${d}/w.txt`, { rwBinds: [d] }));
    expect(r.stdout.toString().trim()).toBe("konuk");
    const { readFile } = await import("node:fs/promises");
    expect((await readFile(join(d, "w.txt"), "utf8")).trim()).toBe("konuk");
    await expect(vm.run(sh("true", { roBinds: ["/etc"] }))).rejects.toMatchObject({ code: "vm_path_not_shared" });
    await expect(vm.run(sh("true", { roBinds: [process.env["HOME"] ?? "/Users"] }))).rejects.toMatchObject({ code: "vm_path_not_shared" });
  });

  it("zaman aşımı ve kill: konukta yetim süreç kalmaz (işaretle pkill + timeout)", async () => {
    const mark = `ops-vm-orphan-${Date.now()}`;
    const r = await vm.run(sh(`sleep 300; echo ${mark}`, { timeoutMs: 1_000 }));
    expect(r.timedOut).toBe(true);
    await new Promise((res) => setTimeout(res, 1_500));
    const left = await vm.remote(`pgrep -af 'sleep 300' | grep -v pgrep || echo yok`);
    expect(left.stdout.toString()).toContain("yok");
    // akışlı: kill() sonrası da kalıntı yok
    const p = await vm.spawn(sh("sleep 301", { timeoutMs: 60_000 }));
    await new Promise((res) => setTimeout(res, 800));
    p.kill();
    await p.exited;
    await new Promise((res) => setTimeout(res, 1_500));
    const left2 = await vm.remote(`pgrep -af 'sleep 301' | grep -v pgrep || echo yok`);
    expect(left2.stdout.toString()).toContain("yok");
  });

  it("ağ: ad alanı ayrı; 'host' ağı konuğun ağıdır — host loopback'i GÖRÜLMEZ (ADR-0011 §7)", async () => {
    const server = createServer((s) => s.end("pong"));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      const probe = `exec 3<>/dev/tcp/127.0.0.1/${port} && echo bagli || echo baglanamadi`;
      for (const network of ["none", "host"] as const) {
        const r = await vm.run({ ...sh(probe), argv: ["/bin/bash", "-c", probe], network });
        expect(r.stdout.toString()).toContain("baglanamadi");
      }
    } finally {
      server.close();
    }
  });

  it("konuk dosya sistemi görünümü: araçlar konukta var, host yolları yok; sha256 konuk dosyasının", async () => {
    expect(await vm.fs.executable(GUEST_NODE)).toBe(true);
    expect(await vm.fs.executable("/opt/ops-tools/bin/tofu")).toBe(true);
    expect(await vm.fs.executable("/usr/bin/git")).toBe(true);
    expect(await vm.fs.exists("/Applications")).toBe(false);
    expect(await vm.fs.readlink("/bin")).toBe("usr/bin");
    expect(await vm.fs.realpath("/bin/sh")).toMatch(/^\/usr\/bin\/(dash|sh|bash)$/);
    const d = await mkdtemp(join(tmpdir(), "ops-vmsha-"));
    dirs.push(d);
    await writeFile(join(d, "f"), "merhaba\n");
    const { createHash } = await import("node:crypto");
    expect(await vm.fs.sha256(join(d, "f"))).toBe(createHash("sha256").update("merhaba\n").digest("hex"));
    expect(await vm.fs.sha256("/yok/dosya")).toBeNull();
  });

  it("stdin iletilir, stdout/stderr ayrı, çıkış kodu aynen, çıktı sınırı keser", async () => {
    const r = await vm.run(sh("cat; echo hata >&2; exit 3", { stdin: new TextEncoder().encode("girdi") }));
    expect(r.stdout.toString()).toBe("girdi");
    expect(r.stderr.toString()).toBe("hata\n");
    expect(r.code).toBe(3);
    const big = await vm.run(sh("yes x | head -c 1000000", { maxOutputBytes: 5_000 }));
    expect(big.truncated).toBe(true);
  });
});
