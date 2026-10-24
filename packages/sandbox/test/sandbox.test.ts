import { createServer } from "node:net";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { makeCanary } from "@ops/testkit";
import {
  BwrapSandbox,
  SeatbeltSandbox,
  UnsafeDirectRunner,
  buildBwrapArgs,
  buildSeatbeltProfile,
  detectSandbox,
  sbplString,
  validateSpec,
} from "../src/index.ts";
import type { HostLayout, Sandbox, SandboxSpec } from "../src/index.ts";

const layout: HostLayout = {
  async entry(p) {
    if (p === "/bin" || p === "/lib" || p === "/lib64") return { type: "symlink", target: `usr${p}` };
    if (p === "/etc/ssl") return { type: "dir" };
    return undefined;
  },
};
const base: SandboxSpec = { argv: ["/usr/bin/true"], env: {}, timeoutMs: 5000, maxOutputBytes: 10_000 };

describe("bwrap argüman kurucusu (saf)", () => {
  it("tüm ad alanları ayrı, ortam temizlenir, argv '--' sonrasında ve kabuk yok", async () => {
    const a = await buildBwrapArgs({ ...base, argv: ["/usr/bin/aws", "eks", "get-token"], env: { AWS_REGION: "eu-west-1" } }, layout);
    expect(a.slice(0, 3)).toEqual(["--die-with-parent", "--new-session", "--unshare-all"]);
    expect(a).not.toContain("--share-net");
    expect(a).toContain("--clearenv");
    expect(a.slice(a.indexOf("--") + 1)).toEqual(["/usr/bin/aws", "eks", "get-token"]);
    const setenv = a.flatMap((x, i) => (x === "--setenv" ? [`${a[i + 1]}=${a[i + 2]}`] : []));
    expect(setenv).toEqual(expect.arrayContaining(["AWS_REGION=eu-west-1", "PATH=/usr/local/bin:/usr/bin:/bin"]));
    expect(a.join(" ")).not.toMatch(/\/home|\/root|\/run\b|\/var\b/);
  });

  it("merged-usr symlink'leri korunur; /etc'den yalnız sertifika depoları", async () => {
    const a = await buildBwrapArgs(base, layout);
    const s = a.join(" ");
    expect(s).toContain("--symlink usr/bin /bin");
    expect(s).toContain("--ro-bind /usr /usr");
    expect(s).not.toMatch(/--(?:ro-)?bind(?:-try)? \/etc \/etc/);
    expect(s).not.toContain("/etc/passwd");
    expect(s).not.toContain("/etc/shadow");
  });

  it("ağ yalnız 'host' istenirse paylaşılır ve çözümleyici dosyaları eklenir", async () => {
    const none = (await buildBwrapArgs(base, layout)).join(" ");
    expect(none).not.toContain("resolv.conf");
    const host = await buildBwrapArgs({ ...base, network: "host" }, layout);
    expect(host).toContain("--share-net");
    expect(host.join(" ")).toContain("/etc/resolv.conf");
  });

  it("roBinds salt okunur, rwBinds yazılabilir; ev dizini tmpfs'te, bağlamalardan ÖNCE", async () => {
    const a = await buildBwrapArgs({ ...base, home: "/home/u", roBinds: ["/home/u/.aws"], rwBinds: ["/srv/cache"] }, layout);
    const s = a.join(" ");
    expect(s).toContain("--ro-bind /home/u/.aws /home/u/.aws");
    expect(s).toContain("--bind /srv/cache /srv/cache");
    expect(a.indexOf("--tmpfs")).toBeLessThan(a.indexOf("/home/u/.aws"));
    expect(s.indexOf("--tmpfs /home/u")).toBeLessThan(s.indexOf("--ro-bind /home/u/.aws"));
    expect(a.flatMap((x, i) => (x === "--setenv" ? [`${a[i + 1]}=${a[i + 2]}`] : []))).toContain("HOME=/home/u");
  });

  it("geçersiz girdi reddedilir: göreli ikili, '..', NUL, kötü env adı, kabuk metakarakterli değerler argv'de tek parça kalır", async () => {
    expect(() => validateSpec({ ...base, argv: ["aws"] })).toThrow(/mutlak/);
    expect(() => validateSpec({ ...base, roBinds: ["/a/../etc"] })).toThrow(/'\.\.'/);
    expect(() => validateSpec({ ...base, argv: ["/usr/bin/x", "a\0b"] })).toThrow(/NUL/);
    expect(() => validateSpec({ ...base, env: { "A B": "x" } })).toThrow(/ortam değişkeni/);
    expect(() => validateSpec({ ...base, timeoutMs: 0 })).toThrow();
    const a = await buildBwrapArgs({ ...base, argv: ["/usr/bin/x", "; rm -rf /", "$(id)"] }, layout);
    expect(a.slice(-2)).toEqual(["; rm -rf /", "$(id)"]);
  });
});

describe("seatbelt profil kurucusu (macOS'ta ELLE doğrulanmalı)", () => {
  it("varsayılan ret, ağ kapalı; 'host' ağı açar; yollar tırnaklanır", () => {
    const p = buildSeatbeltProfile({ ...base, roBinds: ["/Users/u/.aws"], home: "/private/tmp/h" });
    expect(p).toContain("(deny default)");
    expect(p).toContain("(deny network*)");
    expect(p).toContain('(subpath "/Users/u/.aws")');
    expect(buildSeatbeltProfile({ ...base, network: "host" })).toContain("(allow network*)");
  });

  it("profil enjeksiyonu: tırnak/yeni satır içeren yol reddedilir", () => {
    expect(() => sbplString('/x") (allow default) ("')).toThrow();
    expect(() => buildSeatbeltProfile({ ...base, roBinds: ['/a"b'] })).toThrow();
    expect(() => buildSeatbeltProfile({ ...base, roBinds: ["/a\nb"] })).toThrow();
  });

  it("komut: env -i ile ortam temizlenir, argv sonda", () => {
    const sb = new SeatbeltSandbox("/usr/bin/sandbox-exec");
    const c = sb.buildCommand({ ...base, argv: ["/usr/local/bin/kubelogin", "get-token"], env: { X: "1" } });
    expect(c.file).toBe("/usr/bin/sandbox-exec");
    expect(c.args.slice(0, 1)).toEqual(["-p"]);
    expect(c.args).toEqual(expect.arrayContaining(["/usr/bin/env", "-i", "X=1"]));
    expect(c.args.slice(-2)).toEqual(["/usr/local/bin/kubelogin", "get-token"]);
  });
});

describe("detectSandbox", () => {
  it("bwrap yoksa veya yoklama başarısızsa null (çağıran fail-closed olur)", async () => {
    expect(await detectSandbox({ platform: "linux", pathEnv: "/yok" })).toBeNull();
    expect(await detectSandbox({ platform: "win32" })).toBeNull();
    expect(await detectSandbox({ platform: "linux", probe: async () => false })).toBeNull();
  });
});

describe("UnsafeDirectRunner", () => {
  it("açık onay ister ve yalnız verilen ortamı geçirir", async () => {
    // @ts-expect-error onay olmadan oluşturulamaz
    expect(() => new UnsafeDirectRunner({})).toThrow();
    process.env["OPS_TEST_CANARY_ENV"] = "ortamdan-sizar";
    try {
      const r = await new UnsafeDirectRunner({ acknowledgeNoIsolation: true }).run({ ...base, argv: ["/usr/bin/env"], env: { A: "1" } });
      const text = r.stdout.toString();
      expect(text).toContain("A=1");
      expect(text).not.toContain("ortamdan-sizar");
    } finally {
      delete process.env["OPS_TEST_CANARY_ENV"];
    }
  });
});

// ---- GERÇEK izolasyon (bwrap kurulu ve çalışıyorsa) ------------------------------------------

const real: Sandbox | null = await detectSandbox();

describe("bwrap ile gerçek izolasyon (S-15)", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  const need = (): Sandbox => {
    if (!real) throw new Error("bwrap yok");
    return real;
  };
  const sh = (script: string, extra: Partial<SandboxSpec> = {}): SandboxSpec => ({
    argv: ["/bin/sh", "-c", script],
    env: {},
    timeoutMs: 10_000,
    maxOutputBytes: 100_000,
    ...extra,
  });
  const itReal = (name: string, fn: () => Promise<void>) => (real === null ? it.skip : it)(name, fn);

  it("bu ortamda bwrap tespit edilir (yoksa aşağıdaki gerçek testler atlanır)", () => {
    if (real === null) console.warn("UYARI: bwrap yok/çalışmıyor — gerçek izolasyon testleri atlandı");
    expect(real === null || real.kind === "bwrap").toBe(true);
  });

  itReal("host ortamı sızmaz: yalnız verilen env görünür", async () => {
    const c = makeCanary("sandbox-env");
    process.env["OPS_SANDBOX_CANARY"] = c.value;
    try {
      const r = await need().run(sh("env", { env: { ONLY: "this" } }));
      const out = r.stdout.toString();
      expect(out).toContain("ONLY=this");
      expect(out).not.toContain(c.value);
      expect(out).not.toContain("OPS_SANDBOX_CANARY");
    } finally {
      delete process.env["OPS_SANDBOX_CANARY"];
    }
  });

  itReal("ev dizini ve kimlik yolları yok: ~/.kube, ~/.aws, ~/.ssh, /root, /home, /run, D-Bus soketi", async () => {
    const fake = await mkdtemp(join(tmpdir(), "ops-fakehome-"));
    dirs.push(fake);
    const c = makeCanary("sandbox-file");
    await mkdir(join(fake, ".kube"), { recursive: true });
    await writeFile(join(fake, ".kube", "config"), `token: ${c.value}\n`);
    await mkdir(join(fake, ".aws"), { recursive: true });
    await writeFile(join(fake, ".aws", "credentials"), c.value);
    const r = await need().run(sh(`cat ${fake}/.kube/config ${fake}/.aws/credentials 2>&1; ls /root /home /run /var /etc/passwd /etc/shadow 2>&1; echo done`));
    const out = r.stdout.toString();
    expect(out).not.toContain(c.value);
    expect(out).toContain("No such file");
    expect(out).toContain("done");
    expect(out).not.toMatch(/dbus|keyring/i);
  });

  itReal("yalnız açıkça bağlanan yol görünür ve salt okunurdur", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-bind-"));
    dirs.push(d);
    await writeFile(join(d, "ok.txt"), "merhaba");
    const r = await need().run(sh(`cat ${d}/ok.txt; echo x > ${d}/yeni.txt 2>&1; echo kod=$?`, { roBinds: [d] }));
    const out = r.stdout.toString();
    expect(out).toContain("merhaba");
    expect(out).toMatch(/kod=[12]/);
    await expect(readFile(join(d, "yeni.txt"))).rejects.toThrow();
  });

  itReal("yazılabilir bağ host'a yansır; /tmp ve home tmpfs'tir (kalıcı değil)", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-rw-"));
    dirs.push(d);
    const r = await need().run(sh(`echo x > ${d}/w.txt; echo y > /tmp/gecici.txt; echo z > $HOME/h.txt; echo ok`, { rwBinds: [d], home: "/home/sandbox" }));
    expect(r.stdout.toString()).toContain("ok");
    expect((await readFile(join(d, "w.txt"), "utf8")).trim()).toBe("x");
    await expect(readFile("/tmp/gecici.txt")).rejects.toThrow();
  });

  itReal("ağ ad alanı ayrı: host loopback'inde dinleyen sunucuya erişilemez; 'host' ağında erişilir", async () => {
    const server = createServer((s) => {
      s.on("error", () => undefined); // istemci bağlantıyı hemen kapatabilir (ECONNRESET)
      s.end("pong");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      const probe = `exec 3<>/dev/tcp/127.0.0.1/${port} && echo bagli || echo baglanamadi`;
      const none = await need().run({ ...sh(probe), argv: ["/bin/bash", "-c", probe] });
      expect(none.stdout.toString()).toContain("baglanamadi");
      const host = await need().run({ ...sh(probe), argv: ["/bin/bash", "-c", probe], network: "host" });
      expect(host.stdout.toString()).toContain("bagli");
    } finally {
      server.close();
    }
  });

  itReal("PID ad alanı ayrı: host süreçleri görünmez", async () => {
    const r = await need().run(sh("ls /proc | grep -c '^[0-9]'"));
    expect(Number(r.stdout.toString().trim())).toBeLessThan(10);
  });

  itReal("stdin iletilir; zaman aşımı süreci öldürür; çıktı sınırı kesip öldürür", async () => {
    const echo = await need().run(sh("cat", { stdin: new TextEncoder().encode("girdi") }));
    expect(echo.stdout.toString()).toBe("girdi");
    const t0 = Date.now();
    const to = await need().run(sh("sleep 30", { timeoutMs: 400 }));
    expect(to.timedOut).toBe(true);
    expect(Date.now() - t0).toBeLessThan(5000);
    const big = await need().run(sh("yes x | head -c 1000000", { maxOutputBytes: 5_000 }));
    expect(big.truncated).toBe(true);
  });

  itReal("çalıştırılabilir yazma: sandbox içinden host'ta betik bırakılamaz (/usr salt okunur)", async () => {
    const r = await need().run(sh("echo x > /usr/bin/ops-test-yaz 2>&1; echo kod=$?"));
    expect(r.stdout.toString()).toMatch(/kod=[12]/);
    await expect(readFile("/usr/bin/ops-test-yaz")).rejects.toThrow();
  });

  itReal("açık izin verilmeyen ikili çalışmaz: tmp'de bıraktığımız betik host'tan bağlanmadıkça görünmez", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-bin-"));
    dirs.push(d);
    const script = join(d, "plugin.sh");
    await writeFile(script, "#!/bin/sh\necho calisti\n");
    await chmod(script, 0o755);
    const hidden = await need().run({ ...sh(""), argv: [script], env: {} }).catch((e: Error) => e);
    const out = hidden instanceof Error ? hidden.message : `${hidden.stdout.toString()}${hidden.stderr.toString()}`;
    expect(out).not.toContain("calisti");
    const shown = await need().run({ argv: [script], env: {}, roBinds: [d], timeoutMs: 5000, maxOutputBytes: 1000 });
    expect(shown.stdout.toString()).toContain("calisti");
  });
});

describe("BwrapSandbox yanlış yol", () => {
  it("var olmayan bwrap ikilisi anlamlı hata verir", async () => {
    await expect(new BwrapSandbox("/yok/bwrap").run(base)).rejects.toThrow();
  });
});
