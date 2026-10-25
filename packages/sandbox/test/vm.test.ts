import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  LAYOUT_PATHS,
  VmSandbox,
  buildBwrapArgs,
  buildRemoteCommand,
  detectSandbox,
  detectSandboxDetailed,
  layoutProbeCommand,
  loadVmState,
  mapGuestPath,
  parseLayoutProbe,
  parseVmState,
  remoteKillCommand,
  shellQuote,
  translateSpec,
  withCallMarker,
} from "../src/index.ts";
import type { SandboxSpec, VmState } from "../src/index.ts";

const state: VmState = {
  version: 1,
  box: "bento/ubuntu-24.04",
  boxVersion: "202502.21.0",
  provider: "vmware_desktop",
  shares: [
    { host: "/Users/u/.ops-assistant/worktrees", guest: "/Users/u/.ops-assistant/worktrees", mode: "rw" },
    { host: "/Users/u/src/infra", guest: "/Users/u/src/infra", mode: "ro" },
    { host: "/Volumes/data/repo", guest: "/ops/repo", mode: "ro" },
  ],
  toolDirs: ["/opt/ops-tools/bin", "/opt/ops-tools/venv/bin"],
  guestRoots: ["/opt/ops-tools", "/etc/alternatives"],
  sshConfig: "/Users/u/.ops-assistant/vm/ssh_config",
  createdAt: "2026-10-25T00:00:00Z",
};
const base: SandboxSpec = { argv: ["/usr/bin/true"], env: {}, timeoutMs: 5000, maxOutputBytes: 10_000 };

describe("VM yol eşlemesi (ADR-0011 §4)", () => {
  it("paylaşım altı → konuk yolu (aynı veya farklı önek); konuk kökü aynen; başka her şey null", () => {
    expect(mapGuestPath("/Users/u/.ops-assistant/worktrees/s1--infra/work", state)).toBe("/Users/u/.ops-assistant/worktrees/s1--infra/work");
    expect(mapGuestPath("/Users/u/.ops-assistant/worktrees", state)).toBe("/Users/u/.ops-assistant/worktrees");
    expect(mapGuestPath("/Volumes/data/repo/main.tf", state)).toBe("/ops/repo/main.tf");
    expect(mapGuestPath("/opt/ops-tools/venv/bin/ansible-lint", state)).toBe("/opt/ops-tools/venv/bin/ansible-lint");
    expect(mapGuestPath("/Users/u/.ops-assistant/vault", state)).toBeNull();
    expect(mapGuestPath("/Users/u/.ops-assistant/worktreesX", state)).toBeNull(); // önek değil, dizin sınırı
    expect(mapGuestPath("/Users/u", state)).toBeNull();
    expect(mapGuestPath("/Volumes/data", state)).toBeNull();
  });

  const noReal = async (): Promise<string | null> => null;
  const tr = (spec: SandboxSpec) => translateSpec(spec, state, noReal);

  it("translateSpec: bağlar paylaşım/konuk kökü altında olmalı; rw bağ yalnız rw paylaşımda; cwd ev dizini veya /tmp olabilir", async () => {
    const t = await tr({ ...base, argv: ["/Volumes/data/repo/run.sh", "--config=/Volumes/data/repo/cfg", "/Users/u/.ops-assistant/worktrees/a"], env: { TF_DATA_DIR: "/Volumes/data/repo/td", X: "/Users/u/.ssh/id" }, roBinds: ["/Volumes/data/repo", "/opt/ops-tools"], rwBinds: ["/Users/u/.ops-assistant/worktrees/s1--infra/work"], cwd: "/Volumes/data/repo", home: "/home/ops-iac" });
    expect(t.argv).toEqual(["/ops/repo/run.sh", "--config=/ops/repo/cfg", "/Users/u/.ops-assistant/worktrees/a"]);
    expect(t.env).toEqual({ TF_DATA_DIR: "/ops/repo/td", X: "/Users/u/.ssh/id" }); // paylaşılmayan yol değişmez (ve bağlanamaz)
    expect(t.roBinds).toEqual(["/ops/repo", "/opt/ops-tools"]);
    expect(t.rwBinds).toEqual(["/Users/u/.ops-assistant/worktrees/s1--infra/work"]);
    expect(t.cwd).toBe("/ops/repo");
    await expect(tr({ ...base, roBinds: ["/Users/u/.ssh"] })).rejects.toMatchObject({ code: "vm_path_not_shared" });
    await expect(tr({ ...base, roBinds: ["/Users/u/.ops-assistant/vault"] })).rejects.toThrow(/paylaşılmamış/);
    await expect(tr({ ...base, rwBinds: ["/Users/u/src/infra"] })).rejects.toThrow(/salt okunur/);
    await expect(tr({ ...base, rwBinds: ["/opt/ops-tools"] })).rejects.toThrow(/salt okunur|konuk kökü/);
    await expect(tr({ ...base, cwd: "/Users/u" })).rejects.toThrow(/çalışma dizini/);
    expect((await tr({ ...base, cwd: "/home/ops-mcp", home: "/home/ops-mcp" })).cwd).toBe("/home/ops-mcp");
    expect((await tr({ ...base, cwd: "/tmp" })).cwd).toBe("/tmp");
    // konuk ikilisi: paylaşım dışı argv[0] dokunulmaz (konukta var sayılır; yoksa bwrap açık hata verir)
    expect((await tr({ ...base, argv: ["/usr/bin/git", "status"] })).argv).toEqual(["/usr/bin/git", "status"]);
  });

  it("sembolik bağ: paylaşıma GİREN bağ gerçek yoluyla bağlanır; paylaşımdan ÇIKAN bağ reddedilir (realpath host'ta çözülür)", async () => {
    const links: Record<string, string> = { "/Users/u/infra-link": "/Users/u/src/infra", "/Users/u/src/infra/evil": "/Users/u/.ssh" };
    const resolve = async (p: string): Promise<string | null> => links[p] ?? null;
    const t = await translateSpec({ ...base, roBinds: ["/Users/u/infra-link"], cwd: "/Users/u/infra-link" }, state, resolve);
    expect(t.roBinds).toEqual(["/Users/u/src/infra"]);
    expect(t.cwd).toBe("/Users/u/src/infra");
    await expect(translateSpec({ ...base, roBinds: ["/Users/u/src/infra/evil"] }, state, resolve)).rejects.toMatchObject({ code: "vm_path_not_shared" });
  });

  it("validateSpec kuralları VM'de de geçer ('..', göreli ikili)", async () => {
    await expect(tr({ ...base, roBinds: ["/Users/u/.ops-assistant/worktrees/../vault"] })).rejects.toThrow(/'\.\.'/);
    await expect(tr({ ...base, argv: ["git"] })).rejects.toThrow(/mutlak/);
  });
});

describe("uzak komut kurucusu (ADR-0011 §3)", () => {
  it("tek tırnak kaçışı: kabuk metakarakterleri yorumlanmaz", () => {
    expect(shellQuote("a b")).toBe("'a b'");
    expect(shellQuote("it's $(id) `x` ; rm -rf /")).toBe(`'it'\\''s $(id) \`x\` ; rm -rf /'`);
    expect(() => shellQuote("a\0b")).toThrow(/NUL/);
  });

  it("exec timeout -s KILL + bwrap; aynı bwrap argümanları; çağrı işareti --unshare-all'dan sonra", async () => {
    const layout = { entry: async (p: string) => (p === "/bin" ? ({ type: "symlink", target: "usr/bin" } as const) : undefined) };
    const args = await buildBwrapArgs({ ...base, argv: ["/usr/bin/aws", "eks", "get-token"], env: { A: "x y" } }, layout);
    const marked = withCallMarker(args, "0123456789abcdef");
    expect(marked.slice(0, 5)).toEqual(["--die-with-parent", "--new-session", "--unshare-all", "--hostname", "ops-0123456789abcdef"]);
    expect(marked.slice(5)).toEqual(args.slice(3));
    const cmd = buildRemoteCommand(marked, { timeoutMs: 4_200 });
    expect(cmd.startsWith("exec timeout -s KILL 7 bwrap '--die-with-parent' '--new-session' '--unshare-all' '--hostname' 'ops-0123456789abcdef'")).toBe(true);
    expect(cmd).toContain("'--setenv' 'A' 'x y'");
    expect(cmd.endsWith("'--' '/usr/bin/aws' 'eks' 'get-token'")).toBe(true);
    expect(() => withCallMarker(args, "kısa")).toThrow(/jeton/);
    expect(() => withCallMarker(["--clearenv"], "0123456789abcdef")).toThrow(/unshare-all/);
  });

  it("çok uzun komut reddedilir (MAX_ARG_STRLEN)", () => {
    expect(() => buildRemoteCommand(["--unshare-all", "x".repeat(200_000)], { timeoutMs: 1000 })).toThrow(/tavan/);
  });

  it("uzak kill: desen kendisiyle eşleşmez, işaretle eşleşir; sonu `exit 0`", () => {
    const k = remoteKillCommand("0123456789abcdef");
    expect(k).toBe("pkill -KILL -f -- '[o]ps-0123456789abcdef'; exit 0");
    expect(new RegExp("[o]ps-0123456789abcdef").test("bwrap --hostname ops-0123456789abcdef -- /bin/sh")).toBe(true);
    expect(new RegExp("[o]ps-0123456789abcdef").test(k)).toBe(false);
  });

  it("düzen yoklaması: tüm LAYOUT_PATHS tırnaklı sorulur; çıktı symlink/dir/file/none olarak ayrışır", () => {
    const cmd = layoutProbeCommand();
    for (const p of LAYOUT_PATHS) expect(cmd).toContain(`'${p}'`);
    const m = parseLayoutProbe("/bin\tsymlink\tusr/bin\n/etc/ssl\tdir\n/etc/hosts\tfile\n/lib64\tnone\n/etc/localtime\tsymlink\t/usr/share/zoneinfo/Etc/UTC\n");
    expect(m.get("/bin")).toEqual({ type: "symlink", target: "usr/bin" });
    expect(m.get("/etc/ssl")).toEqual({ type: "dir" });
    expect(m.get("/etc/hosts")).toEqual({ type: "file" });
    expect(m.get("/lib64")).toBeUndefined();
    expect(m.get("/etc/localtime")).toEqual({ type: "symlink", target: "/usr/share/zoneinfo/Etc/UTC" });
  });
});

describe("VM durum dosyası ve tespit", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  it("parseVmState: eksik/bozuk alan reddedilir; sondaki / atılır", () => {
    const ok = parseVmState(JSON.stringify({ ...state, shares: [{ host: "/a/b/", guest: "/a/b/", mode: "rw" }] }));
    expect(ok.shares[0]).toEqual({ host: "/a/b", guest: "/a/b", mode: "rw" });
    expect(() => parseVmState("{")).toThrow(/JSON/);
    expect(() => parseVmState(JSON.stringify({ ...state, version: 2 }))).toThrow(/version/);
    expect(() => parseVmState(JSON.stringify({ ...state, shares: [{ host: "rel", guest: "/x", mode: "rw" }] }))).toThrow(/shares/);
    expect(() => parseVmState(JSON.stringify({ ...state, shares: [{ host: "/x/../y", guest: "/x", mode: "rw" }] }))).toThrow(/shares/);
    expect(() => parseVmState(JSON.stringify({ ...state, sshConfig: "ssh_config" }))).toThrow(/sshConfig/);
    expect(() => parseVmState(JSON.stringify({ ...state, toolDirs: ["bin"] }))).toThrow(/toolDirs/);
  });

  it("loadVmState: dosya yoksa null; VmSandbox araç dizinlerini durumdan alır", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-vmstate-"));
    dirs.push(d);
    expect(await loadVmState(d)).toBeNull();
    await writeFile(join(d, "state.json"), JSON.stringify(state));
    const s = await loadVmState(d);
    expect(s?.toolDirs).toEqual(["/opt/ops-tools/bin", "/opt/ops-tools/venv/bin"]);
    const sb = new VmSandbox({ state: s! });
    expect(sb.kind).toBe("vm");
    expect(sb.toolDirs).toEqual(s!.toolDirs);
    expect(sb.fs).toBeDefined();
  });

  it("detectSandbox: VM asla başlatılmaz — durum yoksa null (nedeniyle); OPS_SANDBOX=vm erişilemezse null; OPS_SANDBOX=none/geçersiz null", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-vmdetect-"));
    dirs.push(d);
    const none = await detectSandboxDetailed({ platform: "darwin", env: {}, vmStateDir: d });
    expect(none.sandbox).toBeNull();
    expect(none.reason).toMatch(/ops vm up/);
    const forced = await detectSandboxDetailed({ platform: "linux", env: { OPS_SANDBOX: "vm" }, vmStateDir: d });
    expect(forced.sandbox).toBeNull();
    expect(forced.reason).toMatch(/VM kurulu değil/);
    // durum var ama yoklama geçmiyor (VM kapalı): null, başlatma denemesi yok
    await writeFile(join(d, "state.json"), JSON.stringify({ ...state, sshConfig: join(d, "ssh_config") }));
    const down = await detectSandboxDetailed({ platform: "darwin", env: {}, vmStateDir: d, probe: async () => false });
    expect(down.sandbox).toBeNull();
    expect(down.reason).toMatch(/erişilemiyor/);
    const up = await detectSandboxDetailed({ platform: "darwin", env: {}, vmStateDir: d, probe: async () => true });
    expect(up.sandbox?.kind).toBe("vm");
    expect(await detectSandbox({ platform: "linux", env: { OPS_SANDBOX: "none" }, vmStateDir: d })).toBeNull();
    // OPS_VM_DIR verilen dizini geçersiz kılar (ayrı OPS_HOME'lu testler gerçek VM'i bulur)
    const viaEnv = await detectSandboxDetailed({ platform: "darwin", env: { OPS_VM_DIR: d }, vmStateDir: "/yok", probe: async () => true });
    expect(viaEnv.sandbox?.kind).toBe("vm");
    expect((await detectSandboxDetailed({ platform: "linux", env: { OPS_SANDBOX: "seatbelt" }, vmStateDir: d })).reason).toMatch(/geçersiz/);
  });

  it("gerçek ssh ile erişilemeyen VM: run anlamlı hata verir (ssh_config yok)", async () => {
    const d = await mkdtemp(join(tmpdir(), "ops-vmdown-"));
    dirs.push(d);
    const sb = new VmSandbox({ state: { ...state, sshConfig: join(d, "ssh_config") } });
    await expect(sb.run(base)).rejects.toThrow(/VM'e erişilemedi/);
    const p = await sb.probe(5_000);
    expect(p.ok).toBe(false);
  });
});
