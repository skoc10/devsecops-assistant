import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { WorkspaceRegistry } from "@ops/workspace";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";
import { resolvePaths } from "../src/paths.ts";
import { computeShares, parseSshConfig, renderSshConfig, workspaceShareStatus } from "../src/vm.ts";

const gitInit = (dir: string): void => {
  execFileSync("git", ["init", "-q", dir]);
};
// Test depoları geçici dizindedir; gerçek kural (`roBindProblem`) /var/folders gibi çalışma zamanı dizinlerini haklı olarak
// reddeder. Yapısal testler kuralı gevşetir; kuralın kendisi ayrı testte varsayılanla sınanır.
const permissive = (): null => null;

describe("ops vm: paylaşım listesi (ADR-0011 §5/§7)", () => {
  const dirs: string[] = [];
  const repos: TestRepo[] = [];
  afterAll(async () => {
    for (const r of repos) await r.cleanup();
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  const fresh = async () => {
    const root = await mkdtemp(join(tmpdir(), "ops-vmcli-"));
    dirs.push(root);
    const paths = resolvePaths(join(root, "ops"));
    await mkdir(paths.home, { recursive: true, mode: 0o700 });
    const fakeHome = join(root, "home");
    await mkdir(fakeHome, { recursive: true });
    return { root, paths, fakeHome, registry: await WorkspaceRegistry.open(paths.workspacesFile) };
  };

  it("yalnız anlık kopya kökü (rw) + kayıtlı depoların GERÇEK yolu (ro); sembolik bağla kayıt gerçek yola çözülür", async () => {
    const { root, paths, fakeHome, registry } = await fresh();
    const repo = await makeRepo();
    repos.push(repo);
    const link = join(root, "repo-link");
    await symlink(repo.dir, link);
    await registry.add({ id: "infra", path: link, engine: "opentofu" }, { home: fakeHome });
    const shares = await computeShares(paths, { HOME: fakeHome }, permissive);
    const real = await realpath(repo.dir);
    expect(shares).toEqual([
      { host: await realpath(paths.worktreesDir), guest: await realpath(paths.worktreesDir), mode: "rw" },
      { host: real, guest: real, mode: "ro" },
    ]);
    // durum raporu: paylaşılan ✓, paylaşılmayan ✗ (iac.* fail-closed)
    const state = { shares, toolDirs: [], guestRoots: [], version: 1 as const, box: "b", boxVersion: "v", provider: "p", sshConfig: "/x/ssh_config", createdAt: "t" };
    expect((await workspaceShareStatus(paths, state)).join("\n")).toMatch(/✓ infra/);
    expect((await workspaceShareStatus(paths, { ...state, shares: shares.slice(0, 1) })).join("\n")).toMatch(/✗ infra.*workspace_not_shared.*ops vm reload/);
  });

  it("paylaşılmayacak yerdeki kayıt (kimlik dizini, geçici dizin) ve var olmayan yol: sessizce daraltılmaz, REDDEDİLİR", async () => {
    const { paths, fakeHome, registry } = await fresh();
    const sshRepo = join(fakeHome, ".ssh", "repo");
    await mkdir(sshRepo, { recursive: true });
    gitInit(sshRepo);
    await registry.add({ id: "bad", path: sshRepo, engine: "ansible" }, { home: fakeHome });
    // varsayılan kural: `.ssh` kimlik konumu — ve zaten geçici dizin altında (çalışma zamanı konumu)
    await expect(computeShares(paths, { HOME: fakeHome })).rejects.toMatchObject({ code: "vm_share_refused", message: expect.stringMatching(/kimlik|secret|çalışma zamanı/) });
    await registry.remove("bad");

    const gone = await makeRepo();
    await registry.add({ id: "gone", path: gone.dir, engine: "opentofu" }, { home: fakeHome });
    await gone.cleanup();
    await expect(computeShares(paths, { HOME: fakeHome }, permissive)).rejects.toMatchObject({ code: "vm_share_refused", message: expect.stringMatching(/yolu yok/) });
  });

  it("iç içe paylaşımlar reddedilir (üst dizin asla paylaşılmaz)", async () => {
    const { paths, fakeHome, registry } = await fresh();
    const outer = await makeRepo();
    repos.push(outer);
    const inner = join(outer.dir, "sub");
    await mkdir(inner);
    gitInit(inner);
    await registry.add({ id: "outer", path: outer.dir, engine: "opentofu" }, { home: fakeHome });
    await registry.add({ id: "inner", path: inner, engine: "opentofu" }, { home: fakeHome });
    await expect(computeShares(paths, { HOME: fakeHome }, permissive)).rejects.toMatchObject({ code: "vm_share_refused", message: expect.stringMatching(/iç içe/) });
  });
});

describe("ops vm: ssh yapılandırması", () => {
  it("vagrant ssh-config ayrıştırılır; üretilen yapılandırma sabit sunucu anahtarı, yalnız anahtar kimliği, iletim yok", () => {
    const info = parseSshConfig("Host default\n  HostName 127.0.0.1\n  User vagrant\n  Port 2250\n  UserKnownHostsFile /dev/null\n  StrictHostKeyChecking no\n  IdentityFile /x/.vagrant/machines/default/vmware_desktop/private_key\n  IdentitiesOnly yes\n");
    expect(info).toEqual({ hostName: "127.0.0.1", port: "2250", user: "vagrant", identityFile: "/x/.vagrant/machines/default/vmware_desktop/private_key" });
    const cfg = renderSshConfig(info, "/h/vm/known_hosts", "/h/run/vm.sock");
    expect(cfg).toContain("StrictHostKeyChecking yes");
    expect(cfg).toContain("UserKnownHostsFile /h/vm/known_hosts");
    expect(cfg).toContain("IdentitiesOnly yes");
    expect(cfg).toContain("ForwardAgent no");
    expect(cfg).toContain("ClearAllForwardings yes");
    expect(cfg).toContain("ControlPath /h/run/vm.sock");
    expect(cfg).not.toContain("StrictHostKeyChecking no");
    expect(() => parseSshConfig("Host default\n  HostName 127.0.0.1\n")).toThrow(/eksik/);
    expect(() => parseSshConfig("Host default\n  HostName 127.0.0.1\n  User vagrant\n  Port 2250\n  IdentityFile key\n")).toThrow(/beklenmedik/);
  });
});
