import { lstat, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { detectSandbox } from "@ops/sandbox";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";
import { WorkspaceManager, WorkspaceRegistry, loadSnapshot } from "../src/index.ts";

const sandbox = await detectSandbox();

describe.skipIf(!sandbox)("WorkspaceManager: kalıcı anlık kopyalar (gerçek git + gerçek bubblewrap)", () => {
  let repo: TestRepo;
  let home = "";
  let manager: WorkspaceManager;
  beforeAll(async () => {
    repo = await makeRepo();
    home = await mkdtemp(join(tmpdir(), "ops-mgr-"));
    const reg = await WorkspaceRegistry.open(join(home, "workspaces.json"));
    await reg.add({ id: "infra", path: repo.dir, engine: "opentofu", denyPaths: ["modules/vpc/**"] });
    manager = new WorkspaceManager({ registry: reg, worktreesDir: join(home, "worktrees"), sandbox });
  });
  afterAll(async () => {
    await repo.cleanup();
    await rm(home, { recursive: true, force: true });
  });

  it("activate sonrası snapshots() oturumu listeler; openSnapshot() farkı kalıcı kopyadan verir (sandbox gerekmez)", async () => {
    const a = await manager.activate("infra", "sess-a");
    await a.fs.write("new.tf", 'output "x" {\n  value = 1\n}\n');
    manager.deactivate();
    const list = await manager.snapshots("infra");
    expect(list.map((s) => [s.workspaceId, s.sessionId])).toEqual([["infra", "sess-a"]]);
    expect(list[0]?.head).toMatch(/^[0-9a-f]{40,64}$/);

    const offline = new WorkspaceManager({ registry: await WorkspaceRegistry.open(join(home, "workspaces.json")), worktreesDir: join(home, "worktrees"), sandbox: null });
    const { fs, info } = await offline.openSnapshot("infra");
    expect(info.sessionId).toBe("sess-a");
    const ch = await fs.changes();
    expect(ch.changes.map((c) => [c.path, c.status])).toEqual([["new.tf", "added"]]);
    expect(ch.patch).toContain("+++ b/new.tf");
    // kayıt politikası yeniden uygulanır: denyPaths'taki dosya fark/okuma dışı
    await expect(fs.read("modules/vpc/main.tf")).rejects.toThrow(/denyPaths|reddedildi/);
  });

  it("en yeni oturum varsayılan; --session ile seçilir; bilinmeyen oturum/alan açık hata", async () => {
    await new Promise((r) => setTimeout(r, 20));
    await manager.activate("infra", "sess-b");
    manager.deactivate();
    const all = await manager.snapshots("infra");
    expect(all.map((s) => s.sessionId)).toEqual(["sess-b", "sess-a"]);
    expect((await manager.openSnapshot("infra")).info.sessionId).toBe("sess-b");
    expect((await manager.openSnapshot("infra", "sess-a")).info.sessionId).toBe("sess-a");
    await expect(manager.openSnapshot("infra", "yok")).rejects.toMatchObject({ code: "snapshot_not_found" });
    await expect(manager.openSnapshot("nope")).rejects.toMatchObject({ code: "workspace_not_found" });
    expect(await manager.snapshots("baska")).toEqual([]);
  });

  it("yabancı / bozuk / sembolik dizinler listeye ALINMAZ", async () => {
    const wt = join(home, "worktrees");
    // 1) ad kalıbına uymayan
    await mkdir(join(wt, "rastgele dizin"), { recursive: true });
    // 2) kalıba uyan ama workspace.json'u tutarsız (başka alan kimliği)
    await mkdir(join(wt, "evil--infra", "work"), { recursive: true });
    await mkdir(join(wt, "evil--infra", "base"), { recursive: true });
    await writeFile(join(wt, "evil--infra", "workspace.json"), JSON.stringify({ id: "baska", sessionId: "evil", head: "a".repeat(40) }));
    await writeFile(join(wt, "evil--infra", "manifest.json"), JSON.stringify({ version: 1, head: "a".repeat(40), createdAt: "2099-01-01T00:00:00Z", files: {}, skipped: [] }));
    // 3) sembolik bağ ile başka bir anlık kopyaya yönlendirme
    await symlink(join(wt, "sess-a--infra"), join(wt, "link--infra"));
    // 4) manifest'i bozuk
    await mkdir(join(wt, "broken--infra", "work"), { recursive: true });
    await mkdir(join(wt, "broken--infra", "base"), { recursive: true });
    await writeFile(join(wt, "broken--infra", "workspace.json"), JSON.stringify({ id: "infra", sessionId: "broken", head: "a".repeat(40) }));
    await writeFile(join(wt, "broken--infra", "manifest.json"), "{not json");
    const ids = (await manager.snapshots("infra")).map((s) => s.sessionId).sort();
    expect(ids).toEqual(["sess-a", "sess-b"]);
    expect((await lstat(join(wt, "link--infra"))).isSymbolicLink()).toBe(true);
  });

  it("loadSnapshot: eksik dizin / sembolik work dizini / geçersiz manifest reddedilir", async () => {
    await expect(loadSnapshot(join(home, "yok"))).rejects.toMatchObject({ code: "snapshot_invalid" });
    const d = await mkdtemp(join(tmpdir(), "ops-ls-"));
    try {
      await mkdir(join(d, "base"));
      await mkdir(join(d, "real-work"));
      await symlink(join(d, "real-work"), join(d, "work"));
      await writeFile(join(d, "manifest.json"), JSON.stringify({ version: 1, head: "b".repeat(40), createdAt: "x", files: {}, skipped: [] }));
      await expect(loadSnapshot(d)).rejects.toMatchObject({ code: "snapshot_invalid" });
    } finally {
      await rm(d, { recursive: true, force: true });
    }
  });
});
