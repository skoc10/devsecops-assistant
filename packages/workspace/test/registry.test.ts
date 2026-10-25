import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";
import { WorkspaceRegistry } from "../src/index.ts";

describe("WorkspaceRegistry kalıcılığı", () => {
  let repo: TestRepo;
  let home = "";
  beforeAll(async () => {
    repo = await makeRepo();
    home = await mkdtemp(join(tmpdir(), "ops-wsreg-"));
  });
  afterAll(async () => {
    await repo.cleanup();
    await rm(home, { recursive: true, force: true });
  });

  it("geçici dosya yoluna önceden dikilmiş symlink izlenmez: hedef değişmez, kayıt normal dosya olur", async () => {
    const file = join(home, "workspaces.json");
    const victim = join(home, "kurban.txt");
    await writeFile(victim, "dokunulmamalı\n");
    await symlink(victim, `${file}.${process.pid}.tmp`);
    const reg = await WorkspaceRegistry.open(file);
    await reg.add({ id: "infra", path: repo.dir, engine: "opentofu" });
    expect(await readFile(victim, "utf8")).toBe("dokunulmamalı\n");
    const st = await lstat(file);
    expect(st.isFile()).toBe(true);
    expect(st.mode & 0o777).toBe(0o600);
    expect((await WorkspaceRegistry.open(file)).get("infra")?.engine).toBe("opentofu");
  });
});
