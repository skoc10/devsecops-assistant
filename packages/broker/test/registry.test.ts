import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeTestProfile, verifyFixtureSignature } from "@ops/testkit";
import { ProfileRegistry } from "../src/index.ts";

describe("ProfileRegistry", () => {
  let dir: string;
  let path: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-reg-"));
    path = join(dir, "profiles.json");
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const open = (extra: Partial<Parameters<typeof ProfileRegistry.open>[0]> = {}) =>
    ProfileRegistry.open({ path, testMode: false, ...extra });

  it("ekle/oku/sil, 0600 ve yeniden açınca kalıcı", async () => {
    const r = await open();
    await r.add(makeTestProfile({ id: "a" }));
    await r.add(makeTestProfile({ id: "b" }));
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await open()).list().map((p) => p.id)).toEqual(["a", "b"]);
    expect(await r.remove("a")).toBe(true);
    expect(await r.remove("a")).toBe(false);
    expect((await open()).list().map((p) => p.id)).toEqual(["b"]);
  });

  it("aynı kimlik replace olmadan eklenemez", async () => {
    const r = await open();
    await r.add(makeTestProfile({ id: "a" }));
    await expect(r.add(makeTestProfile({ id: "a" }))).rejects.toMatchObject({ code: "profile_exists" });
    await r.add(makeTestProfile({ id: "a", displayName: "yeni" }), { replace: true });
    expect(r.get("a")?.displayName).toBe("yeni");
  });

  it("bozuk dosya veya geçersiz profil profiles_corrupt", async () => {
    await writeFile(path, "{");
    await expect(open()).rejects.toMatchObject({ code: "profiles_corrupt" });
    await writeFile(path, JSON.stringify({ version: 1, profiles: [{ id: "x", token: "gizli" }] }));
    await expect(open()).rejects.toMatchObject({ code: "profiles_corrupt" });
  });

  it("secret taşıyan alanlı profil kaydedilemez (şema katı)", async () => {
    const r = await open();
    const bad = { ...makeTestProfile({ id: "a" }), kubeconfig: "gizli" } as never;
    await expect(r.add(bad)).rejects.toThrow();
  });

  it("test kipinde admit zorunlu; imzasız ve prod profil reddedilir; imzalı kabul edilir", async () => {
    await expect(ProfileRegistry.open({ path, testMode: true })).rejects.toMatchObject({ code: "test_mode_admit_required" });
    const r = await ProfileRegistry.open({ path, testMode: true, admit: (p) => (verifyFixtureSignature(p) ? true : "imza geçersiz") });
    await r.add(makeTestProfile({ id: "ok" }));
    const unsigned = { ...makeTestProfile({ id: "bad" }), testFixtureSig: undefined };
    await expect(r.add(unsigned)).rejects.toMatchObject({ code: "test_mode_profile_refused" });
    const prod = makeTestProfile({ id: "prod", environment: "prod" });
    await expect(r.add(prod)).rejects.toMatchObject({ code: "test_mode_prod_refused" });
    expect(r.list().map((p) => p.id)).toEqual(["ok"]);
  });

  it("test kipinde diske sonradan eklenmiş imzasız profil yüklenmez", async () => {
    const plain = await open();
    await plain.add({ ...makeTestProfile({ id: "sizdi" }), testFixtureSig: undefined });
    await expect(ProfileRegistry.open({ path, testMode: true, admit: (p) => (verifyFixtureSignature(p) ? true : "imza geçersiz") })).rejects.toMatchObject({
      code: "test_mode_profile_refused",
    });
  });

  it("OPS_TEST_MODE=1 ortam değişkeni test kipini açar", async () => {
    process.env["OPS_TEST_MODE"] = "1";
    try {
      await expect(ProfileRegistry.open({ path })).rejects.toMatchObject({ code: "test_mode_admit_required" });
    } finally {
      delete process.env["OPS_TEST_MODE"];
    }
    expect(JSON.parse(await readFile(path, "utf8").catch(() => "{}"))).toBeDefined();
  });
});
