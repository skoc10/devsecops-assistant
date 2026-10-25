import { lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canaryVariants, makeCanary } from "@ops/testkit";
import {
  EncryptedFileStore,
  MacSecurityBackend,
  MemorySecretStore,
  OsKeychainStore,
  SecretToolBackend,
} from "../src/index.ts";
import type { Exec } from "../src/index.ts";

const FAST = { kdf: { N: 1 << 10, r: 8, p: 1 } };
const pass = (s: string) => async (): Promise<Uint8Array> => new TextEncoder().encode(s);

describe("EncryptedFileStore", () => {
  let dir: string;
  let path: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-vault-"));
    path = join(dir, "vault", "vault.json");
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("değerler diskte düz metin/kodlu hiçbir biçimde bulunmaz; yeniden açınca okunur", async () => {
    const c = makeCanary("kubeconfig-token");
    const s = await EncryptedFileStore.open(path, pass("parola-1"), FAST);
    await s.set("profile/a/credential", new TextEncoder().encode(c.value));
    const onDisk = await readFile(path, "utf8");
    for (const v of canaryVariants(c)) expect(onDisk.includes(v.needle), v.name).toBe(false);

    const again = await EncryptedFileStore.open(path, pass("parola-1"), FAST);
    expect(new TextDecoder().decode((await again.get("profile/a/credential"))!)).toBe(c.value);
    expect(await again.get("yok")).toBeNull();
  });

  it("dosya 0600, dizin 0700", async () => {
    await EncryptedFileStore.open(path, pass("p"), FAST);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, "vault"))).mode & 0o777).toBe(0o700);
  });

  it("R-V2: önceden dikilmiş vault.json.tmp symlink'i izlenmez (yazım hedefe gitmez, symlink kasa olmaz)", async () => {
    await mkdir(join(dir, "vault"), { recursive: true });
    const victim = join(dir, "kurban.txt");
    await writeFile(victim, "dokunulmamali");
    await symlink(victim, `${path}.tmp`);
    const s = await EncryptedFileStore.open(path, pass("p"), FAST);
    await s.set("a", new TextEncoder().encode("deger-12345"));
    expect(await readFile(victim, "utf8")).toBe("dokunulmamali");
    const st = await lstat(path);
    expect(st.isSymbolicLink()).toBe(false);
    expect(st.isFile()).toBe(true);
    expect(st.mode & 0o777).toBe(0o600);
    // sarkan (hedefi olmayan) symlink: hedef oluşturulmaz
    await symlink(join(dir, "yok.txt"), `${path}.tmp`);
    await s.set("b", new Uint8Array([1]));
    await expect(stat(join(dir, "yok.txt"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await lstat(path)).isSymbolicLink()).toBe(false);
    const again = await EncryptedFileStore.open(path, pass("p"), FAST);
    expect(new TextDecoder().decode((await again.get("a"))!)).toBe("deger-12345");
    expect(await again.list("")).toEqual(["a", "b"]);
  });

  it("yanlış parola vault_locked verir ve hiçbir şey okutmaz", async () => {
    const s = await EncryptedFileStore.open(path, pass("dogru"), FAST);
    await s.set("a", new Uint8Array([1, 2, 3]));
    await expect(EncryptedFileStore.open(path, pass("yanlis"), FAST)).rejects.toMatchObject({ code: "vault_locked" });
  });

  it("şifreli blok kurcalanırsa vault_corrupt (düz metin dönmez)", async () => {
    const s = await EncryptedFileStore.open(path, pass("p"), FAST);
    await s.set("a", new TextEncoder().encode("gizli-deger-12345"));
    const j = JSON.parse(await readFile(path, "utf8")) as { entries: Record<string, { ct: string }> };
    const ct = Buffer.from(j.entries["a"]!.ct, "base64");
    ct[0] = (ct[0] ?? 0) ^ 0xff;
    j.entries["a"]!.ct = ct.toString("base64");
    await writeFile(path, JSON.stringify(j));
    const reopened = await EncryptedFileStore.open(path, pass("p"), FAST);
    await expect(reopened.get("a")).rejects.toMatchObject({ code: "vault_corrupt" });
  });

  it("şifreli blok başka bir girdi adına taşınamaz (AAD bağı)", async () => {
    const s = await EncryptedFileStore.open(path, pass("p"), FAST);
    await s.set("profile/a/credential", new TextEncoder().encode("a-icin-gizli-deger"));
    await s.set("profile/b/credential", new TextEncoder().encode("b-icin-gizli-deger"));
    const j = JSON.parse(await readFile(path, "utf8")) as { entries: Record<string, unknown> };
    j.entries["profile/b/credential"] = j.entries["profile/a/credential"];
    await writeFile(path, JSON.stringify(j));
    const reopened = await EncryptedFileStore.open(path, pass("p"), FAST);
    await expect(reopened.get("profile/b/credential")).rejects.toMatchObject({ code: "vault_corrupt" });
  });

  it("list/delete; eşzamanlı yazımlar kaybolmaz", async () => {
    const s = await EncryptedFileStore.open(path, pass("p"), FAST);
    await Promise.all(Array.from({ length: 20 }, (_, i) => s.set(`profile/p${i}/credential`, new Uint8Array([i]))));
    expect((await s.list("profile/")).length).toBe(20);
    expect(await s.delete("profile/p3/credential")).toBe(true);
    expect(await s.delete("profile/p3/credential")).toBe(false);
    const again = await EncryptedFileStore.open(path, pass("p"), FAST);
    expect((await again.list("profile/")).length).toBe(19);
  });

  it("close() sonrası işlem vault_locked", async () => {
    const s = await EncryptedFileStore.open(path, pass("p"), FAST);
    await s.set("a", new Uint8Array([1]));
    s.close();
    await expect(s.get("a")).rejects.toMatchObject({ code: "vault_locked" });
  });

  it("parola tamponu kullanımdan sonra sıfırlanır", async () => {
    let buf: Uint8Array | null = null;
    await EncryptedFileStore.open(path, async () => (buf = new TextEncoder().encode("sifirlanacak")), FAST);
    expect([...buf!].every((b) => b === 0)).toBe(true);
  });

  it("bozuk dosya vault_corrupt", async () => {
    await writeFile(path.replace("vault.json", "bozuk.json"), "{", { flag: "w" }).catch(() => undefined);
    const bad = join(dir, "bozuk.json");
    await writeFile(bad, "{");
    await expect(EncryptedFileStore.open(bad, pass("p"), FAST)).rejects.toMatchObject({ code: "vault_corrupt" });
  });
});

describe("MemorySecretStore", () => {
  it("kopya döndürür, silince sıfırlar", async () => {
    const m = new MemorySecretStore();
    const v = new Uint8Array([1, 2, 3]);
    await m.set("a", v);
    v.fill(9);
    expect([...(await m.get("a"))!]).toEqual([1, 2, 3]);
    expect(await m.list("a")).toEqual(["a"]);
    expect(await m.delete("a")).toBe(true);
    expect(await m.get("a")).toBeNull();
  });
});

describe("OS anahtar zinciri arka uçları (komut kurucu; gerçek anahtar zinciri bu ortamda yok)", () => {
  function recorder(handler: (cmd: string, args: string[], stdin?: Buffer) => { code: number; stdout?: string } = () => ({ code: 0 })) {
    const calls: { cmd: string; args: string[]; stdin?: Buffer }[] = [];
    const exec: Exec = async (cmd, args, stdin) => {
      calls.push({ cmd, args, ...(stdin ? { stdin } : {}) });
      const r = handler(cmd, args, stdin);
      return { code: r.code, stdout: Buffer.from(r.stdout ?? ""), stderr: "" };
    };
    return { calls, exec };
  }

  it("secret-tool: değer argv'de DEĞİL stdin'de (base64) taşınır", async () => {
    const { calls, exec } = recorder();
    const store = new OsKeychainStore(new SecretToolBackend(exec));
    const c = makeCanary("kc");
    await store.set("profile/a/credential", new TextEncoder().encode(c.value));
    const setCall = calls.find((x) => x.args[0] === "store")!;
    expect(setCall.args.join(" ")).not.toContain(c.value);
    expect(setCall.args.join(" ")).not.toContain(Buffer.from(c.value).toString("base64"));
    expect(setCall.stdin?.toString()).toBe(Buffer.from(c.value).toString("base64"));
    expect(setCall.args).toEqual(expect.arrayContaining(["service", "ops-assistant", "account", "profile/a/credential"]));
  });

  it("get taşınan base64'ü çözer; yok/hata null; dizin list'i besler", async () => {
    const mem = new Map<string, string>();
    const { exec } = recorder((_cmd, args, stdin) => {
      const acct = args[args.indexOf("account") + 1]!;
      if (args[0] === "store") { mem.set(acct, stdin!.toString()); return { code: 0 }; }
      if (args[0] === "lookup") return mem.has(acct) ? { code: 0, stdout: mem.get(acct)! } : { code: 1 };
      if (args[0] === "clear") return { code: mem.delete(acct) ? 0 : 1 };
      return { code: 0 };
    });
    const store = new OsKeychainStore(new SecretToolBackend(exec));
    await store.set("profile/a/credential", new TextEncoder().encode("deger-1"));
    await store.set("profile/b/credential", new TextEncoder().encode("deger-2"));
    expect(new TextDecoder().decode((await store.get("profile/a/credential"))!)).toBe("deger-1");
    expect(await store.get("profile/yok/credential")).toBeNull();
    expect(await store.list("profile/")).toEqual(["profile/a/credential", "profile/b/credential"]);
    await store.delete("profile/a/credential");
    expect(await store.list("profile/")).toEqual(["profile/b/credential"]);
  });

  it("yazma başarısız olursa keychain_error (secret mesajda yok)", async () => {
    const { exec } = recorder(() => ({ code: 1 }));
    const store = new OsKeychainStore(new SecretToolBackend(exec));
    const err = await store.set("a", new TextEncoder().encode("cok-gizli-deger")).catch((e: Error) => e);
    expect(err).toMatchObject({ code: "keychain_error" });
    expect(String((err as Error).message)).not.toContain("cok-gizli-deger");
  });

  it("macOS arka ucu security komutlarını kurar", async () => {
    const { calls, exec } = recorder();
    const b = new MacSecurityBackend(exec);
    await b.set("svc", "acct", Buffer.from("x"));
    await b.get("svc", "acct");
    await b.delete("svc", "acct");
    expect(calls.map((c) => c.args[0])).toEqual(["add-generic-password", "find-generic-password", "delete-generic-password"]);
    expect(await new SecretToolBackend(async () => { throw new Error("yok"); }).available()).toBe(false);
  });
});
