import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { EncryptedFileStore } from "@ops/broker";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseDurationSec, reauthVaultPassphrase } from "../src/reauth.ts";
import type { TtyIo } from "../src/approval.ts";

/** Yanıtları sırayla yazan sahte kontrol terminali (istem çıktısını izler). */
function fakeTty(answers: string[]): { open: () => Promise<TtyIo>; shown: () => string } {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  let i = 0;
  output.on("data", (b: Buffer) => {
    chunks.push(b.toString());
    if (/: $/.test(chunks.join("").slice(-12))) {
      const a = answers[i++];
      if (a !== undefined) setTimeout(() => input.write(`${a}\n`), 0);
    }
  });
  return { open: async () => ({ input, output }), shown: () => chunks.join("") };
}

describe("yeniden kimlik doğrulama (break-glass)", () => {
  const verifyWith = (good: string) => async (p: Uint8Array) => Buffer.from(p).toString("utf8") === good;
  const noSleep = async () => undefined;

  it("doğru parola → {yöntem, zaman} kanıtı; parola çıktıya yazılmaz", async () => {
    const t = fakeTty(["dogru-parola"]);
    const now = new Date("2026-10-24T10:00:00Z");
    const proof = await reauthVaultPassphrase({ openTty: t.open, vaultFile: "/yok", verify: verifyWith("dogru-parola"), now: () => now, sleep: noSleep });
    expect(proof).toEqual({ method: "vault-passphrase", verifiedAt: now });
    expect(t.shown()).not.toContain("dogru-parola");
  });

  it("yanlış parola 3 denemeden sonra başarısız (break_glass_reauth); doğru parola 2. denemede kabul", async () => {
    const bad = fakeTty(["a", "b", "c"]);
    await expect(reauthVaultPassphrase({ openTty: bad.open, vaultFile: "/yok", verify: verifyWith("x"), sleep: noSleep })).rejects.toMatchObject({ code: "break_glass_reauth" });
    expect(bad.shown().match(/Parola yanlış/g)).toHaveLength(3);
    const ok = fakeTty(["yanlis", "dogru"]);
    await expect(reauthVaultPassphrase({ openTty: ok.open, vaultFile: "/yok", verify: verifyWith("dogru"), sleep: noSleep })).resolves.toMatchObject({ method: "vault-passphrase" });
  });

  it("kontrol terminali yoksa REDDEDİLİR (fail-closed); ortam değişkeni/dosyası kabul EDİLMEZ", async () => {
    process.env["OPS_PASSPHRASE_FILE"] = "/tmp/yok-ama-var-sayilir";
    try {
      await expect(reauthVaultPassphrase({ openTty: async () => null, vaultFile: "/yok", verify: async () => true })).rejects.toMatchObject({ code: "break_glass_reauth" });
    } finally {
      delete process.env["OPS_PASSPHRASE_FILE"];
    }
  });

  it("gerçek kasa dosyasına karşı doğrular (yanlış/yok/bozuk → false; durum değiştirmez)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ops-vault-"));
    try {
      const file = join(dir, "vault.json");
      const store = await EncryptedFileStore.open(file, async () => new Uint8Array(Buffer.from("kasa-parolasi")), { kdf: { N: 1 << 10, r: 8, p: 1 } });
      store.close();
      expect(await EncryptedFileStore.verify(file, new Uint8Array(Buffer.from("kasa-parolasi")))).toBe(true);
      expect(await EncryptedFileStore.verify(file, new Uint8Array(Buffer.from("yanlis")))).toBe(false);
      expect(await EncryptedFileStore.verify(join(dir, "yok.json"), new Uint8Array(Buffer.from("x")))).toBe(false);
      const t = fakeTty(["kasa-parolasi"]);
      await expect(reauthVaultPassphrase({ openTty: t.open, vaultFile: file, sleep: noSleep })).resolves.toMatchObject({ method: "vault-passphrase" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("parseDurationSec", () => {
    expect(parseDurationSec("30m")).toBe(1800);
    expect(parseDurationSec("90s")).toBe(90);
    expect(parseDurationSec("1h")).toBe(3600);
    expect(parseDurationSec("45")).toBe(45);
    for (const bad of ["", "m", "-5m", "1d", "abc", "1.5h", "30 dakika"]) expect(() => parseDurationSec(bad), bad).toThrow();
  });
});
