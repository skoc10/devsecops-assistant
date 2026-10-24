import { stat } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { createTestHome, makeTestProfile, verifyFixtureSignature } from "../src/index.ts";

describe("sahte profiller", () => {
  it("imzalıdır ve .invalid uç noktası kullanır", () => {
    const p = makeTestProfile();
    expect(p.testFixtureSig).toBeTruthy();
    expect(verifyFixtureSignature(p)).toBe(true);
    expect(new URL(p.targetPin.endpoint).hostname.endsWith(".invalid")).toBe(true);
  });

  it("alan değişirse imza geçersiz olur (prod'a çevrilemez)", () => {
    const p = makeTestProfile();
    expect(verifyFixtureSignature({ ...p, environment: "prod" })).toBe(false);
    expect(verifyFixtureSignature({ ...p, targetPin: { endpoint: "https://real.example:6443" } })).toBe(false);
  });

  it("imzasız profil geçersiz", () => {
    const { testFixtureSig: _s, ...rest } = makeTestProfile();
    expect(verifyFixtureSignature(rest as never)).toBe(false);
  });

  it("izole OPS_HOME 0700 ile oluşur ve temizlenir", async () => {
    const home = await createTestHome();
    const s = await stat(home.path);
    expect(s.mode & 0o777).toBe(0o700);
    await home.cleanup();
    await expect(stat(home.path)).rejects.toThrow();
  });
});
