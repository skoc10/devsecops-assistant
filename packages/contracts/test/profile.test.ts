import { describe, expect, it } from "vitest";
import { ProfileSchema, scopeAllows, TargetSchema, estimateTokens } from "../src/index.ts";

const valid = {
  id: "prod-eu",
  kind: "k8s",
  displayName: "Prod EU",
  environment: "prod",
  targetPin: { endpoint: "https://k8s.example.invalid:6443" },
  classCeiling: "read",
  allowedScopes: ["payments"],
  credentialSource: { kind: "static" },
  egressClass: "tenant-cloud",
};

describe("ProfileSchema", () => {
  it("geçerli profili kabul eder ve varsayılanları doldurur", () => {
    const p = ProfileSchema.parse(valid);
    expect(p.maxLeaseTtlSec).toBe(120);
    expect(p.attributes).toEqual({});
    expect(p.credentialSource.ambientDependencies).toEqual([]);
  });

  it("secret taşıyabilecek bilinmeyen alanı reddeder", () => {
    expect(ProfileSchema.safeParse({ ...valid, kubeconfig: "..." }).success).toBe(false);
    expect(ProfileSchema.safeParse({ ...valid, token: "..." }).success).toBe(false);
    expect(
      ProfileSchema.safeParse({ ...valid, credentialSource: { kind: "static", password: "x" } }).success,
    ).toBe(false);
  });

  it("boş allowedScopes'u reddeder (karar açık olmalı)", () => {
    expect(ProfileSchema.safeParse({ ...valid, allowedScopes: [] }).success).toBe(false);
  });

  it("egressClass zorunlu (güvensiz varsayılan yok)", () => {
    const { egressClass: _drop, ...rest } = valid;
    expect(ProfileSchema.safeParse(rest).success).toBe(false);
  });

  it("geçersiz kimlikleri reddeder", () => {
    expect(ProfileSchema.safeParse({ ...valid, id: "Prod EU" }).success).toBe(false);
    expect(ProfileSchema.safeParse({ ...valid, id: "../etc" }).success).toBe(false);
  });

  it("CA parmak izi 64 hane küçük harf hex olmalı", () => {
    const pin = { endpoint: "https://x.invalid", caFingerprint: "ZZ" };
    expect(ProfileSchema.safeParse({ ...valid, targetPin: pin }).success).toBe(false);
    const ok = { endpoint: "https://x.invalid", caFingerprint: "a".repeat(64) };
    expect(ProfileSchema.safeParse({ ...valid, targetPin: ok }).success).toBe(true);
  });
});

describe("scopeAllows: sahip/* kalıbı", () => {
  it("yalnız tek düzey altını kapsar; iç içe ve benzer önek kapsanmaz", () => {
    expect(scopeAllows(["acme/*"], "acme/payments")).toBe(true);
    expect(scopeAllows(["acme/*"], "acme/a/b")).toBe(false);
    expect(scopeAllows(["acme/*"], "acme-evil/payments")).toBe(false);
    expect(scopeAllows(["acme/*"], "acme/")).toBe(false);
    expect(scopeAllows(["acme/*"], "acme")).toBe(false);
    expect(scopeAllows(["acme/payments"], "acme/billing")).toBe(false);
    expect(scopeAllows(["*/*"], "acme/payments")).toBe(false);
    expect(scopeAllows(["a*/*"], "ab/c")).toBe(false);
  });
});

describe("scopeAllows", () => {
  it("* hepsini kapsar, yoksa tam eşleşme", () => {
    expect(scopeAllows(["*"], "anything")).toBe(true);
    expect(scopeAllows(["payments"], "payments")).toBe(true);
    expect(scopeAllows(["payments"], "payments-2")).toBe(false);
  });
});

describe("TargetSchema", () => {
  it("katı: fazladan alan yok", () => {
    const t = { profileId: "p", kind: "k8s", endpoint: "https://x.invalid", scopes: [], refs: [] };
    expect(TargetSchema.safeParse(t).success).toBe(true);
    expect(TargetSchema.safeParse({ ...t, server: "x" }).success).toBe(false);
  });
});

describe("estimateTokens", () => {
  it("boş metin 0; uzunlukla monoton artar", () => {
    expect(estimateTokens("")).toBe(0);
    expect(estimateTokens("a".repeat(100))).toBeGreaterThan(estimateTokens("a".repeat(10)));
  });
});
