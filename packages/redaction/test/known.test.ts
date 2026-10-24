import { describe, expect, it } from "vitest";
import { Counter, KnownSecrets, MIN_KNOWN_SECRET_BYTES, secretNeedles } from "../src/index.ts";
import { canaryVariants, makeCanary } from "@ops/testkit";

describe("M3 bilinen-secret taraması", () => {
  it("testkit oracle'ındaki tüm canary biçimlerini maskeler", () => {
    const canary = makeCanary("kubeconfig-token");
    const known = new KnownSecrets();
    expect(known.add("kc", canary.value)).toBe(true);
    for (const v of canaryVariants(canary)) {
      const out = known.scrub(`öncesi ${v.needle} sonrası`);
      expect(out, v.name).not.toContain(v.needle);
      expect(out, v.name).toContain("‹redacted:known:kc›");
    }
  });

  it("başka bir metne gömülü base64'ü hizalamadan bağımsız maskeler", () => {
    const canary = makeCanary("tok");
    const known = new KnownSecrets();
    known.add("t", canary.value);
    for (const prefix of ["", "a", "ab", "abc", "abcd"]) {
      const blob = Buffer.from(`${prefix}${canary.value}-sonek-metin`).toString("base64");
      const out = known.scrub(`yük: ${blob}`);
      const decodedRegion = out.match(/yük: (.*)/)?.[1] ?? "";
      expect(canaryVariants(canary).some((v) => decodedRegion.includes(v.needle)), `prefix=${prefix.length}`).toBe(false);
    }
  });

  it("çok satırlı materyalde (PEM benzeri) tek bir satırın sızmasını da yakalar", () => {
    const material = ["-----BEGIN X-----", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "MDEyMzQ1Njc4OWFiY2RlZg==", "-----END X-----"].join("\n");
    const known = new KnownSecrets();
    known.add("pem", material);
    expect(known.scrub("log: MDEyMzQ1Njc4OWFiY2RlZg== bitti")).toContain("‹redacted:known:pem›");
  });

  it("çok kısa değeri kabul etmez (yanlış pozitif seli)", () => {
    const known = new KnownSecrets();
    expect(known.add("kısa", "a".repeat(MIN_KNOWN_SECRET_BYTES - 1))).toBe(false);
    expect(known.size).toBe(0);
  });

  it("remove/clear sonrası artık maskelemez; sayaç kuralı raporlar", () => {
    const known = new KnownSecrets();
    known.add("a", "cok-gizli-deger-123");
    const c = new Counter();
    known.scrub("x cok-gizli-deger-123 y cok-gizli-deger-123", c);
    expect(c.toSummary()).toEqual([{ rule: "known-secret", count: 2 }]);
    known.remove("a");
    expect(known.scrub("cok-gizli-deger-123")).toBe("cok-gizli-deger-123");
  });

  it("uzun iğne kısa iğneden önce uygulanır (kısmi örtüşme bırakmaz)", () => {
    const known = new KnownSecrets();
    known.add("kısa", "abcdefgh-12345");
    known.add("uzun", "abcdefgh-12345-ekstra-uzun-parca");
    expect(known.scrub("v=abcdefgh-12345-ekstra-uzun-parca")).toBe("v=‹redacted:known:uzun›");
  });

  it("secretNeedles geçersiz UTF-8 baytlarında yalnız bayt tabanlı biçimler üretir", () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7]);
    const needles = secretNeedles(bytes);
    expect(needles.length).toBeGreaterThan(0);
    expect(needles).toContain(Buffer.from(bytes).toString("hex"));
  });
});
