import { describe, expect, it } from "vitest";
import { Counter, DEFAULT_MASKING, MaskingContext, maskByDetectors, maskTable } from "../src/index.ts";

describe("M4 dedektörler", () => {
  it("e-posta, Luhn'lu kart, geçerli IBAN ve uluslararası telefonu maskeler", () => {
    const c = new Counter();
    const out = maskByDetectors(
      "ali@example.invalid kart 4111 1111 1111 1111 iban GB82 WEST 1234 5698 7654 32 tel +90 532 123 45 67",
      c,
    );
    expect(out).toContain("‹redacted:email›");
    expect(out).toContain("‹redacted:card›");
    expect(out).toContain("‹redacted:iban›");
    expect(out).toContain("‹redacted:phone›");
    expect(out).not.toMatch(/4111|GB82|ali@/);
  });

  it("Luhn'u geçmeyen uzun sayıyı ve epoch zaman damgasını maskelemez", () => {
    const text = "id 1234567890123456 epoch 1767225600 trace 1700000000000";
    expect(maskByDetectors(text, new Counter())).toBe(text);
  });

  it("geçersiz IBAN'ı maskelemez", () => {
    const text = "ref GB00 WEST 1234 5698 7654 32";
    expect(maskByDetectors(text, new Counter())).toBe(text);
  });

  it("e-posta: 64 karakterlik yerel kısım ve bitişik adresler maskelenir; daha uzun koşuda adres yine yakalanır", () => {
    const local = `${"a".repeat(30)}.${"b".repeat(33)}`;
    expect(maskByDetectors(`to ${local}@mail.example.invalid ok`, new Counter())).toBe("to ‹redacted:email› ok");
    expect(maskByDetectors("ali@x.invalid.v@y.invalid", new Counter())).toBe("‹redacted:email›‹redacted:email›");
    const out = maskByDetectors(`${"x".repeat(100)}@example.invalid`, new Counter());
    expect(out).toBe(`${"x".repeat(36)}‹redacted:email›`);
  });

  it("detectors:false ile devre dışı", () => {
    expect(maskByDetectors("a@b.invalid", new Counter(), { columns: [], detectors: false })).toBe("a@b.invalid");
  });
});

describe("M4 tablo maskeleme", () => {
  const table = {
    columns: [{ name: "id" }, { name: "email" }, { name: "phone" }, { name: "password_hash" }, { name: "note" }],
    rows: [
      [1, "ali@example.invalid", "05321234567", "abc", "kart 4111111111111111 ile ödedi"],
      [2, "veli@example.invalid", "05329876543", "def", "sorun yok"],
    ],
  } as const;

  it("sütun kuralları uygulanır: hash/truncate/redact; kural dışı sütunda dedektör çalışır", () => {
    const ctx = new MaskingContext();
    const out = maskTable(table, DEFAULT_MASKING, ctx, new Counter());
    expect(out.columns.map((c) => c.name)).toEqual(["id", "email", "phone", "password_hash", "note"]);
    const [r1, r2] = out.rows as unknown[][];
    expect(r1?.[0]).toBe(1);
    expect(String(r1?.[1])).toMatch(/^h:[0-9a-f]{10}$/);
    expect(r1?.[2]).toBe("053…");
    expect(r1?.[3]).toBe("‹redacted:password_hash›");
    expect(String(r1?.[4])).toContain("‹redacted:card›");
    expect(JSON.stringify(out)).not.toMatch(/ali@|veli@|4111|05321234567/);
    expect(r1?.[1]).not.toBe(r2?.[1]);
  });

  it("aynı oturumda aynı değer aynı hash'e gider; farklı oturumda gitmez", () => {
    const a = new MaskingContext();
    const b = new MaskingContext();
    expect(a.hash("x@y.invalid")).toBe(a.hash("x@y.invalid"));
    expect(a.hash("x@y.invalid")).not.toBe(b.hash("x@y.invalid"));
  });

  it("sütun kökeni (tablo.sütun) üzerinden de eşleşir", () => {
    const t = { columns: [{ name: "c1", origin: { relation: "users", column: "email" } }], rows: [["ali@example.invalid"]] };
    const out = maskTable(t, DEFAULT_MASKING, new MaskingContext(), new Counter());
    expect(String(out.rows[0]?.[0])).toMatch(/^h:/);
  });

  it("`g`/`y` bayraklı sütun kuralı ve ek dedektör durum taşımaz (aynı adlı ikinci sütun, ikinci geçiş)", () => {
    const rules = {
      columns: [{ match: /^email$/g, action: "hash" as const }],
      extraDetectors: [{ id: "musteri-no", regex: /\bMN-\d{6}\b/ }],
    };
    const t = {
      columns: [{ name: "email" }, { name: "email" }, { name: "note" }],
      rows: [
        ["a@example.invalid", "b@example.invalid", "MN-123456 ve MN-654321"],
        ["c@example.invalid", "d@example.invalid", "MN-111111"],
      ],
    };
    for (let pass = 0; pass < 2; pass++) {
      const out = maskTable(t, rules, new MaskingContext(), new Counter());
      expect(JSON.stringify(out.rows)).not.toMatch(/example\.invalid|MN-\d/);
    }
  });

  it("drop eylemi sütunu kaldırır", () => {
    const rules = { columns: [{ match: /^note$/, action: "drop" as const }] };
    const out = maskTable(table, rules, new MaskingContext(), new Counter());
    expect(out.columns.map((c) => c.name)).not.toContain("note");
    expect(out.rows[0]).toHaveLength(4);
  });
});
