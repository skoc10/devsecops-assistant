import { describe, expect, it } from "vitest";
import { OpsError } from "@ops/contracts";
import { dbError, staticMessage } from "../src/errors.ts";

const pgErr = (code: string, message: string, extra: Record<string, unknown> = {}) => Object.assign(new Error(message), { code, ...extra });

describe("dbError: hata metni hücre değeri taşımaz", () => {
  it.each([
    ["22P02 sayıya dönüştürme", "22P02", 'invalid input syntax for type integer: "call +90 555 111 22 33 or ayse@example.invalid"', "invalid input syntax for type integer (değer gizlendi)"],
    ["22P02 boş dize", "22P02", 'invalid input syntax for type uuid: ""', "invalid input syntax for type uuid (değer gizlendi)"],
    ["22003 aralık dışı (değer ortada)", "22003", 'value "123456789012" is out of range for type integer', 'value "…" is out of range for type integer (değer gizlendi)'],
    ["22008 tarih/saat", "22008", 'date/time field value out of range: "2024-13-45"', "date/time field value out of range (değer gizlendi)"],
    ["22007 zaman damgası", "22007", 'invalid input syntax for type timestamp with time zone: "Ayse"', "invalid input syntax for type timestamp with time zone (değer gizlendi)"],
    ["22P05 bayt dizisi", "22P05", 'character with byte sequence 0xc4 0xb1 in encoding "UTF8" has no equivalent in encoding "LATIN1"', 'character with byte sequence 0x… 0x… in encoding "…" has no equivalent in encoding "…" (değer gizlendi)'],
    ["2201B düzenli ifade (desen sütundan gelebilir)", "2201B", "invalid regular expression: parentheses () not balanced", "invalid regular expression (değer gizlendi)"],
    ["23505 benzersizlik (DETAIL'deki anahtar zaten atılır)", "23505", 'duplicate key value violates unique constraint "customers_email_key"', 'duplicate key value violates unique constraint "…" (değer gizlendi)'],
    ["kapanmamış tırnak (kesilmiş mesaj)", "22P02", 'value "abc is out of range', 'value "…" (değer gizlendi)'],
  ])("%s", (_n, code, message, expected) => {
    const e = dbError(pgErr(code, message, { detail: "Key (email)=(ayse@example.invalid) already exists.", where: "SQL function", hint: "x" }), "sorgu başarısız");
    expect(e).toBeInstanceOf(OpsError);
    expect(e.code).toBe("db_error");
    expect(e.message).toBe(`sorgu başarısız: [${code}] ${expected}`);
    expect(e.message).not.toMatch(/ayse|Ayse|555|2024-13|123456789012|customers_email_key/);
  });

  it("değer taşımayan veri istisnası ve diğer sınıflar olduğu gibi kalır (SQLSTATE + ilk satır, ≤200)", () => {
    expect(dbError(pgErr("22012", "division by zero"), "sorgu başarısız").message).toBe("sorgu başarısız: [22012] division by zero");
    expect(dbError(pgErr("42P01", 'relation "public.nonexistent_table" does not exist\nLINE 1: …'), "sorgu başarısız").message).toBe('sorgu başarısız: [42P01] relation "public.nonexistent_table" does not exist');
    expect(dbError(pgErr("57014", "canceling statement due to statement timeout"), "x").message).toBe("x: [57014] canceling statement due to statement timeout");
    expect(dbError(new Error("connect ECONNREFUSED 127.0.0.1:1"), "veritabanına bağlanılamadı").message).toBe("veritabanına bağlanılamadı: connect ECONNREFUSED 127.0.0.1:1");
    expect(dbError(pgErr("42601", "x".repeat(500)), "y").message.length).toBeLessThanOrEqual("y: [42601] ".length + 200);
  });

  it("rutin (RAISE/dış rutin) metni hiç iletilmez; OpsError aynen geçer", () => {
    for (const code of ["P0001", "P0004", "38000", "39P01"]) {
      const m = dbError(pgErr(code, "invalid email ayse@example.invalid for customer 1"), "ifade 1/1 (update) başarısız").message;
      expect(m).toBe(`ifade 1/1 (update) başarısız: [${code}] rutin hatası (metin değer taşıyabileceği için iletilmez)`);
    }
    const ops = new OpsError("target_changed", "şema değişti");
    expect(dbError(ops, "x")).toBe(ops);
  });

  it("staticMessage: iki nokta sonrası atılır, tırnaklı parçalar maskelenir", () => {
    expect(staticMessage('invalid input value for enum mood: "sad"')).toBe("invalid input value for enum mood");
    expect(staticMessage("unterminated quoted string at or near 'x")).toBe("unterminated quoted string at or near '…'");
    expect(staticMessage('a "b""c" d')).toBe('a "…" d');
  });
});
