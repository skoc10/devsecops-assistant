import { describe, expect, it } from "vitest";
import {
  Counter,
  KnownSecrets,
  MIN_KNOWN_SECRET_BYTES,
  canonicalNeedles,
  processOutput,
  scrubText,
  secretNeedles,
} from "../src/index.ts";
import type { OutputPolicy } from "../src/index.ts";
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
    expect(canonicalNeedles(bytes)).toEqual([]);
  });
});

/** JSON dizgisi içeriği (tırnaksız), seçilen karakterler `\uXXXX` olarak kaçışlanır. */
function jsonEsc(s: string, escape: RegExp = /(?!)/, upperHex = false): string {
  return JSON.stringify(s)
    .slice(1, -1)
    .replace(escape, (c) => {
      const h = c.charCodeAt(0).toString(16).padStart(4, "0");
      return `\\u${upperHex ? h.toUpperCase() : h}`;
    });
}
const htmlEsc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const formEnc = (s: string): string => new URLSearchParams({ p: s }).toString().slice(2);

const ENCODINGS: readonly (readonly [string, (s: string) => string])[] = [
  ["form-urlencoded (URLSearchParams, HTML formu: boşluk → +)", formEnc],
  ["python quote(): '/' korunur", (s) => encodeURIComponent(s).replace(/%2F/g, "/")],
  ["küçük harfli yüzde kodlaması", (s) => encodeURIComponent(s).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())],
  ["Go encoding/json: \\u0026 \\u003c \\u003e", (s) => jsonEsc(s, /[&<>]/g)],
  ["Python json.dumps (ensure_ascii)", (s) => jsonEsc(s, /[^\x00-\x7f]/g)],
  [".NET System.Text.Json: büyük harfli \\u002B, \\u0027", (s) => jsonEsc(s, /[^\x00-\x7f]|[<>&'+]/g, true)],
  ["PHP json_encode: \\/ ve \\uXXXX", (s) => jsonEsc(s, /[^\x00-\x7f]/g).replace(/\//g, "\\/")],
  ["HTML/XML varlıkları: &amp; &lt; &quot; &#39;", htmlEsc],
  ["sayısal HTML varlıkları: &#NN;", (s) => [...s].map((c) => `&#${c.codePointAt(0)};`).join("")],
  ["onaltılık HTML varlıkları: &#xNN;", (s) => [...s].map((c) => `&#x${(c.codePointAt(0) as number).toString(16)};`).join("")],
  ["büyük harf", (s) => s.toUpperCase()],
  ["küçük harf", (s) => s.toLowerCase()],
  ["çift yüzde kodlaması: %2526", (s) => encodeURIComponent(encodeURIComponent(s))],
  ["çift HTML kaçışı: &amp;amp;", (s) => htmlEsc(htmlEsc(s))],
  ["JSON içinde Go JSON: \\\\u0026", (s) => jsonEsc(jsonEsc(s, /[&<>]/g))],
  ["\\xNN bayt kaçışı (Python repr)", (s) => [...Buffer.from(s)].map((b) => (b > 0x7e ? `\\x${b.toString(16)}` : String.fromCharCode(b))).join("")],
  ["büyük harf + form kodlaması", (s) => formEnc(s.toUpperCase())],
];

const SECRETS: Readonly<Record<string, string>> = {
  ascii: "Tr0ub4dor&3!/x+y=ab", // & / + = ! içeren gerçekçi DB parolası
  "ascii-dışı": "Şifre-Güçlü-2024", // UTF-8 çok baytlı
  "html-özel": `k<y>q'w"e&r 9-zZ`, // < > ' " & ve boşluk
};

describe("M3 yeniden kodlanmış biçimler (kanonik tarama)", () => {
  const known = new KnownSecrets();
  for (const [label, value] of Object.entries(SECRETS)) known.add(label, value);
  const policy: OutputPolicy = { structuralProfile: "default", maxBytes: 64_000, maxItems: 50, maxOutputTokens: 2000, known };

  const cases = ENCODINGS.flatMap(([enc, f]) => Object.entries(SECRETS).map(([label, value]) => [enc, label, f(value)] as const));

  it.each(cases)("%s [%s] scrubText ile maskelenir, çevre metin korunur", (_enc, label, encoded) => {
    expect(scrubText(`db bağlantısı user=app cred ${encoded} retry=0`, known)).toBe(
      `db bağlantısı user=app cred ‹redacted:known:${label}› retry=0`,
    );
  });

  it.each(cases)("%s [%s] processOutput'un hiçbir kanalında kalmaz", (_enc, label, encoded) => {
    const line = `2026-10-25T10:00:00Z level=info msg="POST /login body=user%3Dapp%26pass%3D${encoded}&next=1"`;
    const out = processOutput({ log: line, [`k:${encoded}`]: [encoded] }, `özet ${encoded}`, policy);
    for (const ch of [out.evidenceText, out.viewText]) {
      expect(ch).not.toContain(JSON.stringify(encoded).slice(1, -1));
      expect(ch).toContain(`pass%3D‹redacted:known:${label}›&next=1`);
    }
    expect(out.summary).toBe(`özet ‹redacted:known:${label}›`);
    expect(out.redactions.find((r) => r.rule === "known-secret")?.count).toBe(4);
  });

  it("secret başına kanonik iğne sayısı kodlamalardan bağımsızdır (değer + çok satırlı materyalin uzun satırları)", () => {
    expect(canonicalNeedles(SECRETS["ascii"] as string)).toEqual(["tr0ub4dor&3!/x y=ab"]);
    const pem = ["-----BEGIN X-----", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "MDEyMzQ1Njc4OWFiY2RlZg==", "-----END X-----"].join("\n");
    expect(canonicalNeedles(pem)).toHaveLength(4); // değer + ≥ 16 karakterlik 3 satır
    // çok satırlı materyalin tek satırı PHP `\/` kaçışıyla sızsa da yakalanır
    const k = new KnownSecrets();
    k.add("pem", "-----BEGIN X-----\nQUJDREVGR0hJ/SktMTU5PUFFSU1RVVldYWVo=\n-----END X-----");
    expect(k.scrub('{"line":"QUJDREVGR0hJ\\/SktMTU5PUFFSU1RVVldYWVo="}')).toBe('{"line":"‹redacted:known:pem›"}');
  });

  it("ilgisiz metne dokunmaz: yakın değerler, sıradan kaçışlar, kodlanmış başka metin", () => {
    const benign = [
      "Tr0ub4dor&3 is close but not equal",
      "tr0ub4dor&3!/x+y=a",
      "%54%72%30%75%62%34%64%6f%72%26%33%21%2f%78 (kırpılmış)",
      "GET /api?q=a%20b&x=1&amp;y=2 200 \\u0041\\u0042 &#39;x&#39; \\/path",
      "Sifre-Guclu-2024", // aksansız: farklı değer
    ];
    const c = new Counter();
    for (const b of benign) expect(known.scrub(b, c)).toBe(b);
    expect(c.total()).toBe(0);
  });

  it("örtüşen kanonik eşleşmeler tek maske olur; birebir ve kanonik eşleşmeler ayrı sayılır", () => {
    const c = new Counter();
    const pw = SECRETS["ascii"] as string;
    const out = known.scrub(`a=${pw} b=${pw.toUpperCase()} c=${formEnc(pw)}`, c);
    expect(out).toBe("a=‹redacted:known:ascii› b=‹redacted:known:ascii› c=‹redacted:known:ascii›");
    expect(c.toSummary()).toEqual([{ rule: "known-secret", count: 3 }]);
  });
});
