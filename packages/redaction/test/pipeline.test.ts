import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { estimateTokens } from "@ops/contracts";
import { findCanary, makeCanary } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import { Counter, DEFAULT_MASKING, KnownSecrets, processOutput, registerProfile, scrubText } from "../src/index.ts";
import type { OutputPolicy } from "../src/index.ts";
import { fake } from "./helpers.ts";

function policy(over: Partial<OutputPolicy> = {}, known = new KnownSecrets()): OutputPolicy {
  return { structuralProfile: "default", maxBytes: 64_000, maxItems: 100, maxOutputTokens: 1500, known, ...over };
}

function leakIn(texts: string[], canaries: Canary[]): string[] {
  const found: string[] = [];
  for (const t of texts) for (const c of canaries) {
    const v = findCanary(t, c);
    if (v) found.push(`${c.label}:${v}`);
  }
  return found;
}

describe("S-06 çekirdeği: canary çıktı boru hattından sızmaz", () => {
  it("iç içe değerde, anahtarda, logda ve gömülü base64'te ham/kodlu canary maskelenir", () => {
    const canary = makeCanary("kubeconfig");
    const known = new KnownSecrets();
    known.add("kc", canary.value);
    const blob = Buffer.from(`abc${canary.value}xyz`).toString("base64");
    const data = {
      pods: [{ ad: "a", env: [{ ad: "X", deger: `değer ${canary.value}` }] }],
      [`anahtar-${canary.value}`]: "v",
      log: `2026 ERROR bağlanamadı token=${canary.value}\nbase64: ${blob}\nurl: https://x.invalid/?t=${encodeURIComponent(canary.value)}\nhex ${Buffer.from(canary.value).toString("hex")}`,
    };
    const out = processOutput(data, `özet ${canary.value}`, policy({}, known));
    expect(leakIn([out.evidenceText, out.viewText, out.summary], [canary])).toEqual([]);
    expect(out.redactions.some((r) => r.rule === "known-secret")).toBe(true);
  });

  it("özellik testi: rastgele yerleşim ve biçimde canary hiçbir çıktı kanalında kalmaz", () => {
    const mode = fc.constantFrom("raw", "b64", "url", "hex", "json");
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }), fc.string({ maxLength: 40 }), fc.string({ maxLength: 12 }), mode, (pre, post, key, m) => {
        const canary = makeCanary("prop");
        const known = new KnownSecrets();
        known.add("p", canary.value);
        const encode = (s: string): string =>
          m === "b64" ? Buffer.from(s).toString("base64")
            : m === "url" ? encodeURIComponent(s)
            : m === "hex" ? Buffer.from(s).toString("hex")
            : m === "json" ? JSON.stringify(s).slice(1, -1)
            : s;
        const payload = m === "b64" || m === "hex" ? encode(pre + canary.value + post) : pre + encode(canary.value) + post;
        const data = { [`${key}`]: payload, nested: [{ deep: { v: payload } }], list: [payload, 1, null] };
        const out = processOutput(data, payload, policy({ maxOutputTokens: 4000 }, known));
        return leakIn([out.evidenceText, out.viewText, out.summary], [canary]).length === 0;
      }),
      { numRuns: 300 },
    );
  });

  it("scrubText: hata mesajı / kullanıcı girdisi için M2+M3 + kontrol karakteri temizliği", () => {
    const canary = makeCanary("hata");
    const known = new KnownSecrets();
    known.add("h", canary.value);
    const msg = `bağlantı hatası: ${canary.value} \u001b[31mkırmızı\u001b[0m ${fake.githubToken()}`;
    const out = scrubText(msg, known);
    expect(leakIn([out], [canary])).toEqual([]);
    expect(out).not.toContain("\u001b");
    expect(out).toContain("‹redacted:github-token›");
  });

  it("extraPatternRules scrubText ve processOutput'ta uygulanır; `g`siz/`y`li kural da her geçişi maskeler", () => {
    const rules = [
      { id: "corp-token", regex: /\bCORP-[0-9]{8}\b/ }, // bilerek `g`siz: yalnız ilk geçiş maskelenmemeli
      { id: "corp-ref", regex: /REF#[A-Z]{6}/y },
    ];
    const c = new Counter();
    expect(scrubText("a CORP-12345678 b CORP-87654321 REF#ABCDEF REF#GHIJKL", new KnownSecrets(), c, { extraPatternRules: rules })).toBe(
      "a ‹redacted:corp-token› b ‹redacted:corp-token› ‹redacted:corp-ref› ‹redacted:corp-ref›",
    );
    expect(c.toSummary()).toEqual([
      { rule: "corp-ref", count: 2 },
      { rule: "corp-token", count: 2 },
    ]);
    const out = processOutput({ v: "CORP-12345678", list: ["x CORP-87654321 REF#ABCDEF"] }, "özet CORP-11112222", policy({ extraPatternRules: rules }));
    for (const ch of [out.evidenceText, out.viewText, out.summary]) expect(ch).not.toMatch(/CORP-\d{8}|REF#[A-Z]{6}/);
    expect(out.redactions.find((r) => r.rule === "corp-token")?.count).toBe(3);
    expect(out.redactions.find((r) => r.rule === "corp-ref")?.count).toBe(1);
    // çağıranın RegExp nesnesi değiştirilmez
    expect(rules[0]?.regex.global).toBe(false);
    expect(rules[1]?.regex.lastIndex).toBe(0);
  });

  it("M1 secret anahtarı ve yapılandırılmış profil kuralı birlikte çalışır", () => {
    registerProfile({ name: "t-k8s", dropObject: (n) => (n["kind"] === "Secret" ? "kind-secret" : null) });
    const pw = fake.password();
    const data = { items: [{ kind: "Secret", data: { sifre: Buffer.from(pw).toString("base64") } }, { kind: "ConfigMap", data: { password: pw } }] };
    const out = processOutput(data, undefined, policy({ structuralProfile: "t-k8s" }));
    expect(out.evidenceText).not.toContain(pw);
    expect(out.evidenceText).not.toContain(Buffer.from(pw).toString("base64"));
    expect(out.evidenceText).toContain("‹dropped:kind-secret›");
  });
});

describe("B-03: referansla taşıma ve token tavanı", () => {
  const bigList = Array.from({ length: 800 }, (_, i) => ({
    metadata: { name: `workload-${i}`, namespace: i % 2 ? "a" : "b", uid: `uid-${i}`, labels: { app: `app-${i}`, tier: "backend" } },
    status: { phase: i % 50 === 0 ? "Failed" : "Running", podIP: `10.1.${i % 250}.${i % 200}` },
  }));

  it("tavanı aşan sonuç ham gitmez ya da tavana kırpılarak gider; tam kanıt korunur", () => {
    const out = processOutput(bigList, "800 öğe", policy({ maxOutputTokens: 600, maxBytes: 400_000, maxItems: 1000, projection: { defaultFields: ["metadata.name", "status.phase"], selectable: true } }));
    expect(out.tokens).toBeLessThanOrEqual(600);
    expect(out.fullTokens).toBeGreaterThan(out.tokens);
    expect(out.truncated).toBe(true);
    expect(out.evidenceText).toContain("workload-799");
    expect(out.viewText).not.toContain("workload-799");
  });

  it("sığmayan sonuç yalnız referansla döner", () => {
    const hostile = Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`k${i}`, `değer-${i}`]));
    const out = processOutput(hostile, undefined, policy({ maxOutputTokens: 80, maxBytes: 400_000 }));
    expect(out.byReference).toBe(true);
    expect(out.view).toBeUndefined();
    expect(out.viewText).toBe("");
    expect(out.evidenceText.length).toBeGreaterThan(1000);
  });

  it("özellik testi: görünüm ya tavana sığar ya referansladır", () => {
    fc.assert(
      fc.property(fc.jsonValue(), fc.integer({ min: 60, max: 1200 }), (data, maxTokens) => {
        const out = processOutput(data, undefined, policy({ maxOutputTokens: maxTokens }));
        return out.byReference ? out.viewText === "" : out.tokens <= maxTokens && estimateTokens(out.viewText) === out.tokens;
      }),
      { numRuns: 200 },
    );
  });

  it("kompaktlaştırma redaksiyondan SONRA: projeksiyonla atılan alandaki secret kanıtta da yok", () => {
    const canary = makeCanary("sonra");
    const known = new KnownSecrets();
    known.add("s", canary.value);
    const data = [{ ad: "a", gizli_alan: canary.value }, { ad: "b", gizli_alan: canary.value }];
    const out = processOutput(data, undefined, policy({ projection: { defaultFields: ["ad"], selectable: false } }, known));
    expect(leakIn([out.evidenceText, out.viewText], [canary])).toEqual([]);
    expect(out.viewText).not.toContain("gizli_alan");
    expect(out.evidenceText).toContain("‹redacted:");
  });

  it("kanıt bayt üst sınırı aşılırsa kesilir ve işaretlenir", () => {
    const data = { metin: "x".repeat(50_000), liste: Array.from({ length: 500 }, (_, i) => i) };
    const out = processOutput(data, undefined, policy({ maxBytes: 5_000, maxItems: 100 }));
    expect(Buffer.byteLength(out.evidenceText)).toBeLessThanOrEqual(5_200);
    expect(out.truncated).toBe(true);
  });

  it("tablo girdisine M4 uygulanır ve sütun maskesi görünüme de yansır", () => {
    const table = { columns: [{ name: "id" }, { name: "email" }], rows: [[1, "ali@example.invalid"], [2, "veli@example.invalid"]] };
    const out = processOutput(table, undefined, policy({ masking: { columns: [{ match: /^email$/, action: "hash" }] } }));
    expect(out.evidenceText).not.toContain("example.invalid");
    expect(out.viewText).not.toContain("example.invalid");
    expect(out.redactions.some((r) => r.rule === "m4:column:hash")).toBe(true);
  });

  it("tablodaki jsonb/dizi hücrelerinde PII kanıta ve görünüme gitmez", () => {
    const table = {
      columns: [{ name: "id" }, { name: "meta" }, { name: "tags" }],
      rows: [[1, { iletisim: { eposta: "ayse.yilmaz@example.invalid", tel: "+90 532 123 45 67" } }, ["kart 4111 1111 1111 1111"]]],
    };
    const out = processOutput(table, undefined, policy({ masking: DEFAULT_MASKING }));
    for (const ch of [out.evidenceText, out.viewText]) expect(ch).not.toMatch(/ayse\.yilmaz|532 123|4111/);
    expect(out.redactions.map((r) => r.rule)).toEqual(expect.arrayContaining(["m4:email", "m4:phone", "m4:card"]));
  });
});

describe("ReDoS: tek satırlık saldırgan girdi olay döngüsünü kilitlemez", () => {
  const N = 256 * 1024; // günlük araçlarının izin verdiği tek satır üst sınırı
  const rep = (unit: string): string => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  // Düzeltme öncesi her biri processOutput'ta saniyeler–dakikalar sürüyordu (karesel geri izleme):
  // ör. 256 KB `token`×n ≈ 51 sn, `eyJ-`×n ≈ 107 sn, `a`×n ≈ 41 sn.
  const hostile: readonly (readonly [string, () => string])[] = [
    ["kv-secret: token×n", () => rep("token")],
    ["jwt: eyJ-×n", () => rep("eyJ-")],
    ["url-credentials + e-posta: a-×n", () => rep("a-")],
    ["e-posta yerel kısım: a×n", () => rep("a")],
    ["e-posta alan adı geri izlemesi", () => rep(`${"a".repeat(64)}@${"b.".repeat(126)}b1`)],
    ["END'siz BEGIN PRIVATE KEY×n", () => rep("-----BEGIN PRIVATE KEY-----!\n")],
    ["END'siz BEGIN CERTIFICATE×n", () => rep("-----BEGIN CERTIFICATE-----!\n")],
    ["M3 çözme: %C5×n", () => rep("%C5")],
    ["M3 çözme: \\u0041×n", () => rep("\\u0041")],
    ["M3 çözme: &amp;×n", () => rep("&amp;")],
  ];
  const known = new KnownSecrets();
  known.add("db", "Tr0ub4dor&3!/x+y=ab");
  known.add("tok", fake.highEntropy());
  const p = policy({ maxBytes: 300_000, masking: DEFAULT_MASKING }, known);

  // Cömert sınır (titrek olmasın): hedef ≪ 300 ms, yerelde ≈ 10–90 ms; karesel davranış onlarca saniye.
  it.each(hostile)("%s: 256 KB tek satır (nesne ve günlük metni) 1,5 sn'nin altında", (_name, gen) => {
    const line = gen();
    for (const data of [{ log: line }, line]) {
      const t = performance.now();
      processOutput(data, "özet", { ...p, logLike: typeof data === "string" });
      expect(performance.now() - t).toBeLessThan(1500);
    }
  });

  it("uzun saldırgan satırın sonundaki secret ve PII yine maskelenir (sınırlı nicelikler tespiti daraltmaz)", () => {
    const pw = fake.password();
    const jwt = fake.jwt();
    const tail = ` password=${pw} dsn=postgres://app:${pw}@db.example.invalid/x auth ${jwt} mail ali.veli@example.invalid`;
    const out = processOutput({ log: `${rep("token-a-eyJ-")}${tail}` }, undefined, p);
    for (const ch of [out.evidenceText, out.viewText]) {
      expect(ch).not.toContain(pw);
      expect(ch).not.toContain(jwt.split(".")[1] as string);
      expect(ch).not.toContain("ali.veli@");
    }
    const rules = out.redactions.map((r) => r.rule);
    expect(rules).toEqual(expect.arrayContaining(["kv-secret", "url-credentials", "jwt", "m4:email"]));
  });
});
