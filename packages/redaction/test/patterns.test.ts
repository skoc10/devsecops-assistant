import { describe, expect, it } from "vitest";
import { applyPatternRules, Counter, looksLikeHighEntropySecret } from "../src/index.ts";
import { fake } from "./helpers.ts";

const run = (s: string, entropy = true): { out: string; c: Counter } => {
  const c = new Counter();
  return { out: applyPatternRules(s, c, { entropy }), c };
};

describe("M2 desen kuralları", () => {
  it.each([
    ["aws-access-key-id", () => `key=${fake.awsKeyId()} x`],
    ["github-token", () => `token ${fake.githubToken()}`],
    ["gitlab-token", () => `CI_JOB ${fake.gitlabToken()}`],
    ["slack-token", () => `hook ${fake.slackToken()}`],
    ["google-api-key", () => `k: ${fake.googleKey()}`],
    ["jwt", () => `auth ${fake.jwt()} bitti`],
    ["private-key-block", () => `${fake.privateKeyBlock()}`],
  ])("%s maskelenir", (rule, make) => {
    const input = make();
    const { out, c } = run(input);
    expect(out).toContain(`‹redacted:${rule}›`);
    expect(c.toSummary().some((s) => s.rule === rule)).toBe(true);
    for (const piece of input.split(/\s+/).filter((p) => p.length > 20 && !p.includes("-----"))) {
      expect(out).not.toContain(piece);
    }
  });

  it("google-api-key: '-' ile biten anahtar da maskelenir (sondaki \\b kelime karakteri ister; eskiden kaçıyordu)", () => {
    for (const tail of ["-", "_", "A", "9"]) {
      const key = `AIza${"x".repeat(34)}${tail}`;
      const { out } = run(`k: ${key} bitti`);
      expect(out, tail).toContain("‹redacted:google-api-key›");
      expect(out, tail).not.toContain(key.slice(4));
    }
    // 36 karakterlik gövde anahtar değildir (yanlış pozitif yok)
    expect(run(`AIza${"x".repeat(36)}`).out).not.toContain("‹redacted:google-api-key›");
  });

  it("kırpılmış (END'siz) özel anahtar bloğunu da maskeler", () => {
    const block = fake.privateKeyBlock();
    const truncated = block.slice(0, block.indexOf("-----END"));
    const { out } = run(`log: ${truncated}`);
    expect(out).toContain("‹redacted:private-key-block›");
    expect(out).not.toMatch(/[A-Za-z0-9+/]{60,}/);
  });

  it("Bearer ve Basic başlıklarında yalnız değeri maskeler", () => {
    const { out } = run(`Authorization: Bearer ${fake.highEntropy()}\nAuthorization: Basic dXNlcjpwYXJvbGExMjM0NQ==`);
    expect(out).toContain("Bearer ‹redacted:bearer-token›");
    expect(out).toContain("Basic ‹redacted:basic-auth›");
  });

  it("URL içindeki kimlik bilgisini maskeler, kullanıcı adını korur", () => {
    const pw = fake.password();
    const { out } = run(`postgres://app:${pw}@db.example.invalid:5432/orders`);
    expect(out).toBe("postgres://app:‹redacted:url-credentials›@db.example.invalid:5432/orders");
  });

  it("anahtar=değer biçimindeki secret'ları maskeler (env, ini, yaml, json)", () => {
    const pw = fake.password();
    const { out } = run(`DB_PASSWORD=${pw}\napi_key: "${pw}"\n{"client_secret": "${pw}"}`);
    expect(out).not.toContain(pw);
    expect((out.match(/‹redacted:kv-secret›/g) ?? []).length).toBe(3);
  });

  it("şablon/referans/sayaç değerlerini maskelemez (yanlış pozitif)", () => {
    const benign = [
      "token: ${TOKEN}",
      "password: {{ .Values.db.password }}",
      "secret: <your-secret>",
      "tokenCount: 5",
      "password: true",
      "secretsRotated: 12345",
      "api_key: null",
    ].join("\n");
    expect(run(benign).out).toBe(benign);
  });

  it("kanıt değeri olan özet, UUID, k8s adı, imaj ve yol metinlerini bozmaz", () => {
    const sha = `sha256:${"ab12".repeat(16)}`;
    const text = [
      "Pod payments-api-7d9f8b6c5d-x2k4q Running",
      "image ghcr.io/example/app@" + sha,
      "id 3f2b8c1e-9a4d-4e7b-8f21-0c5d6e7a8b9c",
      "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
      "GET /api/v1/namespaces/payments/pods?limit=500 200",
      "OOMKilled exit code 137 after 1048576 bytes",
    ].join("\n");
    const { out, c } = run(text);
    expect(out).toBe(text);
    expect(c.total()).toBe(0);
  });

  it("yüksek entropili karışık jetonu yakalar; entropi kapatılabilir", () => {
    const t = fake.highEntropy();
    expect(looksLikeHighEntropySecret(t)).toBe(true);
    expect(run(`bilinmeyen ${t}`).out).toContain("‹redacted:high-entropy›");
    expect(run(`bilinmeyen ${t}`, false).out).toContain(t);
  });

  it("idempotent: ikinci geçiş çıktıyı değiştirmez", () => {
    const text = `${fake.awsKeyId()} password=${fake.password()} Bearer ${fake.highEntropy()}`;
    const once = run(text).out;
    expect(run(once).out).toBe(once);
  });

  it("PEM sertifikasını secret saymaz ama token için sıkıştırır", () => {
    const cert = ["-----BEGIN CERTIFICATE-----", "A".repeat(64), "-----END CERTIFICATE-----"].join("\n");
    const { out, c } = run(`ca:\n${cert}`);
    expect(out).toMatch(/‹pem:CERTIFICATE \d+B›/);
    expect(c.toSummary().map((s) => s.rule)).toContain("compact:pem-certificate");
  });
});
