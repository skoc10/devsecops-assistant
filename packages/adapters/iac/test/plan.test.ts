import { describe, expect, it } from "vitest";
import { makeCanary } from "@ops/testkit";
import { risksFor, summarizePlan } from "../src/index.ts";

const rc = (address: string, type: string, actions: string[], before: unknown, after: unknown, extra: Record<string, unknown> = {}) => ({
  address,
  mode: "managed",
  type,
  name: address.split(".").pop(),
  change: { actions, before, after, after_unknown: {}, before_sensitive: {}, after_sensitive: {}, ...extra },
});

describe("summarizePlan (saf)", () => {
  it("sayılar, eylem sırası (silme önce), risk etiketleri ve kaynak adresleri", () => {
    const s = summarizePlan({
      format_version: "1.2",
      resource_changes: [
        rc("aws_s3_bucket.logs", "aws_s3_bucket", ["create"], null, { bucket: "logs" }),
        rc("aws_db_instance.main", "aws_db_instance", ["delete", "create"], { engine: "pg" }, { engine: "pg" }),
        rc("aws_iam_role.app", "aws_iam_role", ["create"], null, { name: "app" }),
        rc("aws_security_group.web", "aws_security_group", ["update"], { description: "a" }, { description: "b" }),
        rc("aws_instance.old", "aws_instance", ["delete"], { ami: "x" }, null),
        rc("aws_vpc.unchanged", "aws_vpc", ["no-op"], {}, {}),
      ],
      output_changes: { endpoint: { actions: ["create"], after_sensitive: false }, token: { actions: ["create"], after_sensitive: true } },
    });
    expect(s.counts).toEqual({ create: 2, update: 1, delete: 1, replace: 1, read: 0, "no-op": 1 });
    expect(s.changes.map((c) => `${c.action}:${c.address}`)).toEqual([
      "delete:aws_instance.old",
      "replace:aws_db_instance.main",
      "update:aws_security_group.web",
      "create:aws_iam_role.app",
      "create:aws_s3_bucket.logs",
    ]);
    const labels = Object.fromEntries(s.risks.map((r) => [r.label, r.count]));
    expect(labels).toMatchObject({ silme: 1, "yeniden-yaratma": 1, "kimlik-yetki": 1, "ağ-kuralı": 1, "veri-kaybı-riski": 1 });
    expect(s.outputs).toEqual([
      { name: "endpoint", action: "create", sensitive: false },
      { name: "token", action: "create", sensitive: true },
    ]);
  });

  it("hassas bayraklı, gizli-adlı ve bilinmeyen öznitelik DEĞERLERİ hiçbir koşulda çıkmaz; prior_state/configuration/variables kopyalanmaz", () => {
    const c = { pw: makeCanary("plan-pw"), tok: makeCanary("plan-tok"), plain: makeCanary("plan-plain"), prior: makeCanary("plan-prior"), conf: makeCanary("plan-conf"), varv: makeCanary("plan-var") };
    const s = summarizePlan({
      format_version: "1.2",
      variables: { db_password: { value: c.varv.value } },
      prior_state: { values: { root_module: { resources: [{ values: { secret: c.prior.value } }] } } },
      configuration: { root_module: { resources: [{ expressions: { password: { constant_value: c.conf.value } } }] } },
      resource_changes: [
        rc(
          "x_db.main",
          "x_db",
          ["create"],
          null,
          { name: "main", password: c.pw.value, master_token: c.tok.value, region: "eu", api_key_id: "k1", conn: c.pw.value, tags: { a: c.plain.value }, size: 20 },
          { after_sensitive: { conn: true }, after_unknown: { endpoint: true } },
        ),
      ],
    }, { maxAttrs: 12 });
    const text = JSON.stringify(s);
    for (const canary of Object.values(c)) {
      if (canary === c.plain) continue; // tags nesnesi zaten alınmaz
      expect(text, canary.label).not.toContain(canary.value);
    }
    expect(text).not.toContain(c.plain.value);
    const attrs = s.changes[0]?.attrs ?? [];
    expect(attrs.find((a) => a.name === "name")).toMatchObject({ value: "main" });
    expect(attrs.find((a) => a.name === "size")).toMatchObject({ value: "20" });
    expect(attrs.find((a) => a.name === "password")).toEqual({ name: "password", note: "gizli-adlı" });
    expect(attrs.find((a) => a.name === "master_token")).toEqual({ name: "master_token", note: "gizli-adlı" });
    expect(attrs.find((a) => a.name === "conn")).toEqual({ name: "conn", note: "hassas" });
    expect(attrs.find((a) => a.name === "endpoint")).toEqual({ name: "endpoint", note: "apply sonrası belli" });
    expect(attrs.find((a) => a.name === "tags")).toBeUndefined();
  });

  it("update: yalnız değişen öznitelikler, before → after; değişmeyenler yok; hassas değişimde değer yok", () => {
    const sec = makeCanary("upd-sec");
    const s = summarizePlan({
      resource_changes: [rc("x.a", "x", ["update"], { a: "1", b: "same", c: sec.value }, { a: "2", b: "same", c: "new" }, { before_sensitive: { c: true }, after_sensitive: { c: true } })],
    });
    expect(s.changes[0]?.attrs).toEqual([{ name: "a", value: "2", before: "1" }, { name: "c", note: "hassas" }]);
    expect(JSON.stringify(s)).not.toContain(sec.value);
  });

  it("sınırlar: çok değişiklik kırpılır (omitted), öznitelik sayısı ve değer uzunluğu sınırlıdır", () => {
    const many = Array.from({ length: 60 }, (_, i) => rc(`t.r${String(i).padStart(2, "0")}`, "t", ["create"], null, { a: "x".repeat(500), b: 1, c: 2, d: 3, e: 4, f: 5, g: 6, h: 7 }));
    const s = summarizePlan({ resource_changes: many }, { maxChanges: 10 });
    expect(s.changes).toHaveLength(10);
    expect(s.omitted).toBe(50);
    expect(s.counts.create).toBe(60);
    expect(s.changes[0]?.attrs).toHaveLength(6);
    expect(s.changes[0]?.attrs[0]?.value?.length).toBeLessThanOrEqual(61);
  });

  it("bozuk/eksik girdi istisna fırlatmaz", () => {
    for (const v of [null, undefined, 3, "x", [], {}, { resource_changes: "x" }, { resource_changes: [null, 3, { change: 5 }] }]) {
      expect(() => summarizePlan(v)).not.toThrow();
    }
  });

  it("risksFor: tür + eylem kuralları", () => {
    expect(risksFor("aws_iam_policy", "create")).toEqual(["kimlik-yetki"]);
    expect(risksFor("aws_iam_policy", "no-op")).toEqual([]);
    expect(risksFor("azurerm_network_security_group", "update")).toEqual(["ağ-kuralı"]);
    expect(risksFor("google_sql_database_instance", "delete")).toEqual(["silme", "veri-kaybı-riski"]);
    expect(risksFor("random_pet", "create")).toEqual([]);
  });
});
