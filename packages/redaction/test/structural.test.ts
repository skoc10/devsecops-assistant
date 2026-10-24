import { describe, expect, it } from "vitest";
import { applyStructural, Counter, DEFAULT_PROFILE, getProfile, registerProfile } from "../src/index.ts";

const apply = (v: unknown, p = DEFAULT_PROFILE): { out: unknown; c: Counter } => {
  const c = new Counter();
  return { out: applyStructural(v, p, c), c };
};

describe("M1 yapısal reddet listesi", () => {
  it("managedFields atılır; secret-benzeri anahtarların değeri maskelenir", () => {
    const { out } = apply({ metadata: { name: "a", managedFields: [{ x: 1 }] }, password: "p4ss", token: { a: 1 }, ok: true });
    expect(out).toEqual({ metadata: { name: "a" }, password: "‹redacted:field›", token: "‹redacted:field›", ok: true });
  });

  it("boş ve boolean değerler maskelenmez (bilgi sızdırmaz)", () => {
    const { out } = apply({ password: "", token: null, secret: false });
    expect(out).toEqual({ password: "", token: null, secret: false });
  });

  it("{name: SECRET_ADI, value} çiftlerinde value maskelenir", () => {
    const { out } = apply({ env: [{ name: "DB_PASSWORD", value: "x" }, { name: "LOG_LEVEL", value: "debug" }] });
    expect(out).toEqual({ env: [{ name: "DB_PASSWORD", value: "‹redacted:field›" }, { name: "LOG_LEVEL", value: "debug" }] });
  });

  it("nesne düzeyi at kuralı ve kayıtlı profiller çalışır", () => {
    registerProfile({
      name: "test-k8s",
      dropObject: (n) => (n["kind"] === "Secret" ? "kind-secret" : null),
    });
    const { out, c } = apply({ items: [{ kind: "Secret", data: { a: "b" } }, { kind: "Pod" }] }, getProfile("test-k8s"));
    expect(out).toEqual({ items: ["‹dropped:kind-secret›", { kind: "Pod" }] });
    expect(c.toSummary()).toEqual([{ rule: "m1:drop-object:kind-secret", count: 1 }]);
  });

  it("kayıtlı profil varsayılan maskeleri KAYBETMEZ (yalnız ekler)", () => {
    registerProfile({ name: "t-only-drop", dropObject: () => null });
    const { out } = apply({ password: "p4ss", managedFields: [1], env: [{ name: "API_TOKEN", value: "v" }] }, getProfile("t-only-drop"));
    expect(out).toEqual({ password: "‹redacted:field›", env: [{ name: "API_TOKEN", value: "‹redacted:field›" }] });
    registerProfile({ name: "t-extra", maskKeys: /^kimlik$/ });
    const r = apply({ kimlik: "x", password: "y" }, getProfile("t-extra"));
    expect(r.out).toEqual({ kimlik: "‹redacted:field›", password: "‹redacted:field›" });
  });

  it("bilinmeyen profil adı varsayılana düşer", () => {
    expect(getProfile("yok").name).toBe("default");
  });

  it("çok derin yapıyı keser (özyineleme koruması)", () => {
    let deep: unknown = "x";
    for (let i = 0; i < 100; i++) deep = { a: deep };
    expect(JSON.stringify(apply(deep).out)).toContain("max-depth");
  });
});
