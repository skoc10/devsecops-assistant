import { describe, expect, it } from "vitest";
import { estimateTokens } from "@ops/contracts";
import {
  buildTrie,
  clampListsDeep,
  clusterLogLines,
  compactForModel,
  dropEmpty,
  fitToTokens,
  normalizeLogLine,
  projectFields,
  tabulateDeep,
} from "../src/index.ts";

const pods = Array.from({ length: 6 }, (_, i) => ({
  metadata: { name: `api-${i}`, namespace: "payments", labels: { app: "api" }, uid: `uid-${i}` },
  spec: { containers: [{ name: "app", image: "ghcr.io/x/app:1", env: [{ name: "A", value: "b" }] }], nodeName: `n${i}` },
  status: { phase: i === 3 ? "CrashLoopBackOff" : "Running", podIP: `10.0.0.${i}`, conditions: [] },
}));

describe("alan projeksiyonu", () => {
  it("nokta yollu alanlar diziler üzerinde öğe öğe uygulanır", () => {
    const out = projectFields(pods, ["metadata.name", "status.phase", "spec.containers.image"]);
    expect(out).toEqual(
      pods.map((p) => ({
        metadata: { name: p.metadata.name },
        spec: { containers: [{ image: "ghcr.io/x/app:1" }] },
        status: { phase: p.status.phase },
      })),
    );
  });

  it("üst yol tümüyle seçiliyken alt yol onu daraltmaz", () => {
    expect(buildTrie(["a", "a.b"])).toEqual({ a: true });
    expect(buildTrie(["a.b", "a"])).toEqual({ a: true });
  });

  it("olmayan alanı yok sayar", () => {
    expect(projectFields({ a: 1 }, ["b", "a"])).toEqual({ a: 1 });
  });

  it("model kontrollü yol prototip zincirine ulaşamaz (prototip kirletme yok)", () => {
    for (const path of ["__proto__.kirli", "a.__proto__.kirli", "constructor.prototype.kirli", "__proto__"]) {
      expect(() => projectFields({ a: { b: 1 } }, [path, "a.b"])).not.toThrow();
      expect(projectFields({ a: { b: 1 } }, [path, "a.b"])).toEqual({ a: { b: 1 } });
    }
    expect(({} as Record<string, unknown>)["kirli"]).toBeUndefined();
    expect(Object.keys(buildTrie(["__proto__.x", "constructor"]))).toEqual([]);
    // miras alınan özellik "alan var" sayılmaz
    expect(projectFields({ a: 1 }, ["toString", "hasOwnProperty", "a"])).toEqual({ a: 1 });
  });
});

describe("boşları atma, tablo biçimi, liste sınırı", () => {
  it("null/boş string/boş dizi/boş nesne atılır; false ve 0 korunur", () => {
    expect(dropEmpty({ a: null, b: "", c: [], d: {}, e: false, f: 0, g: { h: [] } })).toEqual({ e: false, f: 0 });
  });

  it("aynı biçimli nesne dizisi sütunlu tabloya dönüşür ve token azalır", () => {
    const t = tabulateDeep(pods.map((p) => ({ name: p.metadata.name, phase: p.status.phase })));
    expect(t).toEqual({
      columns: ["name", "phase"],
      rows: pods.map((p) => [p.metadata.name, p.status.phase]),
    });
    expect(estimateTokens(JSON.stringify(t))).toBeLessThan(estimateTokens(JSON.stringify(pods.map((p) => ({ name: p.metadata.name, phase: p.status.phase })))));
  });

  it("tek öğeli veya çok sütunlu diziyi tabloya çevirmez", () => {
    expect(tabulateDeep([{ a: 1 }])).toEqual([{ a: 1 }]);
    const wide = [Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`c${i}`, i])), Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`c${i}`, i]))];
    expect(Array.isArray(tabulateDeep(wide))).toBe(true);
  });

  it("uzun listeyi toplam/gösterilen bilgisiyle sarar", () => {
    expect(clampListsDeep([1, 2, 3, 4, 5], 2)).toEqual({ _total: 5, _shown: 2, items: [1, 2] });
  });

  it("tablo satırlarını sınırlar ve toplamı bildirir", () => {
    const out = clampListsDeep({ columns: ["a"], rows: [[1], [2], [3], [4]] }, 2) as { rows: unknown[]; _total: number; _shown: number };
    expect(out.rows).toHaveLength(2);
    expect(out._total).toBe(4);
    expect(out._shown).toBe(2);
  });
});

describe("log kümeleme", () => {
  const logs = (() => {
    const lines: string[] = [];
    for (let i = 0; i < 400; i++) {
      lines.push(`2026-03-01T10:${String(i % 60).padStart(2, "0")}:00Z INFO request id=${i} took ${i * 3}ms from 10.0.1.${i % 250}`);
    }
    for (let i = 0; i < 120; i++) lines.push(`2026-03-01T11:00:${String(i % 60).padStart(2, "0")}Z ERROR db connection refused host=db-${i % 3} port=5432`);
    lines.push("2026-03-01T11:05:00Z WARN slow query 1200ms");
    lines.push("2026-03-01T11:05:01Z FATAL panic: out of memory");
    return lines.join("\n");
  })();

  it("normalizasyon zaman, sayı, ip ve uuid'yi yer tutucuya çevirir", () => {
    expect(normalizeLogLine("2026-03-01T10:00:00Z INFO id=42 ip=10.1.2.3 u=3f2b8c1e-9a4d-4e7b-8f21-0c5d6e7a8b9c")).toBe(
      "INFO id=<n> ip=<ip> u=<uuid>",
    );
  });

  it("500+ satırı az sayıda kümeye indirir; hata kümeleri önce gelir", () => {
    const v = clusterLogLines(logs);
    expect(v.lines).toBe(522);
    expect(v.clusters.length).toBeLessThanOrEqual(15);
    expect(v.clusters[0]?.severity).toBe("error");
    const err = v.clusters.find((c) => c.pattern.includes("connection refused"));
    expect(err?.n).toBe(120);
    expect(v.tail.at(-1)).toContain("panic");
    expect(estimateTokens(JSON.stringify(v))).toBeLessThan(estimateTokens(logs) / 10);
  });
});

describe("token tavanına sığdırma", () => {
  it("sığıyorsa dokunmaz", () => {
    const r = fitToTokens({ a: 1 }, 100);
    expect(r).toMatchObject({ view: { a: 1 }, byReference: false, truncated: false });
  });

  it("büyük listeyi yarılayarak sığdırır ve kesildiğini bildirir", () => {
    const big = Array.from({ length: 400 }, (_, i) => ({ id: i, ad: `kalem-${i}`, not: "x".repeat(40) }));
    const r = fitToTokens(tabulateDeep(big), 400);
    expect(r.byReference).toBe(false);
    expect(r.truncated).toBe(true);
    expect(r.tokens).toBeLessThanOrEqual(400);
    expect(r.text).toContain("_total");
  });

  it("hiçbir kırpma sığdırmazsa referansla döner", () => {
    const hostile = Object.fromEntries(Array.from({ length: 800 }, (_, i) => [`anahtar_${i}`, i]));
    const r = fitToTokens(hostile, 50);
    expect(r.byReference).toBe(true);
    expect(r.view).toBeUndefined();
    expect(r.truncated).toBe(true);
  });
});

describe("compactForModel", () => {
  it("varsayılan alanlar + dropEmpty + tablo; token tavanına uyar", () => {
    const r = compactForModel(pods, {
      projection: { defaultFields: ["metadata.name", "status.phase"], selectable: true },
      maxTokens: 500,
      maxItems: 50,
    });
    expect(r.byReference).toBe(false);
    expect(r.view).toEqual({
      columns: ["metadata", "status"],
      rows: pods.map((p) => [{ name: p.metadata.name }, { phase: p.status.phase }]),
    });
  });

  it("select yalnız selectable ise alan kümesini genişletir", () => {
    const sel = ["metadata.name", "status.podIP"];
    const open = compactForModel(pods, { projection: { defaultFields: ["metadata.name"], selectable: true }, select: sel, maxTokens: 800, maxItems: 50 });
    const closed = compactForModel(pods, { projection: { defaultFields: ["metadata.name"], selectable: false }, select: sel, maxTokens: 800, maxItems: 50 });
    expect(open.text).toContain("podIP");
    expect(closed.text).not.toContain("podIP");
  });

  it("çok satırlı string loga kümeleme uygular", () => {
    const text = Array.from({ length: 30 }, (_, i) => `INFO tick ${i}`).join("\n");
    const r = compactForModel(text, { maxTokens: 800, maxItems: 20 });
    expect((r.view as { kind: string }).kind).toBe("log");
  });
});
