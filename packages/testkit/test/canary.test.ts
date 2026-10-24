import { describe, expect, it } from "vitest";
import { CaptureSink, canaryVariants, findCanary, makeCanary } from "../src/index.ts";

describe("canary", () => {
  it("her çağrıda farklı, biçimi kodlamada değişen değer üretir", () => {
    const a = makeCanary();
    const b = makeCanary();
    expect(a.value).not.toBe(b.value);
    expect(encodeURIComponent(a.value)).not.toBe(a.value);
  });

  it("ham, base64, url, hex ve json biçimlerini yakalar", () => {
    const c = makeCanary("token");
    for (const v of canaryVariants(c)) {
      expect(findCanary(`önce ${v.needle} sonra`, c), v.name).not.toBeNull();
    }
  });

  it("başka bir metne gömülü base64'ü hizalamadan bağımsız yakalar", () => {
    const c = makeCanary("tok");
    for (const prefix of ["", "a", "ab"]) {
      const blob = Buffer.from(prefix + c.value + "tail").toString("base64");
      expect(findCanary(blob, c), `prefix=${prefix.length}`).not.toBeNull();
    }
  });

  it("bölünmüş/birleştirilmiş sızıntıyı yakalar", () => {
    const c = makeCanary("x");
    const mid = Math.floor(c.value.length / 2);
    const split = `"${c.value.slice(0, mid)}" + "${c.value.slice(mid)}"`;
    expect(findCanary(split, c)).toBe("split-or-concatenated");
  });

  it("temiz metinde bulgu yok", () => {
    expect(findCanary("pod payments-api-7d9 CrashLoopBackOff", makeCanary())).toBeNull();
  });
});

describe("CaptureSink", () => {
  it("kanal bazında toplar; sızıntı raporu değeri içermez", () => {
    const c = makeCanary("kubeconfig");
    const sink = new CaptureSink();
    sink.push("model", "temiz istek");
    sink.push("audit", { alan: "değer" });
    expect(sink.leaks([c])).toEqual([]);
    sink.push("ui", `ekranda ${c.value}`);
    const leaks = sink.leaks([c]);
    expect(leaks).toHaveLength(1);
    expect(leaks[0]?.channel).toBe("ui");
    expect(JSON.stringify(leaks)).not.toContain(c.value);
    expect(() => sink.assertNoCanary([c])).toThrow(/ui:kubeconfig/);
    expect(() => sink.assertNoCanary([c], ["model", "audit"])).not.toThrow();
  });

  it("Uint8Array ve nesneleri serileştirir", () => {
    const c = makeCanary();
    const sink = new CaptureSink();
    sink.push("bin", new TextEncoder().encode(c.value));
    sink.push("obj", { a: [c.value] });
    expect(sink.leaks([c]).map((l) => l.channel).sort()).toEqual(["bin", "obj"]);
  });
});
