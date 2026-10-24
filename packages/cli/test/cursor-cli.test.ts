import { dirname, join } from "node:path";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectSandbox } from "@ops/sandbox";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

const here = dirname(fileURLToPath(import.meta.url));
const MOCK = join(here, "..", "..", "runtimes", "cursor", "test", "mock-sdk.mjs");
const real = await detectSandbox();

describe("OPS_PROVIDER=cursor (CLI)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup();
  });
  const run = async (input: string, env: Record<string, string>, sandbox: "detect" | null) => {
    const stdin = new PassThrough();
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    const done = runCli({ argv: ["chat", "--embedded"], env: { OPS_PROVIDER: "cursor", ...env }, io: { input: stdin, output, error }, paths: fx.rt.paths, store: fx.store, sandbox });
    stdin.write(input);
    stdin.end();
    const code = await done;
    return { code, out: o.join(""), err: e.join("") };
  };

  it("yapılandırma hataları açık: model yok, sandbox yok, SDK kurulu değil", async () => {
    expect((await run("", {}, null)).err).toContain("OPS_CURSOR_MODEL");
    expect((await run("", { OPS_CURSOR_MODEL: "m" }, null)).err).toContain("sandbox_unavailable");
    if (real) {
      const r = await run("", { OPS_CURSOR_MODEL: "m" }, "detect");
      expect(r.err).toContain("Cursor SDK kurulu değil");
    }
  });

  (real ? it : it.skip)("spike geçilmediyse TAVSİYE KİPİ uyarısı; geçildiyse araç modu E-01 (sahte SDK, gerçek sandbox)", async () => {
    const advisory = await run("/use payments-sbx\nsoru\n/quit\n", { OPS_CURSOR_MODEL: "m", OPS_CURSOR_SDK_MODULE: MOCK }, "detect");
    expect(advisory.out).toContain("TAVSİYE KİPİ");
    // tavsiye kipinde SDK'nın "araç çağrısı" olarak raporladığı her şey alarmdır; mock 'tools' senaryosu köprü araçlarına başvurur
    const tools = await run("/use payments-sbx\npayments ns'inde api neden çöküyor?\n/quit\n", { OPS_CURSOR_MODEL: "m", OPS_CURSOR_SDK_MODULE: MOCK, OPS_CURSOR_SPIKE_PASSED: "1" }, "detect");
    expect(tools.code, tools.err).toBe(0);
    expect(tools.out).toContain("→ k8s.workload.health");
    expect(tools.out).toContain("✓ ev-");
    expect(tools.out).toContain("OOMKilled");
    const audit = await readFile(fx.rt.paths.auditLog, "utf8");
    expect(audit).toContain('"provider":"cursor"');
    for (const c of fx.all) {
      expect((tools.out + tools.err + audit).includes(c.value), c.label).toBe(false);
    }
  });
});
