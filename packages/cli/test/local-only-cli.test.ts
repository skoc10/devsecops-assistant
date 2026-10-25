import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider, say } from "@ops/testkit";
import { createRuntime, readAuditRecords, runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

describe("egress: local-only (CLI)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup();
  });

  const chat = async (zone: "local" | "tenant-cloud" | "third-party-cloud", flags: string[], env: Record<string, string> = {}) => {
    const input = new PassThrough();
    input.end("/quit\n");
    const io = { input, output: new PassThrough(), error: new PassThrough() };
    const code = await runCli({ argv: ["chat", "--embedded", ...flags], env, io, paths: fx.rt.paths, store: fx.store, sandbox: null, provider: new ScriptedProvider([say("x")], { trustZone: zone }) });
    return { code, out: (io.output.read() as Buffer | null)?.toString() ?? "", err: (io.error.read() as Buffer | null)?.toString() ?? "" };
  };

  it("--local-only veya OPS_EGRESS=local-only: bulut sağlayıcı AÇILIŞTA reddedilir (bağlam hiç gitmez)", async () => {
    for (const zone of ["tenant-cloud", "third-party-cloud"] as const) {
      const a = await chat(zone, ["--local-only"]);
      expect(a.code, zone).toBe(1);
      expect(a.err).toMatch(/local_only: egress: local-only kipinde yalnız yerel/);
      expect(a.err).toContain("OPS_PROVIDER_BASE_URL=http://127.0.0.1"); // ipucu gerçekten okunan değişkeni söyler
      const b = await chat(zone, [], { OPS_EGRESS: "local-only" });
      expect(b.code).toBe(1);
      expect(b.err).toMatch(/local_only/);
    }
  });

  it("yerel sağlayıcıyla açılır; denetime egress=local-only yazılır; kapalıyken bulut sağlayıcı sorunsuz", async () => {
    const ok = await chat("local", ["--local-only"]);
    expect(ok.code, ok.err).toBe(0);
    const recs = await readAuditRecords(fx.rt.paths.auditLog);
    expect(recs.filter((r) => r.event === "session_start").at(-1)?.message).toContain("egress=local-only");
    const normal = await chat("third-party-cloud", []);
    expect(normal.code, normal.err).toBe(0);
    expect((await readAuditRecords(fx.rt.paths.auditLog)).filter((r) => r.event === "session_start").at(-1)?.message).toContain("egress=normal");
  });

  it("local-only runtime: break-glass kapalı (yalnız okuma kipi tavan yükseltmez)", async () => {
    const rt = await createRuntime({ paths: fx.rt.paths, store: fx.store, sandbox: null, localOnly: true });
    try {
      await rt.bindProfile("payments-sbx");
      await expect(rt.breakGlass.start({ profileId: "payments-sbx", ceiling: "mutate", reason: "INC-1 acil ölçekleme gerekli", ttlSec: 600, reauth: { method: "vault-passphrase", verifiedAt: new Date() } })).rejects.toMatchObject({ code: "break_glass_disabled" });
      expect(rt.session.getBound("payments-sbx")?.classCeiling).toBe("read");
    } finally {
      await rt.close();
    }
  });
});
