import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider, say } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

describe("güvenlik kipleri fail-open olmaz (inceleme bulgusu)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
  });
  afterEach(async () => {
    await fx.cleanup().catch(() => undefined);
  });

  const io = () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    return { io: { input, output, error }, out: () => o.join(""), err: () => e.join("") };
  };
  const run = async (argv: string[], env: Record<string, string> = {}, extra: Record<string, unknown> = {}) => {
    const p = io();
    p.io.input.end();
    const code = await runCli({ argv, env, io: p.io, paths: fx.rt.paths, store: fx.store, sandbox: null, ...extra });
    return { code, out: p.out(), err: p.err() };
  };

  it("OPS_EGRESS yazım hatası (local_only) sessizce normal kipe DÜŞMEZ: açık hata", async () => {
    const r = await run(["chat", "--embedded"], { OPS_EGRESS: "local_only" }, { provider: new ScriptedProvider([say("x")], { trustZone: "third-party-cloud" }) });
    expect(r.code).toBe(2);
    expect(r.err).toContain("OPS_EGRESS");
  });

  it("opsd local-only DEĞİLKEN `ops chat --local-only` (veya OPS_EGRESS=local-only) sohbeti BAŞLATMAZ; karantina uyuşmazlığı da", async () => {
    const stop = new AbortController();
    const p = io();
    const running = runCli({ argv: ["daemon"], env: {}, io: p.io, paths: fx.rt.paths, store: fx.store, sandbox: null, provider: new ScriptedProvider([say("m")], { trustZone: "local" }), stop: stop.signal });
    for (let i = 0; i < 100 && !p.out().includes("dinliyor"); i++) await new Promise((r) => setTimeout(r, 20));
    try {
      const a = await run(["chat", "--local-only"]);
      expect(a.code).toBe(1);
      expect(a.err).toContain("local_only");
      expect(a.err).toContain("ops daemon --local-only");
      const b = await run(["chat"], { OPS_EGRESS: "local-only" });
      expect(b.err).toContain("local_only");
      const c = await run(["chat", "--quarantine", "digest"]);
      expect(c.err).toContain("karantina kipi");
      // istek yoksa uyuşmazlık da yok: sohbet normal açılır
      const d = await run(["chat"]);
      expect(d.err).toBe("");
    } finally {
      stop.abort();
      await running;
    }
  });

  it("opsd local-only + karantina ile açıldıysa uyumlu istemci bağlanır", async () => {
    const stop = new AbortController();
    const p = io();
    const running = runCli({ argv: ["daemon", "--local-only", "--quarantine", "digest"], env: {}, io: p.io, paths: fx.rt.paths, store: fx.store, sandbox: null, provider: new ScriptedProvider([say("m")], { trustZone: "local" }), stop: stop.signal });
    for (let i = 0; i < 100 && !p.out().includes("dinliyor"); i++) await new Promise((r) => setTimeout(r, 20));
    try {
      const ok = await run(["chat", "--local-only", "--quarantine", "digest"]);
      expect(ok.err).toBe("");
      expect(ok.code).toBe(0);
    } finally {
      stop.abort();
      await running;
    }
  });
});
