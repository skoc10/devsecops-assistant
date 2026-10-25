import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ModelProvider } from "@ops/contracts";
import { ScriptedProvider, say, toolUse } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

/** ScriptedProvider kimliği sabit: kademeleri ayırt etmek için model adı verilir. */
const named = (model: string, inner: ScriptedProvider): ModelProvider => ({ id: "kademe", model, capabilities: inner.capabilities, generate: (req) => inner.generate(req) });

describe("OPS_PROVIDER_SMALL_MODEL: skill model_hint ile kademe yönlendirme (CLI)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture();
    await fx.rt.close();
    const dir = join(fx.rt.paths.userSkillsDir, "ucuz");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "SKILL.md"), "---\nname: ucuz\ndescription: Basit sınıflandırma işleri için küçük model yeter; kullanıcı basit soru sorarsa kullan.\n---\nKısa cevap ver.\n");
    await writeFile(join(dir, "ops.skill.yaml"), "model_hint: small\n");
  });
  afterEach(async () => {
    await fx.cleanup().catch(() => undefined);
  });

  const run = async (env: Record<string, string>, factory: (model: string | undefined) => ModelProvider) => {
    const stdin = new PassThrough();
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    const done = runCli({
      argv: ["chat", "--embedded"],
      env: { OPS_PROVIDER: "x", ...env },
      io: { input: stdin, output, error },
      paths: fx.rt.paths,
      store: fx.store,
      sandbox: null,
      providerFactory: async (ctx) => factory(ctx.env["OPS_PROVIDER_MODEL"]),
    });
    stdin.write("basit bir soru\n/quit\n");
    stdin.end();
    return { code: await done, out: o.join(""), err: e.join("") };
  };

  it("küçük model yapılandırılmışsa ve tek etkin skill 'small' ise ikinci tur küçük modelle yürür", async () => {
    const large = new ScriptedProvider([toolUse([{ name: "skill.load", args: { name: "ucuz" } }])]);
    const small = new ScriptedProvider([say("küçük model cevapladı")]);
    const r = await run({ OPS_PROVIDER_SMALL_MODEL: "ucuz-model" }, (m) => (m === "ucuz-model" ? named("ucuz-model", small) : named("buyuk", large)));
    expect(r.code, r.err).toBe(0);
    expect(r.out).toContain("küçük model cevapladı");
    expect(r.out).toContain("model kademesi değişti");
    expect(large.requests).toHaveLength(1);
    expect(small.requests).toHaveLength(1);
  });

  it("OPS_PROVIDER_SMALL_MODEL yoksa aynı senaryoda tüm turlar ana modelle", async () => {
    const large = new ScriptedProvider([toolUse([{ name: "skill.load", args: { name: "ucuz" } }]), say("büyük model cevapladı")]);
    const r = await run({}, () => named("buyuk", large));
    expect(r.out).toContain("büyük model cevapladı");
    expect(r.out).not.toContain("model kademesi değişti");
    expect(large.requests).toHaveLength(2);
  });
});
