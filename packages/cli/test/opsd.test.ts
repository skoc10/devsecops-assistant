import { createConnection } from "node:net";
import { stat } from "node:fs/promises";
import { dirname } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider, say } from "@ops/testkit";
import type { OrchestratorEvent } from "@ops/core";
import { Opsd, OpsdClient } from "../src/index.ts";
import { e01Script, makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

describe("opsd (UDS)", () => {
  let fx: Fixture;
  let d: Opsd;
  let shutdown = false;
  beforeEach(async () => {
    fx = await makeFixture();
    shutdown = false;
  });
  afterEach(async () => {
    await d?.close();
    await fx.cleanup();
  });
  const start = async (provider: ScriptedProvider) => {
    d = new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(provider), socketPath: fx.rt.paths.socket, onShutdown: () => (shutdown = true) });
    await d.listen();
    return OpsdClient.connect(fx.rt.paths.socket);
  };

  it("soket 0600, dizin 0700 (yalnız aynı kullanıcı)", async () => {
    const c = await start(new ScriptedProvider([say("x")]));
    expect((await stat(fx.rt.paths.socket)).mode & 0o777).toBe(0o600);
    expect((await stat(dirname(fx.rt.paths.socket))).mode & 0o777).toBe(0o700);
    expect(await c.ping()).toMatchObject({ pong: true });
    c.close();
  });

  it("profil listele/bağla, sohbet akışı, kullanım raporu", async () => {
    const c = await start(new ScriptedProvider(e01Script(), { trustZone: "local" }));
    expect((await c.profiles())[0]).toMatchObject({ id: "payments-sbx", bound: false });
    const rep = await c.bind("payments-sbx");
    expect(rep.bindable).toBe(true);
    expect((await c.profiles())[0]).toMatchObject({ bound: true });
    const ev: OrchestratorEvent[] = [];
    for await (const e of c.send("api neden çöküyor?")) ev.push(e);
    expect(ev.at(-1)).toMatchObject({ type: "final" });
    expect(ev.filter((e) => e.type === "tool_result").length).toBe(4);
    expect(await c.usage()).toContain("Model çağrısı: 4");
    c.close();
  });

  it("aynı anda tek sohbet: ikinci chat.send 'busy' döner", async () => {
    let release: (() => void) | undefined;
    const slow = new ScriptedProvider([
      () => {
        throw new Error("kullanılmamalı");
      },
    ]);
    const gate = new Promise<void>((r) => (release = r));
    const orig = slow.generate.bind(slow);
    slow.generate = async (req) => {
      await gate;
      void orig;
      return say("bitti");
    };
    const c1 = await start(slow);
    const c2 = await OpsdClient.connect(fx.rt.paths.socket);
    const first = (async () => {
      const ev: OrchestratorEvent[] = [];
      for await (const e of c1.send("uzun")) ev.push(e);
      return ev;
    })();
    await new Promise((r) => setTimeout(r, 50));
    const second: OrchestratorEvent[] = [];
    for await (const e of c2.send("ikinci")) second.push(e);
    expect(second[0]).toMatchObject({ type: "error", code: "busy" });
    release?.();
    expect((await first).at(-1)).toMatchObject({ type: "final" });
    c1.close();
    c2.close();
  });

  it("geçersiz istek ve bilinmeyen yöntem reddedilir; sunucu ayakta kalır", async () => {
    const c = await start(new ScriptedProvider([say("x")]));
    const raw = createConnection(fx.rt.paths.socket);
    const lines: string[] = [];
    raw.on("data", (b) => lines.push(...b.toString().split("\n").filter(Boolean)));
    raw.write('{"id":1,"method":"fs.rm","params":{"path":"/"}}\n');
    raw.write("json değil\n");
    raw.write('{"id":2,"method":"ping","extra":true}\n');
    await new Promise((r) => setTimeout(r, 100));
    expect(lines.map((l) => JSON.parse(l).error?.code)).toEqual(["bad_request", "internal", "bad_request"]);
    expect(lines.map((l) => JSON.parse(l).id)).toEqual([1, -1, 2]);
    raw.destroy();
    expect(await c.ping()).toMatchObject({ pong: true });
    c.close();
  });

  it("S-16: onay/araç çağırma yöntemi bu soketten sunulmaz (yalnız sohbet ve yönetim)", async () => {
    const c = await start(new ScriptedProvider([say("x")]));
    await expect(c.call("tool.invoke", { tool: "k8s.resources.list" })).rejects.toThrow(/bad_request/);
    await expect(c.call("approval.grant", { id: "x" })).rejects.toThrow(/bad_request/);
    c.close();
  });

  it("shutdown isteği geri çağrıyı tetikler; kapanışta soket dosyası silinir", async () => {
    const c = await start(new ScriptedProvider([say("x")]));
    await c.call("shutdown");
    expect(shutdown).toBe(true);
    c.close();
    await d.close();
    await expect(stat(fx.rt.paths.socket)).rejects.toThrow();
  });
});
