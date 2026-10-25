import { createConnection, createServer } from "node:net";
import { link, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ScriptedProvider, say } from "@ops/testkit";
import type { OrchestratorEvent } from "@ops/core";
import { Opsd, OpsdClient } from "../src/index.ts";
import { MAX_SOCKET_PATH_BYTES } from "../src/paths.ts";
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

  it("aynı yolda ikinci opsd: canlı soket DEVRALINMAZ ('zaten çalışıyor'); başlayamayan örneğin close'u soketi silmez", async () => {
    const c = await start(new ScriptedProvider([say("x")]));
    const second = new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(new ScriptedProvider([say("y")])), socketPath: fx.rt.paths.socket });
    await expect(second.listen()).rejects.toMatchObject({ code: "opsd_running", message: expect.stringContaining("opsd zaten çalışıyor") });
    await second.close();
    expect(await c.ping()).toMatchObject({ pong: true });
    const c2 = await OpsdClient.connect(fx.rt.paths.socket); // yeni bağlantılar da ilk daemon'a gider
    expect(await c2.ping()).toMatchObject({ pong: true });
    c.close();
    c2.close();
  });

  it("ölü soket (çökmüş süreç) silinip yeniden dinlenir; soket olmayan dosyaya dokunulmaz", async () => {
    const sock = fx.rt.paths.socket;
    // ölü soket: başka adda dinleyip sabit bağla hedef yola koy, sonra kapat (libuv yalnız kendi adını siler)
    const tmp = join(dirname(sock), "eski.sock");
    const old = createServer();
    await new Promise<void>((r) => old.listen(tmp, () => r()));
    await link(tmp, sock);
    await new Promise<void>((r) => old.close(() => r()));
    expect((await lstat(sock)).isSocket()).toBe(true);
    const c = await start(new ScriptedProvider([say("x")]));
    expect(await c.ping()).toMatchObject({ pong: true });
    c.close();
    await d.close();

    await writeFile(sock, "soket değil");
    const third = new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(new ScriptedProvider([say("z")])), socketPath: sock });
    await expect(third.listen()).rejects.toMatchObject({ code: "socket_path_occupied" });
    expect(await readFile(sock, "utf8")).toBe("soket değil");
  });

  describe("soket yolu ve izinleri", () => {
    let base: string;
    beforeEach(async () => {
      base = await mkdtemp(join(tmpdir(), "ops-uds-"));
    });
    afterEach(async () => {
      await rm(base, { recursive: true, force: true });
    });
    const opsdAt = (socketPath: string): Opsd => new Opsd({ runtime: fx.rt, orchestrator: fx.rt.createOrchestrator(new ScriptedProvider([say("x")])), socketPath });
    const umaskNow = (): number => {
      const m = process.umask(0o022);
      process.umask(m);
      return m;
    };

    it("UDS sınırını aşan yol: sunucu başlamaz (kesik yola bağlanmaz), istemci kesik yolda dinleyen sahteye bağlanmaz", async () => {
      const long = join(base, "d".repeat(MAX_SOCKET_PATH_BYTES), "opsd.sock");
      await expect(opsdAt(long).listen()).rejects.toMatchObject({ code: "socket_path_too_long", message: expect.stringContaining("OPS_HOME") });
      expect(await readdir(base)).toEqual([]); // ne dizin ne 0700 dışında kesik adlı soket
      // libuv yolu keser: sahte dinleyici kesik adda (0700 dizin DIŞINDA) dinler; istemci bağlantı denemez
      let hits = 0;
      const impostor = createServer((s) => {
        hits++;
        s.destroy();
      });
      await new Promise<void>((r) => {
        impostor.once("error", () => r());
        impostor.listen(long, () => r());
      });
      try {
        await expect(OpsdClient.connect(long)).rejects.toMatchObject({ code: "socket_path_too_long" });
        await new Promise((r) => setTimeout(r, 20));
        expect(hits).toBe(0);
      } finally {
        await new Promise<void>((r) => impostor.close(() => r()));
      }
    });

    it("tam sınırdaki yol çalışır: soket 0600 doğar, süreç umask'ı geri yüklenir", async () => {
      const pad = MAX_SOCKET_PATH_BYTES - Buffer.byteLength(join(base, "", "opsd.sock")) - 1;
      expect(pad).toBeGreaterThan(0);
      const exact = join(base, "r".repeat(pad), "opsd.sock");
      expect(Buffer.byteLength(exact)).toBe(MAX_SOCKET_PATH_BYTES);
      const before = umaskNow();
      d = opsdAt(exact);
      await d.listen();
      expect(umaskNow()).toBe(before);
      const st = await lstat(exact);
      expect(st.isSocket()).toBe(true);
      expect(st.mode & 0o777).toBe(0o600);
      expect((await stat(dirname(exact))).mode & 0o777).toBe(0o700);
      const c = await OpsdClient.connect(exact);
      expect(await c.ping()).toMatchObject({ pong: true });
      c.close();
    });

    it("soket dizini sembolik bağsa dinlenmez; istemci bu kullanıcıya ait olmayan/soket olmayan yola bağlanmaz", async () => {
      const target = await mkdtemp(join(base, "hedef-"));
      await symlink(target, join(base, "run"));
      await expect(opsdAt(join(base, "run", "opsd.sock")).listen()).rejects.toMatchObject({ code: "home_insecure" });
      expect(await readdir(target)).toEqual([]);

      await mkdir(join(base, "run2"), { mode: 0o700 });
      await writeFile(join(base, "run2", "opsd.sock"), "soket değil");
      await expect(OpsdClient.connect(join(base, "run2", "opsd.sock"))).rejects.toMatchObject({ code: "socket_insecure" });
    });
  });
});
