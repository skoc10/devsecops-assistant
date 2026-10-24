import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FakeOpenAiServer, makeCanary, openAiText, openAiToolCalls } from "@ops/testkit";
import type { FakeOpenAiStep } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

const evIds = (req: { messages: { role: string; content: string | null }[] }): string[] => [
  ...new Set(req.messages.filter((m) => m.role === "tool").flatMap((m) => [...(m.content ?? "").matchAll(/"id":"(ev-\d+)"/g)].map((x) => x[1] as string))),
];

const steps = (): FakeOpenAiStep[] => [
  () => openAiToolCalls([{ id: "c1", name: "skill.load", args: { name: "kubernetes" } }]),
  () => openAiToolCalls([{ id: "c2", name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }]),
  () =>
    openAiToolCalls([
      { id: "c3", name: "k8s.events.list", args: { namespace: "payments", since: "2h", type: "Warning" } },
      { id: "c4", name: "k8s.pods.logs", args: { namespace: "payments", pod: "api-7d9c-a1", previous: true, since: "1h", tailLines: 100 } },
    ]),
  (req) => {
    const ids = evIds(req);
    return openAiText(`Kök neden: OOMKilled [${ids[1]}], olaylar [${ids[2]}], önceki log [${ids[3]}]. Bellek sınırını artırın; uygulama sizde.`);
  },
];

describe("OpenAI-uyumlu sağlayıcı + gerçek HTTP + CLI (E-01 gerçek sağlayıcı ayağı)", () => {
  let fx: Fixture;
  let srv: FakeOpenAiServer;
  const apiKey = makeCanary("openai-key").value;
  beforeEach(async () => {
    fx = await makeFixture();
    srv = await FakeOpenAiServer.start(steps());
    await fx.rt.close(); // CLI kendi çalışma zamanını açacak (denetim zinciri tek yazıcıda kalsın)
  });
  afterEach(async () => {
    await srv.stop();
    await fx.cleanup();
  });

  const run = async (argv: string[], input: string, extraEnv: Record<string, string> = {}) => {
    const stdin = new PassThrough();
    const output = new PassThrough();
    const error = new PassThrough();
    const o: string[] = [];
    const e: string[] = [];
    output.on("data", (b: Buffer) => o.push(b.toString()));
    error.on("data", (b: Buffer) => e.push(b.toString()));
    const done = runCli({
      argv,
      env: { OPS_PROVIDER: "openai-compatible", OPS_PROVIDER_BASE_URL: srv.url, OPS_PROVIDER_MODEL: "yerel-model", ...extraEnv },
      io: { input: stdin, output, error },
      paths: fx.rt.paths,
      store: fx.store,
      sandbox: null,
    });
    stdin.write(input);
    stdin.end();
    const code = await done;
    return { code, out: o.join(""), err: e.join("") };
  };

  it("anahtar kasaya yazılır; sohbet gerçek HTTP ile E-01'i tamamlar; canary ve anahtar hiçbir kanala sızmaz", async () => {
    const keyFile = join(fx.home, "key");
    await writeFile(keyFile, apiKey, { mode: 0o600 });
    await chmod(keyFile, 0o600);
    const set = await run(["provider", "set-key", "openai-compatible"], "", { OPS_PROVIDER_KEY_FILE: keyFile });
    expect(set.code, set.err).toBe(0);
    expect(set.out).not.toContain(apiKey);
    expect(Buffer.from((await fx.store.get("provider/openai-compatible"))!).toString()).toBe(apiKey);

    const chat = await run(["chat", "--embedded"], "/use payments-sbx\npayments ns'inde api neden çöküyor?\n/usage\n/quit\n");
    expect(chat.code, chat.err).toBe(0);
    expect(chat.out).toContain("BAĞLANABİLİR");
    expect(chat.out).toContain("→ k8s.workload.health");
    expect(chat.out).toContain("Kök neden: OOMKilled");
    expect(chat.out).toContain("Model çağrısı: 4");

    // sağlayıcıya giden her bayt: anahtar yalnız Authorization başlığında; canary hiçbir yerde
    expect(srv.requests.length).toBe(4);
    expect(srv.requests.every((r) => r.authorization === `Bearer ${apiKey}`)).toBe(true);
    const wire = srv.requests.map((r) => r.raw).join("\n");
    const audit = await readFile(fx.rt.paths.auditLog, "utf8");
    for (const c of [...fx.all, { label: "api-key", value: apiKey }]) {
      for (const [name, text] of [["wire", wire], ["audit", audit], ["ui", chat.out + chat.err]] as const) {
        expect(text.includes(c.value), `${c.label} → ${name}`).toBe(false);
      }
    }
    // araç adları dış sağlayıcıya kodlanmış gider
    expect(srv.requests[0]!.body.tools?.map((t) => t.function.name)).toEqual(["evidence__get", "evidence__search", "k8s__profile__describe", "skill__list", "skill__load"]);
    // model turları denetime sağlayıcı/model/bölge ile yazılmış
    expect(audit).toContain('"provider":"openai-compatible"');
    expect(audit).toContain('"model":"yerel-model"');
  });

  it("anahtar yoksa da yerel (loopback) sağlayıcı çalışır: Authorization gönderilmez", async () => {
    const chat = await run(["chat", "--embedded"], "/use payments-sbx\nsoru\n/quit\n");
    expect(chat.code).toBe(0);
    expect(srv.requests[0]!.authorization).toBeNull();
  });

  it("OPS_PROVIDER yoksa veya yanlışsa açık hata; geçersiz bölge reddedilir", async () => {
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER: "" })).err).toContain("provider_not_configured");
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER: "yok" })).err).toContain("bilinmeyen sağlayıcı");
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER_ZONE: "mars" })).err).toContain("OPS_PROVIDER_ZONE");
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER_BASE_URL: "http://uzak.invalid/v1" })).err).toContain("https");
  });

  it("S-13: hassas bağlamda uzak bölge sağlayıcısı reddedilir; aynı oturum 'local' ile devam eder", async () => {
    // Secret nesneleri secret-adjacent: bağlam yalnız yerel sağlayıcıya gidebilir
    const secretSteps: FakeOpenAiStep[] = [
      () => openAiToolCalls([{ id: "a", name: "skill.load", args: { name: "kubernetes" } }]),
      () => openAiToolCalls([{ id: "b", name: "k8s.resources.list", args: { kind: "Secret", namespace: "payments" } }]),
      () => openAiText("gizli nesneler listelendi"),
    ];
    await srv.stop();
    srv = await FakeOpenAiServer.start(secretSteps);
    const remote = await run(["chat", "--embedded"], "/use payments-sbx\nsecret'ları say\n/quit\n", { OPS_PROVIDER_ZONE: "third-party-cloud" });
    expect(remote.out).toContain("no_eligible_provider");
    expect(srv.requests.length).toBe(2); // Secret listesi sonrası üçüncü model çağrısı YAPILMADI
    await srv.stop();
    srv = await FakeOpenAiServer.start(secretSteps);
    const local = await run(["chat", "--embedded"], "/use payments-sbx\nsecret'ları say\n/quit\n", { OPS_PROVIDER_ZONE: "local" });
    expect(local.out).toContain("gizli nesneler listelendi");
    expect(srv.requests.length).toBe(3);
  });
});
