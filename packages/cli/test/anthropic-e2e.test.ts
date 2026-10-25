import { chmod, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeCanary } from "@ops/testkit";
import { runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

interface Seen {
  headers: Record<string, string | string[] | undefined>;
  body: any;
  raw: string;
}
type Step = (body: any) => unknown[] | { content: unknown[]; stop?: string };

const evIds = (body: any): string[] => {
  const blocks: any[] = (body.messages as any[]).flatMap((m) => (Array.isArray(m.content) ? m.content : []));
  return [...new Set(blocks.filter((b) => b.type === "tool_result").flatMap((b) => [...String(b.content).matchAll(/"id":"(ev-\d+)"/g)].map((x) => x[1] as string)))];
};
const tu = (id: string, name: string, input: unknown) => ({ type: "tool_use", id, name, input });
const THINKING = { type: "thinking", thinking: "", signature: "imza-opak-1" };

const steps = (): Step[] => [
  () => ({ content: [THINKING, tu("toolu_1", "skill__load", { name: "kubernetes" })], stop: "tool_use" }),
  () => ({ content: [tu("toolu_2", "k8s__workload__health", { kind: "Deployment", name: "api", namespace: "payments" })], stop: "tool_use" }),
  () => ({
    content: [
      tu("toolu_3", "k8s__events__list", { namespace: "payments", since: "2h", type: "Warning" }),
      tu("toolu_4", "k8s__pods__logs", { namespace: "payments", pod: "api-7d9c-a1", previous: true, since: "1h", tailLines: 100 }),
    ],
    stop: "tool_use",
  }),
  (body) => {
    const ids = evIds(body);
    return [{ type: "text", text: `Kök neden: OOMKilled [${ids[1]}], olaylar [${ids[2]}], önceki log [${ids[3]}]. Bellek sınırını artırın; uygulama sizde.` }];
  },
];

describe("Anthropic sağlayıcı + gerçek HTTP + CLI (E-01 üçüncü ayak)", () => {
  let fx: Fixture;
  let server: Server;
  let url = "";
  let seen: Seen[] = [];
  let script: Step[] = [];
  const apiKey = "sk-ant-" + makeCanary("anthropic-key").value;

  const start = async (): Promise<void> => {
    seen = [];
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (b: Buffer) => chunks.push(b));
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        const body = JSON.parse(raw || "{}");
        seen.push({ headers: req.headers, body, raw });
        const step = script[Math.min(seen.length - 1, script.length - 1)]!;
        const r = step(body);
        const content = Array.isArray(r) ? r : r.content;
        const stop = Array.isArray(r) ? "end_turn" : (r.stop ?? "end_turn");
        res.writeHead(200, { "content-type": "application/json", "request-id": "req_x" });
        res.end(
          JSON.stringify({
            id: `msg_${seen.length}`,
            type: "message",
            role: "assistant",
            model: "claude-opus-5-5",
            content,
            stop_reason: stop,
            stop_sequence: null,
            usage: { input_tokens: 40, output_tokens: 12, cache_creation_input_tokens: 0, cache_read_input_tokens: seen.length > 1 ? 300 : 0 },
          }),
        );
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  };

  beforeEach(async () => {
    fx = await makeFixture();
    script = steps();
    await start();
    await fx.rt.close();
  });
  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
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
      env: { OPS_PROVIDER: "anthropic", OPS_PROVIDER_BASE_URL: url, ...extraEnv },
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

  it("anahtar kasaya yazılır; sohbet E-01'i tamamlar; düşünme bloğu geri gider; anahtar/canary hiçbir kanala sızmaz", async () => {
    const keyFile = join(fx.home, "key");
    await writeFile(keyFile, apiKey, { mode: 0o600 });
    await chmod(keyFile, 0o600);
    const set = await run(["provider", "set-key", "anthropic"], "", { OPS_PROVIDER_KEY_FILE: keyFile });
    expect(set.code, set.err).toBe(0);
    expect(set.out).not.toContain(apiKey);

    const chat = await run(["chat", "--embedded"], "/use payments-sbx\npayments ns'inde api neden çöküyor?\n/usage\n/quit\n");
    expect(chat.code, chat.err).toBe(0);
    expect(chat.out).toContain("→ k8s.workload.health");
    expect(chat.out).toContain("Kök neden: OOMKilled");
    expect(chat.out).toContain("Model çağrısı: 4");
    expect(seen.length).toBe(4);

    // anahtar yalnız kimlik başlığında; hiçbir gövdede yok
    for (const s of seen) {
      expect(JSON.stringify(s.headers)).toContain(apiKey);
      expect(s.raw.includes(apiKey)).toBe(false);
    }
    // araç adları kodlanmış, araç sırası kararlı (önek önbelleği), düşünme bloğu ikinci istekte DEĞİŞMEDEN döner
    const names = (b: any): string[] => b.tools.map((t: any) => t.name);
    expect(names(seen[0]!.body)).toEqual(["evidence__get", "evidence__search", "k8s__profile__describe", "skill__list", "skill__load", "timeline__build"]);
    const asst = seen[1]!.body.messages.find((m: any) => m.role === "assistant");
    expect(asst.content[0]).toEqual(THINKING);
    // paralel araç çağrılarının sonuçları TEK kullanıcı iletisinde
    const last = seen[3]!.body.messages.at(-1);
    expect(last.role).toBe("user");
    expect(last.content.filter((b: any) => b.type === "tool_result").map((b: any) => b.tool_use_id)).toEqual(["toolu_3", "toolu_4"]);
    // önbellek okuması /usage'a yansır
    expect(chat.out).toMatch(/önbellek/i);

    const wire = seen.map((s) => s.raw).join("\n");
    const audit = await readFile(fx.rt.paths.auditLog, "utf8");
    for (const c of [...fx.all, { label: "api-key", value: apiKey }]) {
      for (const [name, text] of [["wire", wire], ["audit", audit], ["ui", chat.out + chat.err]] as const) {
        expect(text.includes(c.value), `${c.label} → ${name}`).toBe(false);
      }
    }
    expect(audit).toContain('"provider":"anthropic"');
    expect(audit).toContain('"model":"claude-opus-5-5"');
  });

  it("anahtar kasada yoksa açık hata; geçersiz effort/bölge reddedilir", async () => {
    expect((await run(["chat", "--embedded"], "")).err).toContain("Anthropic API anahtarı");
    const keyFile = join(fx.home, "key");
    await writeFile(keyFile, apiKey, { mode: 0o600 });
    await run(["provider", "set-key", "anthropic"], "", { OPS_PROVIDER_KEY_FILE: keyFile });
    expect((await run(["chat", "--embedded"], "", { OPS_ANTHROPIC_EFFORT: "çılgın" })).err).toContain("OPS_ANTHROPIC_EFFORT");
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER_ZONE: "mars" })).err).toContain("OPS_PROVIDER_ZONE");
    expect((await run(["chat", "--embedded"], "", { OPS_PROVIDER_BASE_URL: "http://uzak.invalid" })).err).toContain("https");
  });

  it("S-13: Secret listesi (secret-adjacent) uzak bölge sağlayıcısına GİTMEZ; yerel bölgede çalışır", async () => {
    const keyFile = join(fx.home, "key");
    await writeFile(keyFile, apiKey, { mode: 0o600 });
    await run(["provider", "set-key", "anthropic"], "", { OPS_PROVIDER_KEY_FILE: keyFile });
    const secretScript: Step[] = [
      () => ({ content: [tu("a", "skill__load", { name: "kubernetes" })], stop: "tool_use" }),
      () => ({ content: [tu("b", "k8s__resources__list", { kind: "Secret", namespace: "payments" })], stop: "tool_use" }),
      () => [{ type: "text", text: "gizli nesneler listelendi" }],
    ];
    script = secretScript;
    const remote = await run(["chat", "--embedded"], "/use payments-sbx\nsecret'ları say\n/quit\n", { OPS_PROVIDER_ZONE: "third-party-cloud" });
    expect(remote.out).toContain("REDDEDİLDİ [no_eligible_provider]");
    expect(fx.api.requests.some((q) => q.path.includes("/secrets"))).toBe(false);
    seen = [];
    const local = await run(["chat", "--embedded"], "/use payments-sbx\nsecret'ları say\n/quit\n", { OPS_PROVIDER_ZONE: "local" });
    expect(local.out).toContain("gizli nesneler listelendi");
  });
});
