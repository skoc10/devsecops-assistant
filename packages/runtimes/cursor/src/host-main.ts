// cursor-host: OS sandbox İÇİNDE, ayrı süreçte çalışır. Bağımlılıksızdır (yalnız Node + SDK).
// Tek taşıdığı sır Cursor API anahtarıdır ve ilk stdin mesajıyla gelir (env/argv'de değil).
import { createInterface } from "node:readline";
import { buildCursorLaunchOptions } from "./launch.ts";
import { mapSdkMessage } from "./map.ts";
import type { HostToParent, ParentToHost } from "./protocol.ts";
import type { CursorRun, CursorSdk } from "./sdk.ts";

const send = (m: HostToParent): void => {
  process.stdout.write(`${JSON.stringify(m)}\n`);
};

const waiters = new Map<string, (r: { text: string; isError: boolean }) => void>();
let run: CursorRun | undefined;
let started = false;

async function main(first: ParentToHost): Promise<void> {
  if (first.t !== "task") throw new Error("ilk mesaj 'task' olmalı");
  const sdkPath = process.env["OPS_CURSOR_SDK_MODULE"] ?? "@cursor/sdk";
  let sdk: CursorSdk;
  try {
    sdk = (await import(sdkPath)) as CursorSdk;
  } catch {
    throw new Error("Cursor SDK yüklenemedi (OPS_CURSOR_SDK_MODULE / @cursor/sdk)");
  }
  let seq = 0;
  const tools = first.tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
    execute: (args: unknown): Promise<string> =>
      new Promise<string>((resolve) => {
        const id = `h${++seq}`;
        waiters.set(id, (r) => resolve(r.text));
        send({ t: "tool_request", id, name: t.name, args });
      }),
  }));
  const opts = buildCursorLaunchOptions({
    ...(first.apiKey ? { apiKey: first.apiKey } : {}),
    model: first.model,
    system: first.system,
    cwd: first.cwd,
    tools,
  });
  const agent = await sdk.Agent.create(opts);
  const prompt = first.ledgerSummary ? `${first.ledgerSummary}\n\n${first.prompt}` : first.prompt;
  run = await agent.send(prompt);
  for await (const msg of run.stream()) {
    const ev = mapSdkMessage(msg);
    if (ev) send({ t: "event", event: ev });
  }
  await agent.close();
  send({ t: "done" });
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  let m: ParentToHost;
  try {
    m = JSON.parse(line) as ParentToHost;
  } catch {
    return;
  }
  if (m.t === "tool_result") waiters.get(m.id)?.({ text: m.text, isError: m.isError });
  else if (m.t === "cancel") {
    void run?.cancel().catch(() => undefined);
    setTimeout(() => process.exit(0), 100);
  } else if (m.t === "task" && !started) {
    started = true;
    main(m).then(
      () => process.exit(0),
      (e: unknown) => {
        send({ t: "error", message: e instanceof Error ? e.message.slice(0, 300) : "hata" });
        process.exit(1);
      },
    );
  }
});
