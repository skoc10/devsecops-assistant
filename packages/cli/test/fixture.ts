import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemorySecretStore } from "@ops/broker";
import type { ScriptStep } from "@ops/testkit";
import { CaptureSink, FakeK8sApi, buildKubeconfig, generateTestPki, makeCanary, seedPaymentsOutage } from "@ops/testkit";
import type { Canary, TestPki } from "@ops/testkit";
import { createRuntime, resolvePaths } from "../src/index.ts";
import type { Runtime } from "../src/index.ts";

export interface Fixture {
  readonly home: string;
  readonly pki: TestPki;
  readonly api: FakeK8sApi;
  readonly canaries: Record<"kubeToken" | "secretData" | "configToken" | "envPassword" | "logSecret" | "eventSecret", Canary>;
  readonly all: Canary[];
  readonly rt: Runtime;
  readonly store: MemorySecretStore;
  readonly kubeconfigPath: string;
  readonly kubeconfigText: string;
  cleanup(): Promise<void>;
}

/** Sahte küme + izole OPS_HOME + bileşim kökü. Depoda secret yok: hepsi çalışma anında üretilir. */
export async function makeFixture(opts: { addProfile?: boolean } = {}): Promise<Fixture> {
  const home = await mkdtemp(join(tmpdir(), "ops-cli-"));
  const pki = await generateTestPki();
  const canaries = {
    kubeToken: makeCanary("kube-token"),
    secretData: makeCanary("secret-data"),
    configToken: makeCanary("config-token"),
    envPassword: makeCanary("env-password"),
    logSecret: makeCanary("log-secret"),
    eventSecret: makeCanary("event-secret"),
  };
  const api = await FakeK8sApi.start({ pki, token: canaries.kubeToken.value });
  seedPaymentsOutage(api, canaries);
  const kubeconfigText = buildKubeconfig({ server: api.url, caPem: pki.caPem, token: canaries.kubeToken.value, namespace: "payments" });
  const kubeconfigPath = join(home, "kubeconfig.yaml");
  await writeFile(kubeconfigPath, kubeconfigText, { mode: 0o600 });
  const store = new MemorySecretStore();
  const rt = await createRuntime({ paths: resolvePaths(join(home, "ops")), store, sandbox: null });
  if (opts.addProfile !== false) {
    await rt.profiles.addKubeconfig({ id: "payments-sbx", environment: "sandbox", kubeconfigText, allowedScopes: ["payments"], displayName: "Payments sandbox" });
  }
  return {
    home,
    pki,
    api,
    canaries,
    all: Object.values(canaries),
    rt,
    store,
    kubeconfigPath,
    kubeconfigText,
    async cleanup() {
      await rt.close();
      await api.stop();
      await rm(home, { recursive: true, force: true });
    },
  };
}

export const idsIn = (messages: readonly { role: string; content?: string }[]): string[] => [
  ...new Set(messages.filter((m) => m.role === "tool").flatMap((m) => [...(m.content ?? "").matchAll(/"id":"(ev-\d+)"/g)].map((x) => x[1] as string))),
];

/** Faz 0 kabul senaryosu (E-01) için betik: skill yükle → sağlık → olaylar+log (paralel) → atıflı cevap. */
export function e01Script(): ScriptStep[] {
  return [
    { message: { content: "", toolCalls: [{ id: "c1", name: "skill.load", args: { name: "kubernetes" } }] }, usage: { inputTokens: 0, outputTokens: 10, cacheReadTokens: 0 }, stopReason: "tool_use" },
    { message: { content: "", toolCalls: [{ id: "c2", name: "k8s.workload.health", args: { kind: "Deployment", name: "api", namespace: "payments" } }] }, usage: { inputTokens: 0, outputTokens: 10, cacheReadTokens: 0 }, stopReason: "tool_use" },
    {
      message: {
        content: "",
        toolCalls: [
          { id: "c3", name: "k8s.events.list", args: { namespace: "payments", since: "2h", type: "Warning" } },
          { id: "c4", name: "k8s.pods.logs", args: { namespace: "payments", pod: "api-7d9c-a1", previous: true, since: "1h", tailLines: 100 } },
        ],
      },
      usage: { inputTokens: 0, outputTokens: 20, cacheReadTokens: 0 },
      stopReason: "tool_use",
    },
    (req) => {
      const ids = idsIn(req.messages);
      const health = ids[1] ?? "ev-2";
      return {
        message: {
          content: `payments/api: 2 replikanın ikisi de CrashLoopBackOff, kapsayıcı bellek sınırı nedeniyle OOMKilled oluyor [${health}]. Olaylar [${ids[2]}] ve önceki log [${ids[3]}] bunu doğruluyor.\nÖneri: spec.template.spec.containers[0].resources.limits.memory değerini 128Mi'den yükseltin (örn. 512Mi) ve rollout'u izleyin. Uygulamayı siz yapın.`,
          toolCalls: [],
        },
        usage: { inputTokens: 0, outputTokens: 80, cacheReadTokens: 0 },
        stopReason: "end",
      };
    },
  ];
}

export async function allChannels(fx: Fixture, extra: Record<string, string> = {}): Promise<CaptureSink> {
  const sink = new CaptureSink();
  const { readFile } = await import("node:fs/promises");
  sink.push("audit", await readFile(fx.rt.paths.auditLog, "utf8").catch(() => ""));
  for (const e of fx.rt.evidence.all()) sink.push("evidence", e.text);
  for (const [k, v] of Object.entries(extra)) sink.push(k, v);
  return sink;
}
