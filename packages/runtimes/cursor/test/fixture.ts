import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemorySecretStore } from "@ops/broker";
import type { ActiveSkill } from "@ops/core";
import { FakeK8sApi, buildKubeconfig, generateTestPki, makeCanary, seedPaymentsOutage } from "@ops/testkit";
import type { Canary } from "@ops/testkit";
import { createRuntime, resolvePaths } from "@ops/cli";
import type { Runtime } from "@ops/cli";

export interface RuntimeFixture {
  readonly rt: Runtime;
  readonly all: Canary[];
  readonly kubernetesSkill: ActiveSkill;
  cleanup(): Promise<void>;
}

export async function makeFixtureForRuntime(): Promise<RuntimeFixture> {
  const home = await mkdtemp(join(tmpdir(), "ops-cursor-"));
  const pki = await generateTestPki();
  const c = {
    kubeToken: makeCanary("kube-token"),
    secretData: makeCanary("secret-data"),
    configToken: makeCanary("config-token"),
    envPassword: makeCanary("env-password"),
    logSecret: makeCanary("log-secret"),
    eventSecret: makeCanary("event-secret"),
  };
  const api = await FakeK8sApi.start({ pki, token: c.kubeToken.value });
  seedPaymentsOutage(api, c);
  const rt = await createRuntime({ paths: resolvePaths(join(home, "ops")), store: new MemorySecretStore(), sandbox: null });
  const kubeconfigText = buildKubeconfig({ server: api.url, caPem: pki.caPem, token: c.kubeToken.value, namespace: "payments" });
  await writeFile(join(home, "kc.yaml"), kubeconfigText, { mode: 0o600 });
  await rt.profiles.addKubeconfig({ id: "payments-sbx", environment: "sandbox", kubeconfigText, allowedScopes: ["payments"] });
  const sk = rt.skills.get("kubernetes");
  if (!sk) throw new Error("kubernetes skill yok");
  return {
    rt,
    all: Object.values(c),
    kubernetesSkill: { name: sk.name, tier: sk.tier, body: sk.body, tokens: sk.tokens, toolsets: sk.sidecar.requests.toolsets },
    async cleanup() {
      await rt.close();
      await api.stop();
      await rm(home, { recursive: true, force: true });
    },
  };
}
