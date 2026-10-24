import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { detectSandbox, UnsafeDirectRunner } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import type { ExecTemplate } from "@ops/broker";
import { makeCanary } from "@ops/testkit";
import { makeK8sHarness } from "./harness.ts";

const TEMPLATE: ExecTemplate = {
  id: "e2e-plugin",
  description: "e2e",
  binary: "e2e-cloud-plugin",
  prefix: ["token"],
  flags: [{ flag: "--cluster-id", alias: "-i", value: /^[a-z0-9-]{1,40}$/, required: true }],
  env: [],
  ambient: { defaultEnv: [], optInEnv: [], homeFiles: [] },
  network: "none",
};

describe("Kubernetes adapter + exec kimlik eklentisi (uçtan uca)", () => {
  let dir: string;
  let home: string;
  let binary: string;
  let real: Sandbox | null = null;
  const apiToken = makeCanary("e2e-api-token").value;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-e2e-plugin-"));
    home = await mkdtemp(join(tmpdir(), "ops-e2e-home-"));
    binary = join(dir, "e2e-cloud-plugin");
    await writeFile(
      binary,
      `#!/bin/sh\nprintf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s","expirationTimestamp":"2099-01-01T00:00:00Z"}}' '${apiToken}'\n`,
    );
    await chmod(binary, 0o755);
    real = await detectSandbox();
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  });

  const run = async (sandbox: Sandbox | null) => {
    const h = await makeK8sHarness({
      kubeToken: apiToken,
      exec: { template: TEMPLATE, binaryPath: binary, args: ["token", "-i", "demo"], sandbox, homeDir: home },
    });
    return h;
  };

  it("eklenti token üretir; araçlar bu kimlikle çalışır; token hiçbir kanala sızmaz", async () => {
    const sandbox = real ?? new UnsafeDirectRunner({ acknowledgeNoIsolation: true });
    const h = await run(sandbox);
    try {
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status, r.summary).toBe("ok");
      expect(h.api.requests.every((q) => q.bearer === apiToken)).toBe(true);
      const logs = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-7d9c-a1", since: "30m" });
      const sink = await h.sinkFor([r, logs]);
      sink.push("tum-kanallar", JSON.stringify(h.profile));
      expect(sink.leaks([...h.allCanaries, { label: "api-token", value: apiToken }])).toEqual([]);
    } finally {
      await h.stop();
    }
  });

  it("sandbox yoksa araç çağrısı güvenli biçimde hata verir; API'ye hiç istek gitmez", async () => {
    const h = await run(null);
    try {
      const r = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/sandbox/i);
      expect(h.api.requests.length).toBe(0);
    } finally {
      await h.stop();
    }
  });

  it("doktor exec profilinde de çalışır (eklenti → kimlik yankısı → RBAC)", async () => {
    const sandbox = real ?? new UnsafeDirectRunner({ acknowledgeNoIsolation: true });
    const h = await run(sandbox);
    try {
      const lease = await h.broker.acquire({ profile: h.profile, purpose: "doctor", callId: "d", ttlSec: 30 }, h.known);
      const rep = await h.adapter.doctor!(lease.handle, h.profile);
      await lease.release();
      expect(rep).toMatchObject({ connected: true, pinOk: true, bindable: true, effectiveClass: "read" });
    } finally {
      await h.stop();
    }
  });
});
