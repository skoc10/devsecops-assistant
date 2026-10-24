import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KnownSecrets } from "@ops/redaction";
import { detectSandbox, UnsafeDirectRunner } from "@ops/sandbox";
import type { Sandbox, SandboxResult, SandboxSpec } from "@ops/sandbox";
import { CaptureSink, buildKubeconfig, generateTestPki, makeCanary, makeTestProfile } from "@ops/testkit";
import {
  BUILTIN_EXEC_TEMPLATES,
  ExecCredentialRunner,
  LocalBroker,
  MemorySecretStore,
  ProfileRegistry,
  ProfileService,
  ambientFor,
  credentialKey,
  importKubeconfig,
  matchExecSpec,
  parseAmbient,
  parseExecCredential,
} from "../src/index.ts";
import type { ExecTemplate } from "../src/index.ts";

// ---- şablon eşleyici ------------------------------------------------------------------------

const eks = (args: string[], env: { name: string; value: string }[] = [], command = "aws") => matchExecSpec({ command, args, env });

describe("exec şablon eşleyici (T17, S-15)", () => {
  it("gerçek dünya biçimleri kabul edilir", () => {
    expect(eks(["eks", "get-token", "--cluster-name", "prod-1"]).template.id).toBe("aws-eks-get-token");
    expect(eks(["--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod-1", "--output", "json"]).args).toEqual([
      "--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod-1", "--output", "json",
    ]);
    expect(eks(["eks", "get-token", "--cluster-name=prod-1", "--role-arn=arn:aws:iam::123456789012:role/ops-reader"]).args).toContain("--role-arn");
    expect(eks(["eks", "get-token", "--cluster-name", "c"], [{ name: "AWS_PROFILE", value: "dev" }], "/usr/local/bin/aws").env).toEqual({ AWS_PROFILE: "dev" });
    expect(matchExecSpec({ command: "gke-gcloud-auth-plugin", args: [], env: [] }).template.id).toBe("gke-gcloud-auth-plugin");
    expect(matchExecSpec({ command: "kubelogin", args: ["get-token", "--login", "azurecli", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630"], env: [] }).template.id).toBe("kubelogin-get-token");
    expect(matchExecSpec({ command: "aws-iam-authenticator", args: ["token", "-i", "my-cluster"], env: [] }).args).toEqual(["token", "--cluster-id", "my-cluster"]);
  });

  it.each([
    ["bilinmeyen ikili", () => matchExecSpec({ command: "curl", args: ["https://x.invalid"], env: [] })],
    ["farklı alt komut", () => eks(["s3", "ls"])],
    ["zorunlu bayrak yok", () => eks(["eks", "get-token"])],
    ["izin verilmeyen bayrak (--endpoint-url)", () => eks(["eks", "get-token", "--cluster-name", "c", "--endpoint-url", "https://evil.invalid"])],
    ["izin verilmeyen bayrak (--profile sonra değil, --debug)", () => eks(["eks", "get-token", "--cluster-name", "c", "--debug"])],
    ["kabuk metakarakteri değer", () => eks(["eks", "get-token", "--cluster-name", "c; curl evil"])],
    ["komut ikamesi değer", () => eks(["eks", "get-token", "--cluster-name", "$(id)"])],
    ["yinelenen bayrak", () => eks(["eks", "get-token", "--cluster-name", "a", "--cluster-name", "b"])],
    ["fazladan konumsal", () => eks(["eks", "get-token", "--cluster-name", "a", "extra"])],
    ["geçersiz rol ARN", () => eks(["eks", "get-token", "--cluster-name", "a", "--role-arn", "evil"])],
    ["izin verilmeyen env", () => eks(["eks", "get-token", "--cluster-name", "c"], [{ name: "LD_PRELOAD", value: "/tmp/x.so" }])],
    ["env değeri geçersiz", () => eks(["eks", "get-token", "--cluster-name", "c"], [{ name: "AWS_PROFILE", value: "a b;c" }])],
    ["bool bayrağa değer", () => matchExecSpec({ command: "gke-gcloud-auth-plugin", args: ["--use_application_default_credentials=1"], env: [] })],
    ["kubelogin: --cache-dir yok", () => matchExecSpec({ command: "kubelogin", args: ["get-token", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630", "--cache-dir", "/etc"], env: [] })],
  ])("reddedilir: %s", (_n, fn) => {
    expect(fn).toThrow(expect.objectContaining({ code: "kubeconfig_exec_unsupported" }));
  });

  it("hata mesajı değer taşımaz (yalnız bayrak/ad)", () => {
    const c = makeCanary("argv");
    const probes: (() => unknown)[] = [
      () => eks(["eks", "get-token", "--cluster-name", c.value]),
      () => eks(["eks", "get-token", "--cluster-name", "ok", "--token", c.value]),
      () => eks(["eks", "get-token", "--cluster-name", "ok"], [{ name: "AWS_PROFILE", value: c.value }]),
      () => matchExecSpec({ command: c.value, args: [], env: [] }),
    ];
    const sink = new CaptureSink();
    for (const p of probes) {
      try {
        p();
      } catch (e) {
        sink.push("hata", (e as Error).message + JSON.stringify((e as { details?: unknown }).details ?? {}));
      }
    }
    expect(sink.leaks([c])).toEqual([]);
  });

  it("katalogdaki her şablonun kimliği benzersiz ve ağı yalnız gerektiğinde host", () => {
    const ids = BUILTIN_EXEC_TEMPLATES.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of BUILTIN_EXEC_TEMPLATES) {
      expect(t.binary).not.toContain("/");
      expect(t.flags.every((f) => f.value === "bool" || f.value instanceof RegExp)).toBe(true);
    }
  });

  it("ambient: varsayılanlar kimlik içermez; kimlikli env yalnız açık onayla", () => {
    const t = BUILTIN_EXEC_TEMPLATES[0] as ExecTemplate;
    const def = ambientFor(t);
    expect(def).toEqual(expect.arrayContaining(["env:AWS_PROFILE", "home:.aws/config"]));
    expect(def.join(",")).not.toMatch(/ACCESS_KEY|SECRET|SESSION_TOKEN/);
    const opt = ambientFor(t, { optInEnv: ["AWS_ACCESS_KEY_ID", "BASKA_BIR_SEY"], paths: ["/opt/cli"] });
    expect(opt).toContain("env:AWS_ACCESS_KEY_ID");
    expect(opt.join(",")).not.toContain("BASKA_BIR_SEY");
    expect(parseAmbient(opt)).toMatchObject({ paths: ["/opt/cli"] });
  });
});

describe("parseExecCredential", () => {
  const cred = (status: object, over: object = {}) =>
    Buffer.from(JSON.stringify({ apiVersion: "client.authentication.k8s.io/v1", kind: "ExecCredential", status, ...over }));
  it("token + süre", () => {
    const r = parseExecCredential(cred({ token: "abc-def-ghi", expirationTimestamp: "2030-01-01T00:00:00Z" }));
    expect(r.token).toBe("abc-def-ghi");
    expect(r.expiresAt?.toISOString()).toBe("2030-01-01T00:00:00.000Z");
  });
  it("sertifika çifti", () => {
    expect(parseExecCredential(cred({ clientCertificateData: "C", clientKeyData: "K" }))).toMatchObject({ clientCertPem: "C", clientKeyPem: "K" });
  });
  it.each([
    ["JSON değil", Buffer.from("merhaba")],
    ["yanlış tür", cred({ token: "x" }, { kind: "Pod" })],
    ["yanlış apiVersion", cred({ token: "x" }, { apiVersion: "v1" })],
    ["kimlik yok", cred({})],
    ["yarım sertifika", cred({ clientCertificateData: "C" })],
  ])("reddedilir: %s", (_n, b) => {
    expect(() => parseExecCredential(b as Buffer)).toThrow(expect.objectContaining({ code: "exec_output_invalid" }));
  });
});

// ---- çalıştırıcı + broker (gerçek eklenti betiği) -------------------------------------------

const TEST_TEMPLATE: ExecTemplate = {
  id: "test-plugin",
  description: "test eklentisi",
  binary: "fake-cloud-plugin",
  prefix: ["token"],
  flags: [{ flag: "--cluster-id", alias: "-i", value: /^[a-z0-9-]{1,40}$/, required: true }],
  env: [{ name: "FAKE_REGION", value: /^[a-z0-9-]{1,20}$/ }],
  ambient: { defaultEnv: ["FAKE_REGION"], optInEnv: ["FAKE_SECRET"], homeFiles: [".fakecloud"] },
  network: "none",
};
const CATALOG = [TEST_TEMPLATE];

interface Plugin {
  readonly dir: string;
  readonly binary: string;
  readonly home: string;
  setExpiry(iso: string | null): Promise<void>;
  setToken(t: string): Promise<void>;
  setMode(m: "ok" | "probe" | "fail" | "slow" | "garbage"): Promise<void>;
}

async function makePlugin(): Promise<Plugin> {
  const dir = await mkdtemp(join(tmpdir(), "ops-plugin-"));
  const home = await mkdtemp(join(tmpdir(), "ops-plughome-"));
  const binary = join(dir, "fake-cloud-plugin");
  await writeFile(
    binary,
    [
      "#!/bin/sh",
      'd=$(dirname "$0")',
      'mode=$(cat "$d/mode")',
      'tok=$(cat "$d/token")',
      'exp=""; [ -f "$d/expiry" ] && exp=$(cat "$d/expiry")',
      'case "$mode" in',
      '  fail) echo "boom $tok" >&2; exit 3;;',
      '  slow) sleep 30;;',
      '  garbage) echo "not json"; exit 0;;',
      '  probe)',
      '    k=$(cat "$HOME/.kube/config" 2>/dev/null || echo yok)',
      '    f=$(cat "$HOME/.fakecloud/conf" 2>/dev/null || echo yok)',
      '    e=$(env | grep -c "OPS_PLUGIN_HOST_CANARY" || true)',
      '    tok="K:$k|F:$f|E:$e|R:$FAKE_REGION|S:${FAKE_SECRET:-yok}";;',
      "esac",
      'if [ -n "$exp" ]; then',
      '  printf \'{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s","expirationTimestamp":"%s"}}\' "$tok" "$exp"',
      "else",
      '  printf \'{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s"}}\' "$tok"',
      "fi",
    ].join("\n"),
  );
  await chmod(binary, 0o755);
  await writeFile(join(dir, "mode"), "ok");
  await writeFile(join(dir, "token"), "initial-token-value");
  await mkdir(join(home, ".fakecloud"), { recursive: true });
  return {
    dir,
    binary,
    home,
    setExpiry: async (iso) => {
      if (iso === null) await rm(join(dir, "expiry"), { force: true });
      else await writeFile(join(dir, "expiry"), iso);
    },
    setToken: (t) => writeFile(join(dir, "token"), t),
    setMode: (m) => writeFile(join(dir, "mode"), m),
  };
}

class CountingSandbox implements Sandbox {
  runs = 0;
  readonly kind: Sandbox["kind"];
  private readonly inner: Sandbox;
  constructor(inner: Sandbox) {
    this.inner = inner;
    this.kind = inner.kind;
  }
  run(spec: SandboxSpec): Promise<SandboxResult> {
    this.runs += 1;
    return this.inner.run(spec);
  }
  spawn(spec: SandboxSpec): ReturnType<Sandbox["spawn"]> {
    return this.inner.spawn(spec);
  }
}

describe("ExecCredentialRunner + LocalBroker (exec kaynağı)", () => {
  let plugin: Plugin;
  let realSandbox: Sandbox | null = null;
  const dirs: string[] = [];
  beforeAll(async () => {
    plugin = await makePlugin();
    dirs.push(plugin.dir, plugin.home);
    realSandbox = await detectSandbox();
  });
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  const direct = (): Sandbox => new UnsafeDirectRunner({ acknowledgeNoIsolation: true });
  async function setup(opts: { sandbox: Sandbox | null; now?: () => Date; args?: string[]; env?: Record<string, string> }) {
    const pki = await generateTestPki();
    const imp = await importKubeconfig(
      buildKubeconfig({
        server: "https://127.0.0.1:6443",
        caPem: pki.caPem,
        token: undefined as never,
        userExtra: {
          exec: {
            apiVersion: "client.authentication.k8s.io/v1",
            command: plugin.binary,
            args: opts.args ?? ["token", "-i", "demo-cluster"],
            env: Object.entries(opts.env ?? {}).map(([name, value]) => ({ name, value })),
          },
        },
      }),
      { execCatalog: CATALOG },
    );
    const store = new MemorySecretStore();
    const profile = makeTestProfile({
      id: "x1",
      credentialSource: { kind: "exec", execTemplateId: "test-plugin", ambientDependencies: ambientFor(TEST_TEMPLATE) },
    });
    await store.set(credentialKey(profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
    const counting = opts.sandbox ? new CountingSandbox(opts.sandbox) : null;
    const runner = new ExecCredentialRunner({ sandbox: counting, catalog: CATALOG, homeDir: plugin.home, ...(opts.now ? { now: opts.now } : {}) });
    const broker = new LocalBroker({ store, exec: runner, ...(opts.now ? { now: opts.now } : {}) });
    const known = new KnownSecrets();
    return { imp, profile, broker, known, counting, store };
  }
  const lease = (s: Awaited<ReturnType<typeof setup>>) => s.broker.acquire({ profile: s.profile, purpose: "t", callId: "c", ttlSec: 30 }, s.known);

  it("import: eklenti blob'a ikili yolu + SHA-256 + doğrulanmış argv ile yazılır; token YOK", async () => {
    const s = await setup({ sandbox: direct() });
    expect(s.imp.auth).toBe("exec");
    expect(s.imp.blob).toMatchObject({ kind: "k8s-exec", exec: { templateId: "test-plugin", args: ["token", "--cluster-id", "demo-cluster"] } });
    expect(s.imp.blob.exec?.binarySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(s.imp.blob.token).toBeUndefined();
    expect(s.imp.warnings.join(" ")).toMatch(/OS sandbox içinde/);
  });

  it("sandbox yoksa eklenti ÇALIŞTIRILMAZ (fail-closed)", async () => {
    const s = await setup({ sandbox: null });
    await expect(lease(s)).rejects.toMatchObject({ code: "sandbox_unavailable" });
  });

  it("lease token üretir; resolver yalnız lease etkinken verir; M3'e kayıtlıdır", async () => {
    await plugin.setMode("ok");
    await plugin.setToken("tok-from-plugin-1234567890");
    const s = await setup({ sandbox: direct() });
    const l = await lease(s);
    expect(s.broker.resolver.k8s(l.handle)).toMatchObject({ server: "https://127.0.0.1:6443", token: "tok-from-plugin-1234567890" });
    expect(s.known.scrub("x tok-from-plugin-1234567890 y")).not.toContain("tok-from-plugin-1234567890");
    await l.release();
    expect(() => s.broker.resolver.k8s(l.handle)).toThrow(expect.objectContaining({ code: "lease_inactive" }));
  });

  it("prime exec profili için M3'e bir şey kaydetmez ve eklenti çalıştırmaz", async () => {
    const s = await setup({ sandbox: direct() });
    await s.broker.prime!(s.profile, s.known);
    expect(s.counting?.runs).toBe(0);
  });

  it("bitişi bildirilen kimlik önbelleğe alınır; bitişe yaklaşınca yenilenir", async () => {
    let t = Date.parse("2030-01-01T00:00:00Z");
    const now = () => new Date(t);
    await plugin.setMode("ok");
    await plugin.setToken("cached-token-aaaaaaaa");
    await plugin.setExpiry("2030-01-01T00:10:00Z");
    const s = await setup({ sandbox: direct(), now });
    await (await lease(s)).release();
    await (await lease(s)).release();
    expect(s.counting?.runs).toBe(1);
    t += 9 * 60_000 + 40_000; // bitişe 20 sn kala: 30 sn payın içinde
    await plugin.setToken("fresh-token-bbbbbbbb");
    const l = await lease(s);
    expect(s.counting?.runs).toBe(2);
    expect(s.broker.resolver.k8s(l.handle).token).toBe("fresh-token-bbbbbbbb");
    await l.release();
  });

  it("bitişi bildirilmeyen kimlik kısa süre önbelleğe alınır", async () => {
    let t = Date.parse("2030-01-01T00:00:00Z");
    const now = () => new Date(t);
    await plugin.setExpiry(null);
    const s = await setup({ sandbox: direct(), now });
    await (await lease(s)).release();
    t += 10_000;
    await (await lease(s)).release();
    expect(s.counting?.runs).toBe(1);
    t += 25_000;
    await (await lease(s)).release();
    expect(s.counting?.runs).toBe(2);
  });

  it("ikili değişirse (hash) çalıştırılmaz", async () => {
    const other = await makePlugin();
    dirs.push(other.dir, other.home);
    const s = await setup({ sandbox: direct() });
    const blob = JSON.parse((await s.store.get(credentialKey("x1"))) ? Buffer.from((await s.store.get(credentialKey("x1")))!).toString() : "{}");
    await writeFile(plugin.binary, `${await (await import("node:fs/promises")).readFile(plugin.binary, "utf8")}\n# değişti`);
    await expect(lease(s)).rejects.toMatchObject({ code: "exec_binary_changed" });
    expect(blob.kind).toBe("k8s-exec");
  });

  it("kayıtlı şablon katalogdan çıkmışsa çalıştırılmaz", async () => {
    const s = await setup({ sandbox: direct() });
    const runner = new ExecCredentialRunner({ sandbox: direct(), catalog: [], homeDir: plugin.home });
    const broker = new LocalBroker({ store: s.store, exec: runner });
    await expect(broker.acquire({ profile: s.profile, purpose: "t", callId: "c", ttlSec: 30 }, s.known)).rejects.toMatchObject({ code: "kubeconfig_exec_unsupported" });
  });

  it("hata/çıkış: mesajda stderr veya token yok", async () => {
    await plugin.setMode("fail");
    await plugin.setToken("leaky-token-ccccccccc");
    const s = await setup({ sandbox: direct() });
    const err = await lease(s).catch((e: Error) => e);
    expect(err).toMatchObject({ code: "exec_plugin_failed" });
    expect(String((err as Error).message)).not.toContain("leaky-token-ccccccccc");
    expect(String((err as Error).message)).toMatch(/kod 3/);
    await plugin.setMode("garbage");
    await expect(lease(s)).rejects.toMatchObject({ code: "exec_output_invalid" });
    await plugin.setMode("ok");
  });

  it("zaman aşımı eklentiyi öldürür", async () => {
    await plugin.setMode("slow");
    const s = await setup({ sandbox: direct() });
    const runner = new ExecCredentialRunner({ sandbox: direct(), catalog: CATALOG, homeDir: plugin.home, timeoutMs: 300 });
    const broker = new LocalBroker({ store: s.store, exec: runner });
    await expect(broker.acquire({ profile: s.profile, purpose: "t", callId: "c", ttlSec: 30 }, s.known)).rejects.toMatchObject({ code: "exec_plugin_failed" });
    await plugin.setMode("ok");
  });

  it("kayıtlı env ve argv şablonca yeniden doğrulanır (vault kurcalansa bile)", async () => {
    const s = await setup({ sandbox: direct() });
    const raw = JSON.parse(Buffer.from((await s.store.get(credentialKey("x1")))!).toString());
    raw.exec.args = ["token", "--cluster-id", "x", "--evil", "1"];
    await s.store.set(credentialKey("x1"), new Uint8Array(Buffer.from(JSON.stringify(raw))));
    await expect(lease(s)).rejects.toMatchObject({ code: "kubeconfig_exec_unsupported" });
  });

  const realIt = (name: string, fn: () => Promise<void>) => (process.env["OPS_SKIP_REAL_SANDBOX"] === "1" ? it.skip : it)(name, fn);

  realIt("GERÇEK sandbox: eklenti ev dizinindeki ~/.kube/config'i, host ortamını ve gizli env'i GÖRMEZ; beyan edilen ambient dosya görünür (S-15)", async () => {
    if (!realSandbox) {
      console.warn("UYARI: bwrap yok — gerçek sandbox exec testi atlandı");
      return;
    }
    const hostCanary = makeCanary("host-kube");
    const envCanary = makeCanary("host-env");
    await mkdir(join(plugin.home, ".kube"), { recursive: true });
    await writeFile(join(plugin.home, ".kube", "config"), `token: ${hostCanary.value}\n`);
    await writeFile(join(plugin.home, ".fakecloud", "conf"), "ambient-ok");
    process.env["OPS_PLUGIN_HOST_CANARY"] = envCanary.value;
    process.env["FAKE_SECRET"] = "should-not-pass-without-optin";
    try {
      await plugin.setMode("probe");
      await plugin.setExpiry(null);
      const s = await setup({ sandbox: realSandbox, env: { FAKE_REGION: "eu-test-1" } });
      const runner = new ExecCredentialRunner({
        sandbox: realSandbox,
        catalog: CATALOG,
        homeDir: plugin.home,
        hostEnv: () => ({ ...process.env, FAKE_REGION: "ambient-region" }),
      });
      const broker = new LocalBroker({ store: s.store, exec: runner });
      const l = await broker.acquire({ profile: s.profile, purpose: "t", callId: "c", ttlSec: 30 }, s.known);
      const token = broker.resolver.k8s(l.handle).token ?? "";
      await l.release();
      expect(token).toContain("K:yok");
      expect(token).not.toContain(hostCanary.value);
      expect(token).toContain("F:ambient-ok");
      expect(token).toContain("E:0");
      expect(token).not.toContain(envCanary.value);
      expect(token).toContain("R:eu-test-1"); // kubeconfig'teki env, ambient'ten önceliklidir
      expect(token).toContain("S:yok"); // opt-in yok: FAKE_SECRET geçmez
    } finally {
      delete process.env["OPS_PLUGIN_HOST_CANARY"];
      delete process.env["FAKE_SECRET"];
      await plugin.setMode("ok");
    }
  });

  realIt("GERÇEK sandbox: açık onaylı (opt-in) env geçer; onaysız geçmez", async () => {
    if (!realSandbox) return;
    process.env["FAKE_SECRET"] = "optin-secret-value";
    try {
      await plugin.setMode("probe");
      const s = await setup({ sandbox: realSandbox });
      const profileOptIn = makeTestProfile({
        id: "x1",
        credentialSource: { kind: "exec", execTemplateId: "test-plugin", ambientDependencies: ambientFor(TEST_TEMPLATE, { optInEnv: ["FAKE_SECRET"] }) },
      });
      const runner = new ExecCredentialRunner({ sandbox: realSandbox, catalog: CATALOG, homeDir: plugin.home });
      const broker = new LocalBroker({ store: s.store, exec: runner });
      const l = await broker.acquire({ profile: profileOptIn, purpose: "t", callId: "c", ttlSec: 30 }, s.known);
      expect(broker.resolver.k8s(l.handle).token).toContain("S:optin-secret-value");
      await l.release();
    } finally {
      delete process.env["FAKE_SECRET"];
      await plugin.setMode("ok");
    }
  });
});

// ---- ProfileService (exec profili) ----------------------------------------------------------

describe("ProfileService: exec profili", () => {
  it("credentialSource exec + ambient listesi; uyarılar; kasada yalnız yürütme tarifi", async () => {
    const plugin = await makePlugin();
    const dir = await mkdtemp(join(tmpdir(), "ops-svc-exec-"));
    try {
      const pki = await generateTestPki();
      const store = new MemorySecretStore();
      const registry = await ProfileRegistry.open({ path: join(dir, "profiles.json"), testMode: false });
      const svc = new ProfileService({ store, registry });
      const r = await svc.addKubeconfig({
        id: "eks-dev",
        environment: "dev",
        allowedScopes: ["default"],
        sandboxAvailable: false,
        execCatalog: CATALOG,
        ambientOptInEnv: ["FAKE_SECRET", "ALAKASIZ"],
        ambientPaths: ["/opt/fakecli"],
        kubeconfigText: buildKubeconfig({
          server: "https://127.0.0.1:6443",
          caPem: pki.caPem,
          token: undefined as never,
          userExtra: { exec: { apiVersion: "client.authentication.k8s.io/v1beta1", command: plugin.binary, args: ["token", "-i", "c1"] } },
        }),
      });
      expect(r.profile.credentialSource).toMatchObject({ kind: "exec", execTemplateId: "test-plugin" });
      expect(r.profile.credentialSource.ambientDependencies).toEqual(expect.arrayContaining(["env:FAKE_REGION", "home:.fakecloud", "env:FAKE_SECRET", "path:/opt/fakecli"]));
      expect(r.profile.credentialSource.ambientDependencies).not.toContain("env:ALAKASIZ");
      expect(r.warnings.join("\n")).toMatch(/OS sandbox bulunamadı/);
      expect(r.warnings.join("\n")).toMatch(/ambient|ortam bağımlılıkları/);
      const blob = JSON.parse(Buffer.from((await store.get(credentialKey("eks-dev")))!).toString());
      expect(blob.kind).toBe("k8s-exec");
      expect(blob.token).toBeUndefined();
      // geniş bağlama yolu reddedilir
      await expect(
        svc.addKubeconfig({
          id: "x",
          environment: "dev",
          allowedScopes: ["default"],
          execCatalog: CATALOG,
          ambientPaths: ["/home"],
          kubeconfigText: buildKubeconfig({
            server: "https://127.0.0.1:6443",
            caPem: pki.caPem,
            token: undefined as never,
            userExtra: { exec: { apiVersion: "client.authentication.k8s.io/v1", command: plugin.binary, args: ["token", "-i", "c1"] } },
          }),
        }),
      ).rejects.toMatchObject({ code: "exec_bind_refused" });
    } finally {
      await rm(plugin.dir, { recursive: true, force: true });
      await rm(plugin.home, { recursive: true, force: true });
      await rm(dir, { recursive: true, force: true });
    }
  });
});
