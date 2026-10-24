import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseAllDocuments } from "yaml";
import { ScriptedProvider, buildKubeconfig, say } from "@ops/testkit";
import { OpsdClient, resolvePaths, runCli } from "../src/index.ts";
import { makeFixture } from "./fixture.ts";
import type { Fixture } from "./fixture.ts";

function ioPair() {
  const output = new PassThrough();
  const error = new PassThrough();
  const o: string[] = [];
  const e: string[] = [];
  output.on("data", (b: Buffer) => o.push(b.toString()));
  error.on("data", (b: Buffer) => e.push(b.toString()));
  return { io: { input: new PassThrough(), output, error }, out: () => o.join(""), err: () => e.join("") };
}

describe("ops CLI (kasa enjekte)", () => {
  let fx: Fixture;
  beforeEach(async () => {
    fx = await makeFixture({ addProfile: false });
  });
  afterEach(async () => {
    await fx.cleanup();
  });
  const cli = async (argv: string[], over: Partial<Parameters<typeof runCli>[0]> = {}) => {
    const p = ioPair();
    const code = await runCli({ argv, env: {}, io: p.io, paths: fx.rt.paths, store: fx.store, sandbox: null, ...over });
    return { code, out: p.out(), err: p.err() };
  };

  it("profile add → list → doctor → rm", async () => {
    const add = await cli(["profile", "add", "k8s", "--id", "pay", "--kubeconfig", fx.kubeconfigPath, "--env", "sandbox", "--scope", "payments"]);
    expect(add.code, add.err).toBe(0);
    expect(add.out).toContain("Profil eklendi: pay");
    expect(add.out + add.err).not.toContain(fx.canaries.kubeToken.value);
    const list = await cli(["profile", "list"]);
    expect(list.out).toContain("pay\tk8s\tsandbox\ttavan read\tkapsam payments\tstatic");
    const doc = await cli(["profile", "doctor", "pay"]);
    expect(doc.code, doc.out + doc.err).toBe(0);
    expect(doc.out).toContain("BAĞLANABİLİR");
    expect(doc.out).toContain("ops-test-user");
    const rm = await cli(["profile", "rm", "pay"]);
    expect(rm.out).toContain("Silindi: pay");
    expect((await cli(["profile", "rm", "pay"])).code).toBe(1);
    // kasada kimlik kalmadı
    expect(await fx.store.list("profile/")).toEqual([]);
  });

  it("doktor yetki kayması bulursa çıkış kodu 1 ve BAĞLANAMAZ yazar", async () => {
    await cli(["profile", "add", "k8s", "--id", "pay", "--kubeconfig", fx.kubeconfigPath, "--env", "sandbox", "--scope", "payments"]);
    fx.api.setRules("payments", { resourceRules: [{ verbs: ["get", "list"], apiGroups: [""], resources: ["secrets", "pods"] }] });
    const doc = await cli(["profile", "doctor", "pay"]);
    expect(doc.code).toBe(1);
    expect(doc.out).toContain("BAĞLANAMAZ");
    expect(doc.out).toContain("secrets_readable");
  });

  it("kullanım hataları: eksik bayrak, kötü env, bilinmeyen tür/komut", async () => {
    expect((await cli(["profile", "add", "k8s", "--id", "x"])).code).toBe(2);
    expect((await cli(["profile", "add", "k8s", "--id", "x", "--kubeconfig", fx.kubeconfigPath, "--env", "uretim"])).err).toContain("--env");
    expect((await cli(["profile", "add", "db", "--id", "x"])).code).toBe(2);
    expect((await cli(["bilinmeyen"])).code).toBe(2);
    expect((await cli([])).code).toBe(2);
    expect((await cli(["profile", "add", "k8s", "--id", "x", "--kubeconfig", fx.kubeconfigPath, "--env", "dev", "--scope", "a", "--yok"])).code).toBe(1);
  });

  it("reddedilen kubeconfig (insecure TLS) kasaya hiçbir şey yazmaz ve hata secret içermez", async () => {
    const bad = join(fx.home, "bad.yaml");
    await writeFile(bad, buildKubeconfig({ server: fx.api.url, caPem: fx.pki.caPem, token: fx.canaries.kubeToken.value, clusterExtra: { "insecure-skip-tls-verify": true } }), { mode: 0o600 });
    const r = await cli(["profile", "add", "k8s", "--id", "bad", "--kubeconfig", bad, "--env", "dev", "--scope", "a"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("kubeconfig_insecure_tls");
    expect(r.err + r.out).not.toContain(fx.canaries.kubeToken.value);
    expect(await fx.store.list("profile/")).toEqual([]);
  });

  it("profile rbac: manifest üretir (uygulamaz), Secret içermez", async () => {
    const r = await cli(["profile", "rbac", "--sa-namespace", "ops", "--namespace", "payments,orders"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("UYGULANMAZ");
    const docs = parseAllDocuments(r.out).map((d) => d.toJS() as { kind?: string; metadata?: { namespace?: string } } | null);
    expect(docs.some((d) => d?.kind === "RoleBinding" && d.metadata?.namespace === "orders")).toBe(true);
    expect(r.out).not.toMatch(/resources:[\s\S]*- secrets/);
    expect((await cli(["profile", "rbac"])).code).toBe(2);
  });

  it("doctor: sandbox durumu ve ortam kimliklerini içerik OKUMADAN raporlar", async () => {
    const home = await mkdtemp(join(tmpdir(), "ops-doc-home-"));
    try {
      await writeFile(join(home, ".netrc"), `machine x password ${fx.canaries.configToken.value}`);
      await chmod(join(home, ".netrc"), 0o644);
      const r = await cli(["doctor"], { env: { HOME: home, GH_TOKEN: fx.canaries.logSecret.value } });
      expect(r.out).toContain("OS sandbox: YOK");
      expect(r.out).toContain(".netrc");
      expect(r.out).toContain("grup/dünya okuyabilir");
      expect(r.out).toContain("ortam değişkeni: GH_TOKEN");
      expect(r.out + r.err).not.toContain(fx.canaries.configToken.value);
      expect(r.out + r.err).not.toContain(fx.canaries.logSecret.value);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("sağlayıcı yapılandırılmadıysa daemon/chat açık hata verir", async () => {
    const d = await cli(["daemon"]);
    expect(d.code).toBe(1);
    expect(d.err).toContain("provider_not_configured");
    const c = await cli(["chat", "--embedded"]);
    expect(c.err).toContain("provider_not_configured");
    const nodaemon = await cli(["chat"]);
    expect(nodaemon.err).toContain("opsd_unreachable");
  });

  it("daemon başlar, istemci bağlanır, shutdown ile kapanır", async () => {
    const provider = new ScriptedProvider([say("merhaba")], { trustZone: "local" });
    const stop = new AbortController();
    const p = ioPair();
    const running = runCli({ argv: ["daemon"], env: {}, io: p.io, paths: fx.rt.paths, store: fx.store, sandbox: null, provider, stop: stop.signal });
    for (let i = 0; i < 50 && !p.out().includes("dinliyor"); i++) await new Promise((r) => setTimeout(r, 20));
    expect(p.out()).toContain("opsd dinliyor");
    const c = await OpsdClient.connect(fx.rt.paths.socket);
    expect(await c.ping()).toMatchObject({ pong: true });
    c.close();
    stop.abort();
    expect(await running).toBe(0);
  });
});

describe("ops init / parola kaynağı (gerçek şifreli dosya kasası)", () => {
  let home: string;
  const SCRYPT = { N: 1 << 10, r: 8, p: 1 };
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "ops-init-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });
  const cli = async (argv: string[], env: Record<string, string>) => {
    const p = ioPair();
    const code = await runCli({ argv, env, io: p.io, paths: resolvePaths(join(home, "ops")), scryptParams: SCRYPT, sandbox: null });
    return { code, out: p.out(), err: p.err() };
  };

  it("parola dosyası 0600 olmalı; init kasayı 0600 oluşturur; yanlış parola vault_locked", async () => {
    const pw = join(home, "pw");
    await writeFile(pw, "dogru-parola-123\n", { mode: 0o644 });
    const bad = await cli(["init"], { OPS_PASSPHRASE_FILE: pw });
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("passphrase_file_permissions");

    await chmod(pw, 0o600);
    const ok = await cli(["init"], { OPS_PASSPHRASE_FILE: pw });
    expect(ok.code, ok.err).toBe(0);
    expect((await stat(join(home, "ops", "vault", "vault.json"))).mode & 0o777).toBe(0o600);
    expect(await readFile(join(home, "ops", "vault", "vault.json"), "utf8")).not.toContain("dogru-parola-123");

    const again = await cli(["profile", "list"], { OPS_PASSPHRASE_FILE: pw });
    expect(again.code).toBe(0);

    const wrong = join(home, "pw2");
    await writeFile(wrong, "yanlis", { mode: 0o600 });
    const locked = await cli(["profile", "list"], { OPS_PASSPHRASE_FILE: wrong });
    expect(locked.code).toBe(1);
    expect(locked.err).toContain("vault_locked");
  });

  it("etkileşimli terminal ve parola dosyası yoksa açık hata", async () => {
    const r = await cli(["init"], {});
    expect(r.code).toBe(1);
    expect(r.err).toContain("passphrase_unavailable");
  });
});
