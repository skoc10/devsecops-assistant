import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildKubeconfig, CaptureSink, generateTestPki, makeCanary } from "@ops/testkit";
import {
  AUDIT_KEY_NAME,
  MemorySecretStore,
  ProfileRegistry,
  ProfileService,
  credentialKey,
  defaultEgressFor,
  ensureAuditKey,
  scanAmbientCredentials,
  scanAmbientEnv,
} from "../src/index.ts";

const server = "https://127.0.0.1:6443";

describe("ProfileService", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-svc-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  async function make() {
    const store = new MemorySecretStore();
    const registry = await ProfileRegistry.open({ path: join(dir, "profiles.json"), testMode: false });
    return { store, registry, svc: new ProfileService({ store, registry }) };
  }

  it("kimlik yalnız kasada; profil/uyarılar/kayıt dosyası canary içermez", async () => {
    const { store, registry, svc } = await make();
    const pki = await generateTestPki();
    const tok = makeCanary("svc");
    const r = await svc.addKubeconfig({
      id: "stage",
      environment: "stage",
      kubeconfigText: buildKubeconfig({ server, caPem: pki.caPem, token: tok.value, namespace: "payments" }),
    });
    expect(r.profile).toMatchObject({
      id: "stage",
      kind: "k8s",
      classCeiling: "read",
      allowedScopes: ["payments"],
      targetPin: { endpoint: server, caFingerprint: pki.caFingerprint },
    });
    const blob = await store.get(credentialKey("stage"));
    expect(Buffer.from(blob!).toString()).toContain(tok.value);

    const sink = new CaptureSink();
    sink.push("result", JSON.stringify(r));
    sink.push("list", JSON.stringify(svc.list()));
    sink.push("registry", JSON.stringify(registry.list()));
    sink.push("registry-file", await (await import("node:fs/promises")).readFile(join(dir, "profiles.json"), "utf8"));
    expect(sink.leaks([tok])).toEqual([]);
  });

  it("namespace yoksa ve kapsam verilmediyse scope_required; '*' uyarı üretir", async () => {
    const { svc } = await make();
    const pki = await generateTestPki();
    const text = buildKubeconfig({ server, caPem: pki.caPem, token: "t".repeat(12) });
    await expect(svc.addKubeconfig({ id: "a", environment: "dev", kubeconfigText: text })).rejects.toMatchObject({ code: "scope_required" });
    const r = await svc.addKubeconfig({ id: "a", environment: "dev", kubeconfigText: text, allowedScopes: ["*"] });
    expect(r.warnings.join(" ")).toMatch(/tüm namespace/);
  });

  it("aynı kimlik replace olmadan eklenmez; hata kasayı kirletmez", async () => {
    const { store, svc } = await make();
    const pki = await generateTestPki();
    const text = buildKubeconfig({ server, caPem: pki.caPem, token: "t".repeat(12), namespace: "x" });
    await svc.addKubeconfig({ id: "a", environment: "dev", kubeconfigText: text });
    await expect(svc.addKubeconfig({ id: "a", environment: "dev", kubeconfigText: text })).rejects.toMatchObject({ code: "profile_exists" });
    await svc.addKubeconfig({ id: "a", environment: "dev", kubeconfigText: text, replace: true });
    expect(await store.list("profile/")).toEqual([credentialKey("a")]);
  });

  it("registry hata verirse kasaya yazılan kimlik geri alınır", async () => {
    const { store, registry, svc } = await make();
    const pki = await generateTestPki();
    const text = buildKubeconfig({ server, caPem: pki.caPem, token: "t".repeat(12), namespace: "x" });
    // aynı kimlik registry'de var ama kasada yok: registry reddeder, kasa temiz kalmalı
    await svc.addKubeconfig({ id: "r", environment: "dev", kubeconfigText: text });
    await store.delete(credentialKey("r"));
    await expect(svc.addKubeconfig({ id: "r", environment: "dev", kubeconfigText: text })).rejects.toMatchObject({ code: "profile_exists" });
    expect(await store.get(credentialKey("r"))).toBeNull();
    expect(registry.list().length).toBe(1);
  });

  it("reddedilen kubeconfig ne kasaya ne kayda yazar", async () => {
    const { store, registry, svc } = await make();
    const pki = await generateTestPki();
    const text = buildKubeconfig({ server, caPem: pki.caPem, token: "t".repeat(12), clusterExtra: { "insecure-skip-tls-verify": true } });
    await expect(svc.addKubeconfig({ id: "z", environment: "dev", kubeconfigText: text, allowedScopes: ["*"] })).rejects.toMatchObject({
      code: "kubeconfig_insecure_tls",
    });
    expect(await store.list("")).toEqual([]);
    expect(registry.list()).toEqual([]);
  });

  it("remove hem kaydı hem kimliği siler", async () => {
    const { store, svc } = await make();
    const pki = await generateTestPki();
    await svc.addKubeconfig({
      id: "d",
      environment: "dev",
      kubeconfigText: buildKubeconfig({ server, caPem: pki.caPem, token: "t".repeat(12), namespace: "n" }),
    });
    expect(await svc.remove("d")).toBe(true);
    expect(svc.list()).toEqual([]);
    expect(await store.get(credentialKey("d"))).toBeNull();
    expect(await svc.remove("d")).toBe(false);
  });

  it("varsayılan egress: prod DB yerel, prod k8s tenant-cloud", () => {
    expect(defaultEgressFor("db", "prod")).toBe("local");
    expect(defaultEgressFor("k8s", "prod")).toBe("tenant-cloud");
    expect(defaultEgressFor("k8s", "dev")).toBe("third-party-cloud");
  });
});

describe("ortam kimliği taraması", () => {
  let home: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "ops-home-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("yalnız varlık ve izin bitlerini raporlar; içerik okunmaz/sızmaz", async () => {
    const c = makeCanary("ambient");
    await mkdir(join(home, ".kube"), { recursive: true });
    await writeFile(join(home, ".kube", "config"), `token: ${c.value}\n`);
    await chmod(join(home, ".kube", "config"), 0o644);
    await mkdir(join(home, ".ssh"), { recursive: true });
    await writeFile(join(home, ".ssh", "id_ed25519"), c.value);
    await chmod(join(home, ".ssh", "id_ed25519"), 0o600);
    const found = await scanAmbientCredentials(home);
    expect(found.map((f) => f.what).sort()).toEqual(["SSH özel anahtarı", "kubeconfig"]);
    expect(found.find((f) => f.what === "kubeconfig")).toMatchObject({ mode: "644", groupOrWorldReadable: true });
    expect(found.find((f) => f.what === "SSH özel anahtarı")).toMatchObject({ mode: "600", groupOrWorldReadable: false });
    expect(JSON.stringify(found)).not.toContain(c.value);
  });

  it("boş HOME: bulgu yok", async () => {
    expect(await scanAmbientCredentials(home)).toEqual([]);
  });

  it("ortam değişkenlerinden yalnız adlar döner", () => {
    const c = makeCanary("env");
    const names = scanAmbientEnv({ KUBECONFIG: c.value, AWS_PROFILE: "", GH_TOKEN: c.value, PATH: "/bin" });
    expect(names.sort()).toEqual(["GH_TOKEN", "KUBECONFIG"]);
    expect(JSON.stringify(names)).not.toContain(c.value);
  });
});

describe("ensureAuditKey", () => {
  it("yoksa üretir (32 bayt), varsa aynısını döner", async () => {
    const store = new MemorySecretStore();
    const a = await ensureAuditKey(store);
    expect(a.length).toBe(32);
    const b = await ensureAuditKey(store);
    expect(Buffer.from(b).equals(Buffer.from(a))).toBe(true);
    expect(await store.list("audit/")).toEqual([AUDIT_KEY_NAME]);
  });
});
