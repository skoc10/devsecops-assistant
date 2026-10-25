import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildKubeconfig, CaptureSink, generateTestPki, makeCanary } from "@ops/testkit";
import type { TestPki } from "@ops/testkit";
import { importKubeconfig } from "../src/index.ts";

const server = "https://127.0.0.1:6443";

describe("importKubeconfig", () => {
  it("token kimlikli kubeconfig: tek bağlam, CA parmak izi pini, normalize blob", async () => {
    const pki = await generateTestPki();
    const tok = makeCanary("tok");
    const text = buildKubeconfig({ server, caPem: pki.caPem, token: tok.value, namespace: "payments", extraContexts: 2 });
    const r = await importKubeconfig(text);
    expect(r).toMatchObject({ contextName: "test-ctx", server, namespace: "payments", auth: "token", caFingerprint: pki.caFingerprint });
    expect(r.blob).toMatchObject({ v: 1, kind: "k8s-static", server, token: tok.value, caPem: pki.caPem });
    expect(r.warnings.join(" ")).toMatch(/2 diğer bağlam atıldı/);
  });

  it("istemci sertifikası kimliği", async () => {
    const pki = await generateTestPki();
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, clientCertPem: pki.clientCertPem, clientKeyPem: pki.clientKeyPem }));
    expect(r.auth).toBe("client-cert");
    expect(r.blob.clientKeyPem).toBe(pki.clientKeyPem);
  });

  it("harici dosya başvuruları (CA, token, istemci anahtarı) satır içine alınır", async () => {
    const pki = await generateTestPki();
    const tok = makeCanary("dosya");
    const files = new Map<string, string>([
      ["/cfg/ca.crt", pki.caPem],
      ["/cfg/token", `${tok.value}\n`],
    ]);
    const read = async (p: string): Promise<Buffer> => {
      const v = files.get(p);
      if (v === undefined) throw new Error("yok");
      return Buffer.from(v);
    };
    const r = await importKubeconfig(buildKubeconfig({ server, caFile: "ca.crt", tokenFile: "token" }), { baseDir: "/cfg", readFile: read, realpath: async (p) => p });
    expect(r.blob.token).toBe(tok.value);
    expect(r.blob.caPem).toBe(pki.caPem);
    expect(r.caFingerprint).toBe(pki.caFingerprint);
    // okunan her dosya uyarılarda YALNIZ yoluyla
    expect(r.warnings).toEqual(
      expect.arrayContaining([
        "başvurulan dosya okundu ve satır içine alındı (certificate-authority): /cfg/ca.crt",
        "başvurulan dosya okundu ve satır içine alındı (tokenFile): /cfg/token",
      ]),
    );
    expect(r.warnings.join("\n")).not.toContain(tok.value);
  });

  it("CA yoksa uyarır ve parmak izi pini üretmez", async () => {
    const r = await importKubeconfig(buildKubeconfig({ server, token: "t".repeat(12) }));
    expect(r.caFingerprint).toBeUndefined();
    expect(r.warnings.join(" ")).toMatch(/CA verisi yok/);
  });

  it("kimlik yoksa anonim uyarısı", async () => {
    const pki = await generateTestPki();
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem }));
    expect(r.auth).toBe("none");
    expect(r.warnings.join(" ")).toMatch(/anonim/);
  });

  const reject = async (opts: Parameters<typeof buildKubeconfig>[0], code: string): Promise<void> => {
    const pki = await generateTestPki();
    await expect(importKubeconfig(buildKubeconfig({ caPem: pki.caPem, token: "t".repeat(12), ...opts }))).rejects.toMatchObject({ code });
  };

  it.each([
    ["insecure-skip-tls-verify", { server, clusterExtra: { "insecure-skip-tls-verify": true } }, "kubeconfig_insecure_tls"],
    ["proxy-url", { server, clusterExtra: { "proxy-url": "http://proxy.invalid:3128" } }, "kubeconfig_proxy"],
    ["şablon dışı exec eklentisi", { server, token: undefined as never, userExtra: { exec: { apiVersion: "client.authentication.k8s.io/v1beta1", command: "aws", args: ["eks", "get-token"] } } }, "kubeconfig_exec_unsupported"],
    ["exec + statik token birlikte", { server, userExtra: { exec: { apiVersion: "client.authentication.k8s.io/v1beta1", command: "aws", args: ["eks", "get-token", "--cluster-name", "c"] } } }, "kubeconfig_invalid"],
    ["auth-provider", { server, userExtra: { "auth-provider": { name: "gcp" } } }, "kubeconfig_auth_provider"],
    ["basic auth", { server, userExtra: { username: "u", password: "p" } }, "kubeconfig_basic_auth"],
    ["düz http", { server: "http://127.0.0.1:8080" }, "kubeconfig_insecure_tls"],
  ])("%s reddedilir", async (_n, opts, code) => {
    await reject(opts, code);
  });

  it("geçersiz girdiler: Config değil, bozuk YAML, bağlam yok, eksik CA dosyası", async () => {
    await expect(importKubeconfig(buildKubeconfig({ server, kind: "Pod" }))).rejects.toMatchObject({ code: "kubeconfig_invalid" });
    await expect(importKubeconfig("a: [")).rejects.toMatchObject({ code: "kubeconfig_invalid" });
    await expect(importKubeconfig(buildKubeconfig({ server }), { context: "yok" })).rejects.toMatchObject({ code: "kubeconfig_context_missing" });
    const err = await importKubeconfig(buildKubeconfig({ server, caFile: "/gizli/dizin/ca.crt" }), { readFile: async () => { throw new Error("EACCES"); } }).catch((e: Error) => e);
    expect(err).toMatchObject({ code: "kubeconfig_file_unreadable" });
    expect((err as Error).message).toContain("ca.crt");
    expect((err as Error).message).not.toContain("/gizli/dizin");
  });

  it("sertifika/anahtar eşleşmesi zorunlu", async () => {
    const pki = await generateTestPki();
    await expect(importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, clientCertPem: pki.clientCertPem }))).rejects.toMatchObject({ code: "kubeconfig_invalid" });
  });

  it("hata ve uyarı mesajları secret içermez (S-06 CLI kanalı)", async () => {
    const pki = await generateTestPki();
    const tok = makeCanary("ctx");
    const sink = new CaptureSink();
    const variants: Parameters<typeof buildKubeconfig>[0][] = [
      { server, caPem: pki.caPem, token: tok.value, clusterExtra: { "insecure-skip-tls-verify": true } },
      { server, caPem: pki.caPem, token: tok.value, userExtra: { exec: { command: tok.value } } },
      { server, caPem: pki.caPem, token: tok.value, userExtra: { username: tok.value, password: tok.value } },
      { server: `http://${tok.value}`, caPem: pki.caPem, token: tok.value },
      { server, caPem: pki.caPem, token: tok.value, extraContexts: 3 },
      { server, token: tok.value },
    ];
    for (const v of variants) {
      try {
        const r = await importKubeconfig(buildKubeconfig(v));
        sink.push("warnings", r.warnings);
      } catch (e) {
        sink.push("error", (e as Error).message + JSON.stringify((e as { details?: unknown }).details ?? {}));
      }
    }
    expect(sink.leaks([tok])).toEqual([]);
  });
});

describe("importKubeconfig: başvurulan dosyalar (düşmanca paylaşılan kubeconfig)", () => {
  const victim = makeCanary("kurban-secret");
  const read = (field: string, path: string): string => `başvurulan dosya okundu ve satır içine alındı (${field}): ${path}`;
  let root: string;
  let pki: TestPki;
  let dl: string;
  let mk: { kube: string; ca: string; crt: string; key: string };
  let sshKey: string;
  let awsCreds: string;
  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), "ops-kc-ref-"))); // macOS: /var → /private/var
    pki = await generateTestPki();
    await mkdir(join(root, "home", ".aws"), { recursive: true });
    await mkdir(join(root, "home", ".ssh"), { recursive: true });
    await writeFile(join(root, "home", ".vault-token"), `${victim.value}\n`, { mode: 0o600 });
    awsCreds = join(root, "home", ".aws", "credentials");
    await writeFile(awsCreds, `[default]\naws_secret_access_key = ${victim.value}\n`, { mode: 0o600 });
    sshKey = join(root, "home", ".ssh", "id_ed25519");
    await writeFile(sshKey, `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from(victim.value).toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`, { mode: 0o600 });
    dl = join(root, "dl");
    await mkdir(dl, { recursive: true });
    // minikube düzeni: sertifikalar kubeconfig dizininin DIŞINDA, MUTLAK yollarla
    const prof = join(root, "mk", ".minikube", "profiles", "minikube");
    await mkdir(prof, { recursive: true });
    await mkdir(join(root, "mk", ".kube"), { recursive: true });
    mk = { kube: join(root, "mk", ".kube"), ca: join(root, "mk", ".minikube", "ca.crt"), crt: join(prof, "client.crt"), key: join(prof, "client.key") };
    await writeFile(mk.ca, pki.caPem);
    await writeFile(mk.crt, pki.clientCertPem);
    await writeFile(mk.key, pki.clientKeyPem, { mode: 0o600 });
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("R-K1: tokenFile kubeconfig dizininden kaçamaz (../, mutlak yol, symlink hedefi); hata içerik ve dizin taşımaz", async () => {
    await symlink(join(root, "home", ".vault-token"), join(dl, "token-link"));
    for (const tokenFile of ["../home/.vault-token", join(root, "home", ".vault-token"), "token-link"]) {
      const err = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile, namespace: "default" }), { baseDir: dl }).catch((e: Error) => e);
      expect(err, tokenFile).toMatchObject({ code: "kubeconfig_token_file_outside" });
      expect((err as Error).message).not.toContain(victim.value);
      expect((err as Error).message).not.toContain(join(root, "home"));
    }
  });

  it("açık izinle dış tokenFile kabul edilir; gerçek yolu uyarıda raporlanır, içeriği raporlanmaz", async () => {
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile: "../home/.vault-token" }), { baseDir: dl, allowExternalTokenFile: true });
    expect(r.blob.token).toBe(victim.value);
    expect(r.warnings).toContain(read("tokenFile", join(root, "home", ".vault-token")));
    expect(r.warnings.join("\n")).toMatch(/tokenFile kubeconfig dizininin DIŞINDA; açık izinle kabul edildi/);
    expect(r.warnings.join("\n")).not.toContain(victim.value);
  });

  it("kubeconfig dizinindeki (veya alt dizinindeki) tokenFile kabul edilir ve yolu raporlanır", async () => {
    const tok = makeCanary("dizin-ici");
    await mkdir(join(dl, "sec"), { recursive: true });
    await writeFile(join(dl, "sec", "token"), `${tok.value}\n`, { mode: 0o600 });
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile: "sec/token" }), { baseDir: dl });
    expect(r.auth).toBe("token");
    expect(r.blob.token).toBe(tok.value);
    expect(r.warnings).toContain(read("tokenFile", join(dl, "sec", "token")));
    expect(r.warnings.join("\n")).not.toContain(tok.value);
  });

  it("kubeconfig ev dizininde (veya üstünde) ise dizin sınırı bir şey korumaz: tokenFile açık izin ister", async () => {
    const prev = process.env["HOME"];
    process.env["HOME"] = join(root, "home");
    try {
      const kc = buildKubeconfig({ server, caPem: pki.caPem, tokenFile: ".vault-token" });
      await expect(importKubeconfig(kc, { baseDir: join(root, "home") })).rejects.toMatchObject({ code: "kubeconfig_token_file_outside", message: expect.stringMatching(/ev dizininde/) });
      await expect(importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile: "home/.vault-token" }), { baseDir: root })).rejects.toMatchObject({ code: "kubeconfig_token_file_outside" });
      expect((await importKubeconfig(kc, { baseDir: join(root, "home"), allowExternalTokenFile: true })).blob.token).toBe(victim.value);
    } finally {
      if (prev === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prev;
    }
  });

  it("minikube düzeni: kubeconfig dizini dışındaki MUTLAK yollu PEM CA/sertifika/anahtar içe aktarılır ve yolları raporlanır", async () => {
    const r = await importKubeconfig(buildKubeconfig({ server, caFile: mk.ca, clientCertFile: mk.crt, clientKeyFile: mk.key, namespace: "default" }), { baseDir: mk.kube });
    expect(r).toMatchObject({ auth: "client-cert", caFingerprint: pki.caFingerprint });
    expect(r.blob).toMatchObject({ caPem: pki.caPem, clientCertPem: pki.clientCertPem, clientKeyPem: pki.clientKeyPem });
    expect(r.warnings).toEqual(expect.arrayContaining([read("certificate-authority", mk.ca), read("client-certificate", mk.crt), read("client-key", mk.key)]));
    const keyLines = pki.clientKeyPem.split("\n").filter((l) => l.length > 16 && !l.startsWith("-----"));
    for (const l of keyLines) expect(r.warnings.join("\n")).not.toContain(l);
  });

  it("sertifika+anahtar tek dosyada (kubelet düzeni): her alana yalnız kendi türündeki blok girer", async () => {
    const combined = join(root, "mk", "kubelet-client-current.pem");
    await writeFile(combined, pki.clientCertPem + pki.clientKeyPem, { mode: 0o600 });
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, clientCertFile: combined, clientKeyFile: combined }), { baseDir: mk.kube });
    expect(r.blob.clientCertPem).toBe(pki.clientCertPem);
    expect(r.blob.clientKeyPem).toBe(pki.clientKeyPem);
  });

  it("sertifika dosyasındaki blok dışı içerik (açıklama, öznitelik satırları) kasaya girmez", async () => {
    const noisy = join(dl, "noisy-ca.crt");
    await writeFile(noisy, `Bag Attributes\n    friendlyName: ${victim.value}\nsubject=/CN=ops-test-ca\n${pki.caPem}# ${victim.value}\n`);
    const r = await importKubeconfig(buildKubeconfig({ server, caFile: noisy, token: "t".repeat(12) }), { baseDir: dl });
    expect(r.blob.caPem).toBe(pki.caPem);
    expect(JSON.stringify(r)).not.toContain(victim.value);
  });

  it("PEM olmayan veya yanlış türde dosya reddedilir (ör. client-certificate = ~/.aws/credentials); hata içerik taşımaz", async () => {
    const cases: [string, Parameters<typeof buildKubeconfig>[0]][] = [
      ["client-certificate = AWS kimlik dosyası", { server, caPem: pki.caPem, clientCertFile: awsCreds, clientKeyFile: mk.key }],
      ["client-key = AWS kimlik dosyası", { server, caPem: pki.caPem, clientCertFile: mk.crt, clientKeyFile: awsCreds }],
      ["client-key = sertifika", { server, caPem: pki.caPem, clientCertFile: mk.crt, clientKeyFile: mk.crt }],
      ["client-key = OpenSSH anahtarı", { server, caPem: pki.caPem, clientCertFile: mk.crt, clientKeyFile: sshKey }],
      ["certificate-authority = özel anahtar", { server, caFile: mk.key, token: "t".repeat(12) }],
      ["certificate-authority = AWS kimlik dosyası", { server, caFile: awsCreds, token: "t".repeat(12) }],
    ];
    for (const [what, o] of cases) {
      const err = await importKubeconfig(buildKubeconfig(o), { baseDir: dl }).catch((e: Error) => e);
      expect(err, what).toMatchObject({ code: "kubeconfig_file_invalid" });
      const msg = (err as Error).message;
      expect(msg, what).not.toContain(victim.value);
      expect(msg, what).not.toContain(Buffer.from(victim.value).toString("base64"));
      expect(msg, what).not.toContain("PRIVATE KEY-----");
    }
  });

  it("tokenFile tek satırlık bir belirteç değilse reddedilir (çok satırlı kimlik dosyası)", async () => {
    await writeFile(join(dl, "creds"), `[default]\naws_secret_access_key = ${victim.value}\n`);
    const err = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile: "creds" }), { baseDir: dl }).catch((e: Error) => e);
    expect(err).toMatchObject({ code: "kubeconfig_file_invalid" });
    expect((err as Error).message).not.toContain(victim.value);
  });

  it("normal dosya olmayan başvurular okunmaz: dizin, aygıt (/dev/zero), FIFO (bloklanmadan)", async () => {
    const targets = [join(root, "home"), "/dev/zero"];
    const fifo = join(dl, "fifo");
    if (await promisify(execFile)("mkfifo", [fifo]).then(() => true, () => false)) targets.push(fifo);
    for (const caFile of targets) {
      await expect(importKubeconfig(buildKubeconfig({ server, caFile, token: "t".repeat(12) }), { baseDir: dl }), caFile).rejects.toMatchObject({ code: "kubeconfig_file_unreadable" });
    }
  });

  it("uyarıdaki yol terminal kaçışı taşımaz (denetim/biçim karakterleri görünür kaçışa çevrilir)", async () => {
    const tok = makeCanary("kacis");
    const evil = "tok\u001b]52;c;Y2F0\u0007‮";
    await writeFile(join(dl, evil), `${tok.value}\n`);
    const r = await importKubeconfig(buildKubeconfig({ server, caPem: pki.caPem, tokenFile: evil }), { baseDir: dl });
    const w = r.warnings.join("\n");
    expect(w).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f‮]/u);
    expect(w).toContain(`${dl}/tok\\u{1b}]52;c;Y2F0\\u{7}\\u{202e}`);
  });
});
