import { describe, expect, it } from "vitest";
import { buildKubeconfig, CaptureSink, generateTestPki, makeCanary } from "@ops/testkit";
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
    const r = await importKubeconfig(buildKubeconfig({ server, caFile: "ca.crt", tokenFile: "token" }), { baseDir: "/cfg", readFile: read });
    expect(r.blob.token).toBe(tok.value);
    expect(r.blob.caPem).toBe(pki.caPem);
    expect(r.caFingerprint).toBe(pki.caFingerprint);
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
