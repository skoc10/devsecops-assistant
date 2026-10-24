import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

export interface TestPki {
  readonly caPem: string;
  /** CA'nın SHA-256 parmak izi (küçük harf hex, iki nokta yok). */
  readonly caFingerprint: string;
  readonly serverCertPem: string;
  readonly serverKeyPem: string;
  readonly clientCertPem: string;
  readonly clientKeyPem: string;
}

let cached: Promise<TestPki> | null = null;

async function generate(): Promise<TestPki> {
  const dir = await mkdtemp(join(tmpdir(), "ops-pki-"));
  const f = (n: string): string => join(dir, n);
  const ssl = (...args: string[]): Promise<unknown> => run("openssl", args, { cwd: dir });
  try {
    await ssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f("ca.key"));
    await ssl(
      "req", "-x509", "-new", "-key", f("ca.key"), "-sha256", "-days", "2", "-subj", "/CN=ops-test-ca",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
      "-out", f("ca.crt"),
    );
    const leaf = async (name: string, cn: string, ext: string): Promise<void> => {
      await ssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f(`${name}.key`));
      await ssl("req", "-new", "-key", f(`${name}.key`), "-subj", `/CN=${cn}`, "-out", f(`${name}.csr`));
      await writeFile(f(`${name}.ext`), `${ext}\n`);
      await ssl(
        "x509", "-req", "-in", f(`${name}.csr`), "-CA", f("ca.crt"), "-CAkey", f("ca.key"), "-CAcreateserial",
        "-days", "2", "-sha256", "-extfile", f(`${name}.ext`), "-out", f(`${name}.crt`),
      );
    };
    await leaf("server", "ops-test-server", "subjectAltName=DNS:localhost,DNS:k8s.test.invalid,IP:127.0.0.1\nextendedKeyUsage=serverAuth");
    await leaf("client", "ops-test-user", "extendedKeyUsage=clientAuth");
    const rd = (n: string): Promise<string> => readFile(f(n), "utf8");
    const caPem = await rd("ca.crt");
    return {
      caPem,
      caFingerprint: new X509Certificate(caPem).fingerprint256.replace(/:/g, "").toLowerCase(),
      serverCertPem: await rd("server.crt"),
      serverKeyPem: await rd("server.key"),
      clientCertPem: await rd("client.crt"),
      clientKeyPem: await rd("client.key"),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Çalışma anında (süreç başına bir kez) üretilen test CA'sı ve yaprak sertifikalar. Depoda anahtar YOK. */
export function generateTestPki(): Promise<TestPki> {
  cached ??= generate();
  return cached;
}
