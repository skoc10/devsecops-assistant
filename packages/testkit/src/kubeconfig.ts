import { stringify } from "yaml";

export interface TestKubeconfigOpts {
  readonly server: string;
  readonly caPem?: string;
  readonly caFile?: string;
  readonly token?: string;
  readonly tokenFile?: string;
  readonly clientCertPem?: string;
  readonly clientKeyPem?: string;
  readonly clientCertFile?: string;
  readonly clientKeyFile?: string;
  readonly namespace?: string;
  readonly contextName?: string;
  readonly extraContexts?: number;
  readonly clusterExtra?: Record<string, unknown>;
  readonly userExtra?: Record<string, unknown>;
  readonly kind?: string;
}

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

/** Test kubeconfig'i üretir (YAML metni). Değerler çağıranın verdiği (rastgele/canary) değerlerdir. */
export function buildKubeconfig(o: TestKubeconfigOpts): string {
  const ctxName = o.contextName ?? "test-ctx";
  const cluster: Record<string, unknown> = {
    server: o.server,
    ...(o.caPem ? { "certificate-authority-data": b64(o.caPem) } : {}),
    ...(o.caFile ? { "certificate-authority": o.caFile } : {}),
    ...(o.clusterExtra ?? {}),
  };
  const user: Record<string, unknown> = {
    ...(o.token ? { token: o.token } : {}),
    ...(o.tokenFile ? { tokenFile: o.tokenFile } : {}),
    ...(o.clientCertPem ? { "client-certificate-data": b64(o.clientCertPem) } : {}),
    ...(o.clientKeyPem ? { "client-key-data": b64(o.clientKeyPem) } : {}),
    ...(o.clientCertFile ? { "client-certificate": o.clientCertFile } : {}),
    ...(o.clientKeyFile ? { "client-key": o.clientKeyFile } : {}),
    ...(o.userExtra ?? {}),
  };
  const contexts = [{ name: ctxName, context: { cluster: "c1", user: "u1", ...(o.namespace ? { namespace: o.namespace } : {}) } }];
  for (let i = 0; i < (o.extraContexts ?? 0); i++) contexts.push({ name: `other-${i}`, context: { cluster: "c1", user: "u1" } });
  return stringify({
    apiVersion: "v1",
    kind: o.kind ?? "Config",
    "current-context": ctxName,
    clusters: [{ name: "c1", cluster }],
    users: [{ name: "u1", user }],
    contexts,
  });
}
