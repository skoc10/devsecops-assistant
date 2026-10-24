import { basename } from "node:path";
import { OpsError } from "@ops/contracts";

export interface FlagRule {
  readonly flag: string;
  /** Kısa biçim (ör. `-i`). */
  readonly alias?: string;
  /** Değer deseni (tam eşleşme) veya `bool` (değersiz bayrak). */
  readonly value: RegExp | "bool";
  readonly required?: boolean;
}

export interface ExecTemplate {
  readonly id: string;
  readonly description: string;
  /** Çalıştırılabilir dosya ADI (yol değil). */
  readonly binary: string;
  /** Konumsal alt komut öneki. */
  readonly prefix: readonly string[];
  /** Önekten ÖNCE gelebilen genel bayraklar (ör. `aws --region x eks get-token`). */
  readonly globalFlags?: readonly FlagRule[];
  readonly flags: readonly FlagRule[];
  /** `exec.env` içinde izinli girdiler. */
  readonly env: readonly { readonly name: string; readonly value: RegExp }[];
  readonly ambient: {
    /** Varsayılan olarak profilde beyan edilen (kimlik OLMAYAN) ortam değişkenleri. */
    readonly defaultEnv: readonly string[];
    /** Yalnız kullanıcı AÇIKÇA onaylarsa geçirilen (kimlik içerebilen) değişkenler. */
    readonly optInEnv: readonly string[];
    /** Ev dizinine göreli, salt okunur bağlanacak yollar. */
    readonly homeFiles: readonly string[];
  };
  readonly network: "none" | "host";
}

const IDENT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const AWS_NAME = /^[A-Za-z0-9_.@-]{1,64}$/;
const AWS_REGION = /^[a-z]{2}(?:-[a-z]+)+-\d{1}$/;
const AWS_ROLE = /^arn:aws[a-z-]*:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]{1,200}$/;
const GUID_OR_URI = /^(?:[0-9a-fA-F-]{36}|api:\/\/[A-Za-z0-9._-]{1,100}|https:\/\/[A-Za-z0-9._/-]{1,150})$/;

/** Ürünle gelen şablonlar (HER BİRİ **[doğrulanacak]**: kubeconfig exec sözleşmesi ve bayrak adları sürüme bağlı). */
export const BUILTIN_EXEC_TEMPLATES: readonly ExecTemplate[] = [
  {
    id: "aws-eks-get-token",
    description: "AWS CLI: aws [--region R] [--profile P] eks get-token --cluster-name C [--role-arn A] [--output json]",
    binary: "aws",
    prefix: ["eks", "get-token"],
    globalFlags: [
      { flag: "--region", value: AWS_REGION },
      { flag: "--profile", value: AWS_NAME },
    ],
    flags: [
      { flag: "--cluster-name", value: IDENT, required: true },
      { flag: "--region", value: AWS_REGION },
      { flag: "--role-arn", value: AWS_ROLE },
      { flag: "--profile", value: AWS_NAME },
      { flag: "--output", value: /^json$/ },
    ],
    env: [
      { name: "AWS_PROFILE", value: AWS_NAME },
      { name: "AWS_REGION", value: AWS_REGION },
      { name: "AWS_DEFAULT_REGION", value: AWS_REGION },
    ],
    ambient: {
      defaultEnv: ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"],
      optInEnv: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
      homeFiles: [".aws/config", ".aws/credentials", ".aws/sso", ".aws/cli"],
    },
    network: "host",
  },
  {
    id: "aws-iam-authenticator-token",
    description: "aws-iam-authenticator token -i C [-r ROLE]",
    binary: "aws-iam-authenticator",
    prefix: ["token"],
    flags: [
      { flag: "--cluster-id", alias: "-i", value: IDENT, required: true },
      { flag: "--role", alias: "-r", value: AWS_ROLE },
    ],
    env: [{ name: "AWS_PROFILE", value: AWS_NAME }, { name: "AWS_REGION", value: AWS_REGION }],
    ambient: {
      defaultEnv: ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"],
      optInEnv: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
      homeFiles: [".aws/config", ".aws/credentials", ".aws/sso", ".aws/cli"],
    },
    network: "host",
  },
  {
    id: "gke-gcloud-auth-plugin",
    description: "gke-gcloud-auth-plugin [--use_application_default_credentials]",
    binary: "gke-gcloud-auth-plugin",
    prefix: [],
    flags: [{ flag: "--use_application_default_credentials", value: "bool" }],
    env: [],
    ambient: { defaultEnv: ["CLOUDSDK_CONFIG"], optInEnv: ["GOOGLE_APPLICATION_CREDENTIALS"], homeFiles: [".config/gcloud"] },
    network: "host",
  },
  {
    id: "kubelogin-get-token",
    description: "kubelogin get-token --login MODE --server-id ID [--client-id ID] [--tenant-id ID] [--environment E] [--legacy]",
    binary: "kubelogin",
    prefix: ["get-token"],
    flags: [
      { flag: "--login", value: /^(?:azurecli|spn|msi|workloadidentity|devicecode|interactive|ropc|manual)$/ },
      { flag: "--server-id", value: GUID_OR_URI, required: true },
      { flag: "--client-id", value: GUID_OR_URI },
      { flag: "--tenant-id", value: GUID_OR_URI },
      { flag: "--environment", value: /^Azure[A-Za-z]{3,30}$/ },
      { flag: "--legacy", value: "bool" },
    ],
    env: [],
    ambient: { defaultEnv: [], optInEnv: ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AAD_SERVICE_PRINCIPAL_CLIENT_SECRET"], homeFiles: [".azure", ".kube/cache/kubelogin"] },
    network: "host",
  },
];

export interface ExecSpecInput {
  readonly command: string;
  readonly args: readonly string[];
  readonly env: readonly { readonly name: string; readonly value: string }[];
}

export interface ExecMatch {
  readonly template: ExecTemplate;
  /** `binary` HARİÇ, normalize edilmiş argümanlar. */
  readonly args: string[];
  readonly env: Record<string, string>;
}

const safeFlagName = (s: string): string => (/^-{1,2}[A-Za-z0-9_-]{1,40}$/.test(s) ? s : "<bilinmeyen>");
const fail = (reason: string): never => {
  throw new OpsError("kubeconfig_exec_unsupported", `exec eklentisi şablonlara uymuyor: ${reason}`, { reason });
};

function parseFlag(tok: string, rules: readonly FlagRule[]): { rule: FlagRule; inline?: string } | undefined {
  const eq = tok.indexOf("=");
  const name = eq > 0 ? tok.slice(0, eq) : tok;
  const rule = rules.find((r) => r.flag === name || r.alias === name);
  if (!rule) return undefined;
  return { rule, ...(eq > 0 ? { inline: tok.slice(eq + 1) } : {}) };
}

/**
 * kubeconfig `exec` girdisini şablon kataloğuna karşı doğrular. Şablon dışı argüman, bayrak,
 * ortam değişkeni veya değer → ret. Hata mesajları değer taşımaz (yalnız bayrak adı).
 */
export function matchExecSpec(spec: ExecSpecInput, catalog: readonly ExecTemplate[] = BUILTIN_EXEC_TEMPLATES): ExecMatch {
  const bin = basename(spec.command);
  const candidates = catalog.filter((t) => t.binary === bin);
  if (candidates.length === 0) fail(`'${/^[A-Za-z0-9._-]{1,40}$/.test(bin) ? bin : "<bilinmeyen>"}' için şablon yok (kullanıcı şablonu ekleyin)`);
  let lastErr: OpsError | undefined;
  for (const t of candidates) {
    try {
      return matchOne(t, spec);
    } catch (e) {
      if (e instanceof OpsError) lastErr = e;
      else throw e;
    }
  }
  throw lastErr as OpsError;
}

function matchOne(t: ExecTemplate, spec: ExecSpecInput): ExecMatch {
  const out: string[] = [];
  const seen = new Set<string>();
  const args = spec.args;
  let i = 0;

  const takeFlag = (rules: readonly FlagRule[], scope: string): boolean => {
    const tok = args[i] as string;
    const pf = parseFlag(tok, rules);
    if (!pf) return false;
    const { rule } = pf;
    if (seen.has(`${scope}:${rule.flag}`)) fail(`yinelenen bayrak ${rule.flag}`);
    seen.add(`${scope}:${rule.flag}`);
    if (rule.value === "bool") {
      if (pf.inline !== undefined) fail(`${rule.flag} değer almaz`);
      out.push(rule.flag);
      i += 1;
      return true;
    }
    let value: string | undefined = pf.inline;
    if (value === undefined) {
      value = args[i + 1];
      i += 2;
    } else {
      i += 1;
    }
    if (value === undefined || !rule.value.test(value)) fail(`${rule.flag} değeri geçersiz`);
    out.push(rule.flag, value as string);
    return true;
  };

  // 1) önekten önceki genel bayraklar
  while (i < args.length && (args[i] as string).startsWith("-") && t.globalFlags) {
    if (!takeFlag(t.globalFlags, "g")) break;
  }
  // 2) konumsal önek
  for (const p of t.prefix) {
    if (args[i] !== p) fail(`beklenen alt komut '${p}'`);
    out.push(p);
    i += 1;
  }
  // 3) bayraklar
  while (i < args.length) {
    const tok = args[i] as string;
    if (!tok.startsWith("-")) fail("beklenmeyen konumsal argüman");
    if (!takeFlag(t.flags, "f")) fail(`izin verilmeyen bayrak ${safeFlagName(tok.split("=")[0] as string)}`);
  }
  for (const r of t.flags) {
    if (r.required && !seen.has(`f:${r.flag}`)) fail(`zorunlu bayrak eksik ${r.flag}`);
  }

  const env: Record<string, string> = {};
  for (const e of spec.env) {
    const rule = t.env.find((x) => x.name === e.name);
    if (!rule) fail(`izin verilmeyen ortam değişkeni ${/^[A-Z][A-Z0-9_]{0,40}$/.test(e.name) ? e.name : "<bilinmeyen>"}`);
    if (!rule?.value.test(e.value)) fail(`ortam değişkeni değeri geçersiz ${e.name}`);
    env[e.name] = e.value;
  }
  return { template: t, args: out, env };
}
