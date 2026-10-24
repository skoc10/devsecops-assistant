import { stat } from "node:fs/promises";
import { join } from "node:path";

/**
 * Ortam (ambient) kimlikleri: ürünün denetimi DIŞINDA kalan, kullanıcının kendi dosya ve
 * ortamında duran kimlikler. Yalnız VARLIK, tür ve izin bitleri raporlanır — içerik ASLA okunmaz.
 */
export interface AmbientFinding {
  readonly path: string;
  readonly what: string;
  readonly mode: string;
  readonly groupOrWorldReadable: boolean;
}

const CANDIDATES: readonly { rel: string; what: string }[] = [
  { rel: ".kube/config", what: "kubeconfig" },
  { rel: ".aws/credentials", what: "AWS kimlik dosyası" },
  { rel: ".aws/sso/cache", what: "AWS SSO önbelleği" },
  { rel: ".azure", what: "Azure CLI deposu" },
  { rel: ".config/gcloud", what: "gcloud deposu" },
  { rel: ".docker/config.json", what: "Docker kayıt defteri kimlikleri" },
  { rel: ".config/gh/hosts.yml", what: "GitHub CLI kimliği" },
  { rel: ".terraform.d/credentials.tfrc.json", what: "Terraform kimlik dosyası" },
  { rel: ".netrc", what: "netrc" },
  { rel: ".git-credentials", what: "git kimlikleri" },
  { rel: ".npmrc", what: "npm yapılandırması (token içerebilir)" },
  { rel: ".cursor/sdk/auth.json", what: "Cursor SDK oturumu" },
  { rel: ".ssh/id_rsa", what: "SSH özel anahtarı" },
  { rel: ".ssh/id_ed25519", what: "SSH özel anahtarı" },
  { rel: ".ssh/id_ecdsa", what: "SSH özel anahtarı" },
];

export async function scanAmbientCredentials(home: string): Promise<AmbientFinding[]> {
  const out: AmbientFinding[] = [];
  for (const c of CANDIDATES) {
    const path = join(home, c.rel);
    try {
      const s = await stat(path);
      out.push({
        path,
        what: c.what,
        mode: (s.mode & 0o777).toString(8).padStart(3, "0"),
        groupOrWorldReadable: (s.mode & 0o044) !== 0,
      });
    } catch {
      // yok
    }
  }
  return out;
}

const SENSITIVE_ENV = [
  "KUBECONFIG", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
  "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "GITHUB_TOKEN",
  "GITLAB_TOKEN", "CURSOR_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "PGPASSWORD", "VAULT_TOKEN", "TF_TOKEN",
];

/** Ortam değişkenlerinden yalnız ADLARI (değer asla) döndürür. */
export function scanAmbientEnv(env: Record<string, string | undefined> = process.env): string[] {
  return SENSITIVE_ENV.filter((n) => env[n] !== undefined && env[n] !== "");
}
