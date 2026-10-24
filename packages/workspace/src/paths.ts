/**
 * Çalışma alanı yol politikası. Üç sınıf:
 *  - SERT RET (okuma ve yazma): gizli/state/anahtar dosyaları, `.git/`, `.terraform/`;
 *  - YAZMA RET: CI/pipeline tanımları (T21), araç yapılandırması/eklenti yolları (kod çalıştırır);
 *  - kullanıcı `denyPaths` / `writePaths` (glob).
 * Yollar KÜÇÜK bir karakter kümesine indirgenir: boşluk/Unicode/denetim karakteri yok.
 */

export type PathCheck = { readonly ok: true; readonly rel: string } | { readonly ok: false; readonly reason: string };

const NAME = /^[A-Za-z0-9._@+=/-]+$/;

/** Göreli, normal, güvenli adlı bir yol mu? (`a/b.tf`). */
export function normalizeRel(input: string): PathCheck {
  if (typeof input !== "string" || input.length === 0) return { ok: false, reason: "yol boş" };
  if (input.length > 200) return { ok: false, reason: "yol çok uzun (≤200)" };
  if (input.startsWith("/")) return { ok: false, reason: "yol göreli olmalı" };
  if (!NAME.test(input)) return { ok: false, reason: "yol yalnız harf/rakam ve . _ @ + = - / içerebilir" };
  const parts = input.split("/");
  if (parts.some((p) => p === "" || p === "." || p === "..")) return { ok: false, reason: "yol '..', '.' veya boş bölüm içeremez" };
  if (parts.some((p) => p.startsWith("-"))) return { ok: false, reason: "yol bölümü '-' ile başlayamaz" };
  return { ok: true, rel: input };
}

const HARD_DENY: readonly [RegExp, string][] = [
  [/(^|\/)\.git(\/|$)/, ".git içeriği"],
  [/(^|\/)\.terraform(\/|$)/, ".terraform dizini (sağlayıcı/modül önbelleği)"],
  [/\.tfstate(\.backup)?$/, "Terraform state"],
  [/\.tfvars(\.json)?$/, "Terraform değişken dosyası (değer taşır)"],
  [/(^|\/)\.env(\..*)?$/, ".env dosyası"],
  [/\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|gpg|asc)$/, "özel anahtar/sertifika dosyası"],
  [/(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/, "SSH anahtarı"],
  [/(^|\/)\.(npmrc|netrc|pypirc|git-credentials)$/, "kimlik dosyası"],
  [/(^|\/)\.aws(\/|$)|(^|\/)\.kube(\/|$)|(^|\/)\.docker(\/|$)|(^|\/)\.ssh(\/|$)/, "kimlik dizini"],
  [/(^|\/)kubeconfig(\.|$)/, "kubeconfig"],
  [/(^|\/)secrets?\.(ya?ml|json|toml|env)$/, "secrets dosyası"],
  [/(^|\/)credentials?(\.|$)/, "credentials dosyası"],
  [/vault[^/]*\.ya?ml$|(^|\/)\.vault[^/]*$|(^|\/)(group_vars|host_vars)\/(?:[^/]+\/)*[^/]*vault[^/]*$/, "Ansible vault dosyası"],
];

/** Yazma yasak (okuma serbest): CI tanımları ve kod çalıştıran araç yapılandırmaları. */
const WRITE_DENY: readonly [RegExp, string][] = [
  [/^\.github(\/|$)/, "CI/pipeline tanımı (.github)"],
  [/^\.gitlab-ci\.ya?ml$|^\.gitlab(\/|$)/, "CI/pipeline tanımı (GitLab)"],
  [/(^|\/)Jenkinsfile$/, "CI/pipeline tanımı (Jenkinsfile)"],
  [/(^|\/)azure-pipelines[^/]*\.ya?ml$/, "CI/pipeline tanımı (Azure)"],
  [/^\.circleci(\/|$)|(^|\/)bitbucket-pipelines\.ya?ml$|(^|\/)\.drone\.ya?ml$|(^|\/)\.travis\.ya?ml$|(^|\/)buildkite[^/]*\.ya?ml$/, "CI/pipeline tanımı"],
  [/(^|\/)ansible\.cfg$|(^|\/)\.ansible-lint(\.ya?ml)?$|(^|\/)\.ansible(\/|$)/, "Ansible yapılandırması (eklenti/kural yolu yükleyebilir)"],
  [/(^|\/)(library|action_plugins|callback_plugins|connection_plugins|filter_plugins|lookup_plugins|inventory_plugins|module_utils|vars_plugins|strategy_plugins|become_plugins|cache_plugins|test_plugins|netconf_plugins|terminal_plugins|doc_fragments|httpapi_plugins|cliconf_plugins|ansible_collections)\//, "Ansible eklenti/modül dizini (kod çalıştırır)"],
  [/(^|\/)\.tflint\.hcl$|(^|\/)\.terraformrc$|(^|\/)terraform\.rc$|(^|\/)\.terraform\.d(\/|$)|(^|\/)\.checkov\.ya?ml$/, "araç yapılandırması (eklenti yükleyebilir)"],
  [/(^|\/)\.tool-versions$|(^|\/)\.envrc$|(^|\/)\.pre-commit-config\.ya?ml$|(^|\/)\.gitattributes$|(^|\/)\.gitmodules$/, "ortam/kanca yapılandırması"],
];

/** `**` (her şey, `/` dahil), `*` (`/` hariç), `?` destekleyen yol globu. */
export function pathGlob(pattern: string, value: string): boolean {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i += 1;
        if (pattern[i + 1] === "/") i += 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`).test(value);
}

export interface PathPolicy {
  readonly writePaths: readonly string[];
  readonly denyPaths: readonly string[];
}

export function readCheck(input: string, policy: PathPolicy): PathCheck {
  const n = normalizeRel(input);
  if (!n.ok) return n;
  for (const [re, why] of HARD_DENY) if (re.test(n.rel.toLowerCase())) return { ok: false, reason: `gizli dosya deseni: ${why}` };
  if (policy.denyPaths.some((g) => pathGlob(g, n.rel))) return { ok: false, reason: "çalışma alanı denyPaths kuralı" };
  return n;
}

export function writeCheck(input: string, policy: PathPolicy): PathCheck {
  const r = readCheck(input, policy);
  if (!r.ok) return r;
  for (const [re, why] of WRITE_DENY) if (re.test(r.rel)) return { ok: false, reason: `yazma yasak: ${why}` };
  if (!policy.writePaths.some((g) => pathGlob(g, r.rel))) return { ok: false, reason: "çalışma alanı writePaths dışında" };
  return r;
}
