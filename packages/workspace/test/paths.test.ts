import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { normalizeRel, pathGlob, readCheck, writeCheck } from "../src/index.ts";

const P = { writePaths: ["**"], denyPaths: [] as string[] };

describe("normalizeRel", () => {
  it("güvenli göreli yollar", () => {
    for (const ok of ["main.tf", "modules/vpc/main.tf", "roles/web/tasks/main.yml", "a-b_c.d/e@1+2=3.tf"]) expect(normalizeRel(ok), ok).toEqual({ ok: true, rel: ok });
  });
  it.each([
    ["boş", ""], ["mutlak", "/etc/passwd"], ["üst dizin", "../x"], ["ortada ..", "a/../b"], ["nokta bölüm", "a/./b"], ["çift eğik çizgi", "a//b"],
    ["sondaki eğik çizgi", "a/"], ["ters eğik çizgi", "a\\b"], ["boşluk", "a b"], ["unicode", "çalışma.tf"], ["NUL", "a\0b"], ["yeni satır", "a\nb"],
    ["tire ile başlayan bölüm", "a/-rf"], ["çok uzun", "x".repeat(201)], ["kabuk meta", "a;b"], ["backtick", "a`b"], ["dolar", "a$b"],
  ])("reddedilir: %s", (_n, p) => {
    expect(normalizeRel(p as string).ok).toBe(false);
  });
});

describe("okuma/yazma politikası", () => {
  it.each([
    ".git/config", "a/.git/hooks/pre-commit", ".terraform/providers/x", "terraform.tfstate", "x.tfstate.backup", "prod.tfvars", "prod.auto.tfvars", "prod.tfvars.json",
    ".env", "app/.env.production", "deploy/key.pem", "id_rsa", "home/id_ed25519.pub", ".npmrc", ".aws/credentials", ".kube/config", "kubeconfig", "kubeconfig.yaml",
    "secrets.yaml", "config/credentials.json", "vault.yml", "group_vars/all/vault.yml", "inventory/group_vars/web/vault",
  ])("sert ret (okuma ve yazma): %s", (p) => {
    expect(readCheck(p, P).ok, p).toBe(false);
    expect(writeCheck(p, P).ok, p).toBe(false);
  });

  it.each([
    ".github/workflows/ci.yml", ".github/CODEOWNERS", ".gitlab-ci.yml", "Jenkinsfile", "ci/Jenkinsfile", "azure-pipelines.yml", "azure-pipelines-prod.yaml", ".circleci/config.yml",
    "ansible.cfg", "roles/x/library/mod.py", "action_plugins/a.py", "filter_plugins/f.py", ".ansible-lint", ".tflint.hcl", ".terraformrc", ".terraform.d/plugins/x",
    ".envrc", ".pre-commit-config.yaml", ".gitattributes", ".gitmodules",
  ])("okunur ama YAZILAMAZ: %s", (p) => {
    expect(readCheck(p, P).ok, p).toBe(true);
    expect(writeCheck(p, P).ok, p).toBe(false);
  });

  it.each([".GitHub/workflows/deploy.yml", ".GITHUB/workflows/ci.yml", "JenkinsFile", "ci/JENKINSFILE", ".Envrc", "roles/x/Library/mod.py", ".Terraformrc", "Ansible.cfg", ".GitLab-CI.yml"])(
    "yazma yasağı harfe duyarsız (APFS'te aynı dosya): %s",
    (p) => {
      expect(writeCheck(p, P).ok, p).toBe(false);
    },
  );

  it("denyPaths harfe duyarsız, writePaths duyarlı (güvenli yön)", () => {
    const narrow = { writePaths: ["modules/**"], denyPaths: ["modules/legacy/**"] };
    expect(readCheck("modules/Legacy/x.tf", narrow).ok).toBe(false);
    expect(writeCheck("MODULES/LEGACY/x.tf", narrow).ok).toBe(false);
    expect(writeCheck("Modules/vpc/main.tf", narrow).ok).toBe(false);
  });

  it("serbest yollar yazılabilir; writePaths ve denyPaths globları", () => {
    for (const ok of ["main.tf", "modules/vpc/variables.tf", "playbooks/site.yml", "terraform.tfvars.example", "environment.md", "key-concepts.md", "secretary.tf"]) {
      expect(writeCheck(ok, P).ok, ok).toBe(true);
    }
    const narrow = { writePaths: ["modules/**", "*.tf"], denyPaths: ["modules/legacy/**"] };
    expect(writeCheck("modules/vpc/main.tf", narrow).ok).toBe(true);
    expect(writeCheck("main.tf", narrow).ok).toBe(true);
    expect(writeCheck("docs/readme.md", narrow)).toEqual({ ok: false, reason: "çalışma alanı writePaths dışında" });
    expect(writeCheck("modules/legacy/x.tf", narrow).ok).toBe(false);
    expect(readCheck("modules/legacy/x.tf", narrow).ok).toBe(false);
    expect(readCheck("modules/vpc/main.tf", narrow).ok).toBe(true);
  });

  it("pathGlob: ** / * / ? ve regex enjeksiyonuna kapalı", () => {
    expect(pathGlob("**", "a/b/c.tf")).toBe(true);
    expect(pathGlob("*.tf", "a/b.tf")).toBe(false);
    expect(pathGlob("*.tf", "b.tf")).toBe(true);
    expect(pathGlob("modules/**/main.tf", "modules/a/b/main.tf")).toBe(true);
    expect(pathGlob("modules/**/main.tf", "modules/main.tf")).toBe(true);
    expect(pathGlob("a?.tf", "ab.tf")).toBe(true);
    expect(pathGlob("a.tf", "abtf")).toBe(false);
    expect(pathGlob("(a|b).tf", "a.tf")).toBe(false);
    expect(pathGlob("a[bc].tf", "ab.tf")).toBe(false);
  });

  it("özellik: kabul edilen her yol normal, '..' içermez, mutlak değildir ve sert ret desenlerine uymaz", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }), (s) => {
        const r = writeCheck(s, P);
        if (!r.ok) return true;
        return !r.rel.startsWith("/") && !r.rel.split("/").some((x) => x === ".." || x === "." || x === "") && !/\.git(\/|$)/.test(r.rel) && !/\.tfstate/.test(r.rel) && !r.rel.startsWith(".github");
      }),
      { numRuns: 3000 },
    );
  });
});
