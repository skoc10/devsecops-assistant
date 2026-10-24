import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";

const run = promisify(execFile);

export interface TestRepo {
  readonly dir: string;
  readonly root: string;
  /** Tuzak dosyaları: git yapılandırması bunların oluşturulmasına yol açarsa güvenlik ihlalidir. */
  readonly markers: { readonly smudge: string; readonly fsmonitor: string; readonly hook: string };
  cleanup(): Promise<void>;
}

export const SECRET_TFVARS = `db_password = "${randomBytes(8).toString("hex")}-tfvars"\n`;

/**
 * Gerçek bir git deposu: gizli dosyalar, sembolik bağ, çalıştırılabilir betik, büyük dosya, Unicode adlı dosya
 * ve (kötü niyetli) `smudge` süzgeci / fsmonitor / kanca yapılandırması. Anlık kopya bunları ÇALIŞTIRMAMALIDIR.
 */
export async function makeRepo(extra: Record<string, string> = {}): Promise<TestRepo> {
  const root = await mkdtemp(join(tmpdir(), "ops-ws-"));
  const dir = join(root, "repo");
  await mkdir(dir);
  const git = (...args: string[]) => run("git", args, { cwd: dir, env: { PATH: process.env["PATH"] ?? "", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" } });
  await git("init", "-q", "-b", "main");
  const markers = { smudge: join(root, "SMUDGE-RAN"), fsmonitor: join(root, "FSMONITOR-RAN"), hook: join(root, "HOOK-RAN") };
  const files: Record<string, string> = {
    "main.tf": 'terraform {\n  required_version = ">= 1.5"\n}\n\nresource "terraform_data" "x" {\n  input = "hello"\n}\n',
    "variables.tf": 'variable "name" {\n  type    = string\n  default = "demo"\n}\n',
    "modules/vpc/main.tf": 'variable "cidr" {\n  type = string\n}\n\noutput "cidr" {\n  value = var.cidr\n}\n',
    "README.md": "# demo\n\nHello.\n",
    "prod.tfvars": SECRET_TFVARS,
    ".env": "TOKEN=should-never-be-copied\n",
    "terraform.tfstate": '{"version":4,"secret":"state-secret"}\n',
    "deploy/key.pem": "-----BEGIN PRIVATE KEY-----\nMIIBVQ\n-----END PRIVATE KEY-----\n",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    "big.bin": "x".repeat(2_000_000),
    "çalışma.tf": "# unicode ad\n",
    ".gitattributes": "*.tf filter=evil\n",
    "run.sh": "#!/bin/sh\necho hi\n",
    ...extra,
  };
  for (const [p, c] of Object.entries(files)) {
    await mkdir(dirname(join(dir, p)), { recursive: true });
    await writeFile(join(dir, p), c);
  }
  await chmod(join(dir, "run.sh"), 0o755);
  await symlink("/etc/passwd", join(dir, "link"));
  await git("add", "-A");
  await git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "init");
  // kötü niyetli yapılandırma COMMIT'TEN SONRA eklenir (yalnız .git/config ve hooks)
  await git("config", "filter.evil.smudge", `sh -c 'touch ${markers.smudge}; cat'`);
  await git("config", "filter.evil.clean", `sh -c 'touch ${markers.smudge}; cat'`);
  await git("config", "core.fsmonitor", `sh -c 'touch ${markers.fsmonitor}; echo'`);
  const hooks = join(dir, ".git", "hooks");
  for (const h of ["post-checkout", "post-commit", "pre-commit", "post-merge", "reference-transaction"]) {
    await writeFile(join(hooks, h), `#!/bin/sh\ntouch ${markers.hook}\n`, { mode: 0o755 });
  }
  return { dir, root, markers, cleanup: () => rm(root, { recursive: true, force: true }) };
}
