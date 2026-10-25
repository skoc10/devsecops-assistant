import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemorySecretStore } from "@ops/broker";
import type { ApprovalGate, ApprovalRequest } from "@ops/contracts";
import type { OrchestratorEvent } from "@ops/core";
import { GUEST_NODE, detectSandbox, fsOf } from "@ops/sandbox";
import { CaptureSink, ScriptedProvider, makeCanary, say, toolUse } from "@ops/testkit";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";
import { createRuntime, renderEvent, resolvePaths, runCli } from "../src/index.ts";
import { idsIn } from "./fixture.ts";

const run = promisify(execFile);
const sandbox = await detectSandbox();
const TOOL_DIRS = [...(process.env["OPS_TOOL_DIRS"]?.split(":") ?? []), "/opt/ops-tools/bin", "/opt/ops-tools/venv/bin", "/usr/local/bin", "/usr/bin"];
// araçlar sandbox'ın gördüğü dosya sisteminde aranır (VM kipinde konuk; ADR-0011 §6)
const hasTool = async (n: string): Promise<boolean> => {
  for (const d of TOOL_DIRS) if (await fsOf(sandbox).executable(join(d, n))) return true;
  return false;
};
const ok = !!sandbox && (await hasTool("tofu")) && (await hasTool("git"));
// MCP köprüsü: VM kipinde sunucu konuk Node'uyla ve paylaşım (TMPDIR) altına kopyalanan betikle çalışır (ADR-0011)
const mockServer = await (async () => {
  const src = fileURLToPath(new URL("../../mcp-bridge/test/mock-server.mjs", import.meta.url));
  if (sandbox?.kind !== "vm") return src;
  const d = await mkdtemp(join(tmpdir(), "ops-mcpe2e-share-"));
  await copyFile(src, join(d, basename(src)));
  return join(d, basename(src));
})();
const nodeBin = sandbox?.kind === "vm" ? GUEST_NODE : process.execPath;
const nodeSha = sandbox ? ((await fsOf(sandbox).sha256(nodeBin)) ?? "") : "";

const io = () => ({ input: new PassThrough(), output: new PassThrough(), error: new PassThrough() });
const text = (s: PassThrough): string => (s.read() as Buffer | null)?.toString("utf8") ?? "";

class AutoGate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  async request(req: ApprovalRequest) {
    this.requests.push(req);
    return { approved: true, approvalId: `a${this.requests.length}`, actionHash: req.actionHash } as const;
  }
}

const VPC_MODULE = 'variable "cidr" {\n  type        = string\n  description = "VPC CIDR"\n}\n\nresource "terraform_data" "vpc" {\n  input = var.cidr\n}\n\noutput "vpc_id" {\n  value = terraform_data.vpc.id\n}\n';
const NETWORK = 'module "vpc" {\n  source = "./modules/vpc2"\n  cidr   = "10.0.0.0/16"\n}\n';

let home = "";
let repo: TestRepo;
const canaries = { state: makeCanary("tfstate"), tfvars: makeCanary("tfvars"), env: makeCanary("dotenv"), secretsYaml: makeCanary("secretsyaml") };

beforeAll(async () => {
  home = await mkdtemp(join(tmpdir(), "ops-iace2e-"));
  repo = await makeRepo({
    "terraform.tfstate": JSON.stringify({ version: 4, resources: [], outputs: { leak: { value: canaries.state.value } } }),
    "prod.tfvars": `db_password = "${canaries.tfvars.value}"\n`,
    ".env": `TOKEN=${canaries.env.value}\n`,
    "secrets.yaml": `password: ${canaries.secretsYaml.value}\n`,
  });
});
afterAll(async () => {
  await repo?.cleanup();
  await rm(home, { recursive: true, force: true });
});

describe.skipIf(!ok)("Faz 1b: IaC — CLI + runtime uçtan uca (gerçek git, gerçek bubblewrap, gerçek OpenTofu)", () => {
  const paths = resolvePaths(join(tmpdir(), `ops-iace2e-home-${process.pid}`));
  const store = new MemorySecretStore();

  async function cli(argv: string[], env: Record<string, string> = {}) {
    const i = io();
    const code = await runCli({ argv, env: { HOME: home, ...env }, io: i, paths, store, sandbox: "detect" });
    return { code, out: text(i.output), err: text(i.error) };
  }

  it("ops workspace add/list: kayıt ve hatalı girdiler", async () => {
    const add = await cli(["workspace", "add", "--id", "infra", "--path", repo.dir, "--engine", "opentofu"]);
    expect(add.code, add.err).toBe(0);
    expect(add.out).toContain("Çalışma alanı kaydedildi: infra (opentofu");
    expect(add.out).toMatch(/deponuza YAZMAZ/);
    expect((await cli(["workspace", "list"])).out).toMatch(/^infra\topentofu\t.*\tyazılabilir \*\*/m);

    expect((await cli(["workspace", "add", "--id", "x", "--path", repo.dir, "--engine", "puppet"])).code).toBe(2);
    expect((await cli(["workspace", "add", "--id", "x", "--engine", "ansible"])).code).toBe(2);
    const plain = await mkdtemp(join(tmpdir(), "ops-nogit-"));
    const nogit = await cli(["workspace", "add", "--id", "nogit", "--path", plain, "--engine", "ansible"]);
    expect(nogit.code).toBe(1);
    expect(nogit.err).toMatch(/workspace_not_git/);
    await rm(plain, { recursive: true, force: true });
    // ev dizini (ve üstü) kayıt edilemez
    const homeReg = await cli(["workspace", "add", "--id", "h", "--path", home, "--engine", "ansible"], { HOME: home });
    expect(homeReg.code).toBe(1);
    expect(homeReg.err).toMatch(/ev dizini/);
    // yinelenen kimlik
    expect((await cli(["workspace", "add", "--id", "infra", "--path", repo.dir, "--engine", "opentofu"])).err).toMatch(/workspace_exists/);
  });

  it("chat --workspace yalnız --embedded/daemon ile; çalışma alanı olmadan IaC skill'i görünmez", async () => {
    const bad = await cli(["chat", "--workspace", "infra"]);
    expect(bad.code).toBe(2);
    expect(bad.err).toMatch(/--embedded/);
    const rt = await createRuntime({ paths, store, sandbox: "detect" });
    try {
      expect(rt.skills.all().map((s) => s.name)).not.toContain("terraform");
      expect(rt.skills.all().map((s) => s.name)).not.toContain("ansible");
    } finally {
      await rt.close();
    }
  });

  it("Faz 1b bitiş senaryosu: skill → keşif → yaz → fmt → validate (hata → düzelt) → ön-tarama engeli → diff; canary hiçbir kanalda yok", async () => {
    const gate = new AutoGate();
    const rt = await createRuntime({ paths, store, sandbox: "detect", workspace: "infra", toolDirs: TOOL_DIRS, approval: gate });
    const ev: OrchestratorEvent[] = [];
    let provider!: ScriptedProvider;
    try {
      expect(rt.skills.all().map((s) => s.name)).toEqual(expect.arrayContaining(["terraform"]));
      expect(rt.skills.all().map((s) => s.name)).not.toContain("ansible"); // motor opentofu
      provider = new ScriptedProvider(
        [
          toolUse([{ name: "skill.load", args: { name: "terraform" } }]),
          toolUse([{ name: "iac.project.inspect", args: {} }]),
          toolUse([{ name: "fs.write", args: { path: "modules/vpc2/main.tf", content: VPC_MODULE } }]),
          toolUse([{ name: "fs.write", args: { path: "network.tf", content: NETWORK } }]),
          toolUse([{ name: "fs.write", args: { path: "bad.tf", content: 'output "o" {\nvalue = var.undeclared\n}\n' } }]),
          // yasak yollar tek turda: hepsi reddedilir, hiçbiri sızdırmaz
          toolUse([
            { name: "fs.write", args: { path: ".github/workflows/x.yml", content: "name: x\n" } },
            { name: "fs.read", args: { path: "terraform.tfstate" } },
            { name: "fs.read", args: { path: "prod.tfvars" } },
            { name: "fs.read", args: { path: ".env" } },
            { name: "fs.read", args: { path: "secrets.yaml" } },
            { name: "fs.write", args: { path: "leak.tf", content: 'provider "aws" {\n  access_key = "AKIAABCDEFGHIJKLMNOP"\n}\n' } },
          ]),
          toolUse([{ name: "iac.validate", args: {} }]),
          toolUse([{ name: "fs.write", args: { path: "bad.tf", content: 'output "o" {\nvalue=var.name\n}\n' } }]),
          toolUse([{ name: "iac.fmt", args: {} }]),
          toolUse([{ name: "iac.validate", args: {} }]),
          // kod çalıştıran yapı: araç ÇALIŞMAZ
          toolUse([{ name: "fs.write", args: { path: "prov.tf", content: 'resource "terraform_data" "p" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n' } }]),
          toolUse([{ name: "iac.validate", args: {} }]),
          toolUse([{ name: "fs.write", args: { path: "prov.tf", content: "# provisioner kaldırıldı\n" } }]),
          toolUse([{ name: "iac.validate", args: {} }, { name: "fs.diff", args: {} }]),
          (req) => {
            const ids = idsIn(req.messages);
            return say(`VPC modülü ve çağıran kök modül yazıldı; fmt ve validate geçti [${ids.at(-2)}]. Değişiklikler [${ids.at(-1)}]. provisioner ön-tarama tarafından engellendi ve kaldırıldı.`);
          },
        ],
        { trustZone: "tenant-cloud" },
      );
      const orch = rt.createOrchestrator(provider, { maxIterations: 30 });
      for await (const e of orch.send("Küçük bir VPC modülü ve onu çağıran kök modül yaz.")) ev.push(e);

      const results = ev.filter((e): e is Extract<OrchestratorEvent, { type: "tool_result" }> => e.type === "tool_result");
      const byName = (n: string) => results.filter((r) => r.name === n);
      expect(byName("skill.load")[0]?.status).toBe("ok");
      expect(byName("iac.project.inspect")[0]?.status).toBe("ok");
      // yazımlar: ilk yazımda onay, sonra oturum izni (taint'siz)
      expect(byName("fs.write").filter((r) => r.status === "ok").length).toBeGreaterThanOrEqual(6);
      expect(gate.requests.length).toBeGreaterThanOrEqual(1);
      expect(gate.requests[0]?.summary.tool).toBe("fs.write");
      // yasak yollar reddedildi
      const denied = [...byName("fs.read"), ...byName("fs.write")].filter((r) => r.status !== "ok");
      expect(denied.length).toBeGreaterThanOrEqual(6);
      // validate sırası: hata → geçerli → ENGELLİ → geçerli
      const vals = byName("iac.validate").map((r) => r.summary);
      expect(vals[0]).toMatch(/geçersiz/);
      expect(vals[1]).toMatch(/geçerli/);
      expect(vals[2]).toMatch(/ÇALIŞMADI|engelleyici/);
      expect(vals[3]).toMatch(/geçerli/);
      expect(byName("iac.fmt")[0]?.status).toBe("ok");

      const final = ev.find((e) => e.type === "final");
      expect(final).toBeTruthy();
      if (final?.type === "final") expect(final.citations.invalid).toEqual([]);

      // kullanıcının deposu DEĞİŞMEDİ, tuzak yapılandırma çalışmadı
      // ÖNCE işaretler (testin kendi `git status`'u tuzak süzgeci çalıştırır: o yüzden güvenli yapılandırmayla ve SONRA)
      for (const m of Object.values(repo.markers)) expect(existsSync(m), m).toBe(false);
      const status = await run("git", ["-c", "filter.evil.clean=cat", "-c", "filter.evil.smudge=cat", "-c", "core.fsmonitor=false", "status", "--porcelain"], { cwd: repo.dir, env: { PATH: process.env["PATH"] ?? "", HOME: home } });
      expect(status.stdout.trim()).toBe("");

      // tüm kanallarda canary yok
      const sink = new CaptureSink();
      sink.push("audit", await readFile(paths.auditLog, "utf8"));
      for (const e of rt.evidence.all()) sink.push("evidence", e.text);
      sink.push("sağlayıcı-baytları", provider.serialized.join("\n"));
      sink.push("ui", ev.map((e) => renderEvent(e) ?? "").join("\n"));
      expect(sink.leaks(Object.values(canaries))).toEqual([]);
      // modelin KENDİ önerdiği (reddedilen) anahtar benzeri değer denetime ve kanıta GİRMEZ. (Arayüzde modelin önerdiği
      // çağrı olduğu gibi gösterilir ve sağlayıcıya modelin kendi çıktısı olarak geri yansır: yeni bir sızıntı değildir.)
      for (const ch of ["audit", "evidence"]) expect(sink.text(ch), ch).not.toContain("AKIAABCDEFGHIJKLMNOP");
    } finally {
      await rt.close();
    }
  }, 240_000);

  it("ops workspace snapshots/diff/export: yama gerçek depo klonuna `git apply` ile uygulanır; canary yamada yok; üzerine yazma yok", async () => {
    const snaps = await cli(["workspace", "snapshots", "infra"]);
    expect(snaps.out).toMatch(/^infra\toturum \S+\t\d{4}-.*\tHEAD [0-9a-f]{12}/m);
    const diff = await cli(["workspace", "diff", "infra"]);
    expect(diff.code, diff.err).toBe(0);
    expect(diff.out).toMatch(/\+ modules\/vpc2\/main\.tf/);
    expect(diff.out).toMatch(/\+ network\.tf/);
    expect(diff.out).toMatch(/\+ bad\.tf/);
    expect(diff.out).toContain('+  source = "./modules/vpc2"');
    expect(diff.out).toContain("value = var.name"); // fmt sonrası biçim
    expect(diff.out).not.toContain(".github");
    expect(diff.out).not.toContain("leak.tf");

    const patchFile = join(home, "infra.patch");
    const exp = await cli(["workspace", "export", "infra", "--out", patchFile]);
    expect(exp.code, exp.err).toBe(0);
    expect(exp.out).toMatch(/git apply --check/);
    const again = await cli(["workspace", "export", "infra", "--out", patchFile]);
    expect(again.code).toBe(1);
    expect(again.err).toMatch(/zaten var/);
    const patch = await readFile(patchFile, "utf8");
    for (const c of Object.values(canaries)) expect(patch).not.toContain(c.value);

    // gerçek git: temiz klon + git apply
    const clone = join(home, "clone");
    const env = { PATH: process.env["PATH"] ?? "", HOME: home, GIT_CONFIG_NOSYSTEM: "1" };
    await run("git", ["clone", "-q", repo.dir, clone], { env });
    await run("git", ["-c", "core.hooksPath=/dev/null", "apply", "--check", patchFile], { cwd: clone, env });
    await run("git", ["-c", "core.hooksPath=/dev/null", "apply", patchFile], { cwd: clone, env });
    expect(readFileSync(join(clone, "network.tf"), "utf8")).toBe(NETWORK);
    expect(readFileSync(join(clone, "modules/vpc2/main.tf"), "utf8")).toBe(VPC_MODULE);
    expect(readFileSync(join(clone, "bad.tf"), "utf8")).toBe('output "o" {\n  value = var.name\n}\n');
    expect(existsSync(join(clone, ".github/workflows/x.yml"))).toBe(false); // ajan CI tanımı YAZAMADI
    expect(readFileSync(join(clone, ".github/workflows/ci.yml"), "utf8")).toBe("name: ci\non: push\njobs: {}\n"); // özgün dosya değişmedi
    expect(existsSync(join(clone, "leak.tf"))).toBe(false);
    // yamanın kendisi de aynı sonuca götürür: sha256 karşılaştırması
    expect(createHash("sha256").update(readFileSync(join(clone, "network.tf"))).digest("hex")).toBe(createHash("sha256").update(NETWORK).digest("hex"));
  });

  it("diff/export hataları: bilinmeyen çalışma alanı, anlık kopya yok, bilinmeyen oturum", async () => {
    expect((await cli(["workspace", "diff", "nope"])).err).toMatch(/workspace_not_found/);
    expect((await cli(["workspace", "diff", "infra", "--session", "yok-oturum"])).err).toMatch(/snapshot_not_found/);
    expect((await cli(["workspace", "export", "infra"])).code).toBe(2);
    expect((await cli(["workspace", "rm", "nope"])).code).toBe(1);
  });

  it("audit verify: IaC oturumundan sonra zincir DOĞRU", async () => {
    const v = await cli(["audit", "verify"]);
    expect(v.code, v.out + v.err).toBe(0);
    expect(v.out).toMatch(/Denetim zinciri DOĞRU/);
  });
});

describe.skipIf(!sandbox)("Faz 1b: MCP köprüsü — CLI + runtime", () => {
  const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");
  const paths = resolvePaths(join(tmpdir(), `ops-mcpe2e-home-${process.pid}`));
  const store = new MemorySecretStore();

  const manifest = (nodeSha: string): string =>
    [
      "servers:",
      "  - id: mock",
      `    command: ${nodeBin}`,
      `    sha256: ${nodeSha}`,
      `    args: [${mockServer}]`,
      "    files:",
      `      - { path: ${mockServer}, sha256: ${sha(mockServer)} }`,
      "    env: { MOCK_MODE: normal }",
      "    toolset: iac",
      "    tools:",
      "      - { name: echo, description: Metni geri yansıtır., args: { text: { type: string, required: true, maxLength: 100 } } }",
      "      - { name: danger, description: Sunucuda var ama manifestte read.  }",
      "",
    ].join("\n");

  async function cli(argv: string[]) {
    const i = io();
    const code = await runCli({ argv, env: {}, io: i, paths, store, sandbox: "detect" });
    return { code, out: text(i.output), err: text(i.error) };
  }

  it("ops mcp check: manifest yok → açık hata; geçerli manifest → ✓; yanlış pin → ✗ ve sunucu başlamaz", async () => {
    expect((await cli(["mcp", "check"])).err).toMatch(/mcp_manifest_missing/);
    await createRuntime({ paths, store, sandbox: null }).then((r) => r.close()); // OPS_HOME oluştur
    await writeFile(paths.mcpManifestFile, manifest(nodeSha), { mode: 0o600 });
    const good = await cli(["mcp", "check"]);
    expect(good.code, good.out + good.err).toBe(0);
    expect(good.out).toMatch(/✓ mock \(mock-server, protokol 2025-06-18\)/);
    expect(good.out).toMatch(/manifestte olmayan \d+ sunucu aracı \(açılmaz\)/);
    await writeFile(paths.mcpManifestFile, manifest("0".repeat(64)), { mode: 0o600 });
    const bad = await cli(["mcp", "check"]);
    expect(bad.code).toBe(1);
    expect(bad.out + bad.err).toMatch(/✗ mock.*pini uyuşmuyor/);
    await writeFile(paths.mcpManifestFile, "servers: []\n");
    expect((await cli(["mcp", "check"])).err).toMatch(/manifest geçersiz/);
  });

  it("runtime: manifest varsa araçlar kayıtlı ve PEP altında çağrılır; geçersiz manifest oturumu BAŞLATMAZ; toolset 'iac' ile skill'e bağlanabilir", async () => {
    await writeFile(paths.mcpManifestFile, manifest(nodeSha), { mode: 0o600 });
    const rt = await createRuntime({ paths, store, sandbox: "detect" });
    try {
      expect(rt.mcp?.definitions.map((d) => d.descriptor.name)).toEqual(["mcp.mock.echo", "mcp.mock.danger"]);
      expect(rt.mcp?.definitions[0]?.descriptor.toolset).toBe("iac");
      const r = await rt.gateway.invoke({ tool: "mcp.mock.echo", args: { text: "selam" }, providerZone: "local" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      expect(rt.session.context.tainted).toBe(true);
    } finally {
      await rt.close();
    }
    await writeFile(paths.mcpManifestFile, "servers: [ { id: BAD } ]\n");
    await expect(createRuntime({ paths, store, sandbox: "detect" })).rejects.toThrow(/manifest geçersiz/);
    await rm(paths.mcpManifestFile, { force: true });
  }, 60_000);
});
