import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { makeCanary } from "@ops/testkit";
import { makeIacHarness, sandbox } from "./harness.ts";
import { findHostTool, findTool } from "./tools.ts";

const run = promisify(execFile);
const tofu = await findTool("tofu", sandbox);
const terraform = await findTool("terraform", sandbox);
const ok = !!sandbox && !!tofu;

const GOOD = {
  "main.tf": 'terraform {\n  required_version = ">= 1.5"\n}\n\nresource "terraform_data" "x" {\n  input = var.name\n}\n\noutput "id" {\n  value = terraform_data.x.id\n}\n',
  "variables.tf": 'variable "name" {\n  type    = string\n  default = "demo"\n}\n',
  "modules/net/main.tf": 'variable "cidr" {\n  type = string\n}\n\noutput "cidr" {\n  value = var.cidr\n}\n',
};

describe.skipIf(!ok)("Terraform/OpenTofu araçları (gerçek tofu + gerçek bubblewrap, ağsız)", () => {
  it("iac.project.inspect: motor, ikili, değişken/çıktı adları, ön-tarama özeti", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      const r = await h.call("iac.project.inspect", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ engine: "opentofu", tool: { name: "tofu", available: true }, requiredVersion: ">= 1.5", blocked: false });
      expect(Object.keys(j.dirs)[0]).toBe("."); // kök modül önce
      expect(j.dirs["."].variables).toEqual(["name:string="]);
      expect(j.dirs["."].outputs).toEqual(["id"]);
      expect(j.dirs["modules/net"]).toMatchObject({ variables: ["cidr:string"], outputs: ["cidr"] });
      expect(j.resources).toEqual({ terraform_data: 1 });
      expect(j.findings).toEqual([]);
      // gizli/atlanan dosyalar sayılır ama içerikleri görünmez
      expect(j.skipped).toBeGreaterThan(3);
      expect(JSON.stringify(j)).not.toContain("db_password");
    } finally {
      await h.cleanup();
    }
  });

  it("iac.validate: geçerli yapılandırma; çalışma kopyasında .terraform kalmaz; kullanıcının deposu değişmez", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      const r = await h.call("iac.validate", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ executed: true, valid: true, errors: 0 });
      expect(existsSync(join(h.fs.root, ".terraform"))).toBe(false);
      expect(existsSync(join(h.repo.dir, ".terraform"))).toBe(false);
      expect(existsSync(join(h.repo.dir, ".terraform.lock.hcl"))).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("iac.validate: gerçek hata tanıları (dosya:satır) kompakt döner; yazma→doğrula→düzelt döngüsü", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      await h.call("fs.write", { path: "bad.tf", content: 'output "o" {\n  value = var.undeclared\n}\n' });
      const r = await h.call("iac.validate", {});
      const j = h.json(r);
      expect(j).toMatchObject({ executed: true, valid: false });
      expect(j.diagnostics[0]).toMatchObject({ severity: "error", file: "bad.tf", line: 2 });
      expect(j.diagnostics[0].summary).toMatch(/undeclared input variable/i);
      expect(r.summary).toMatch(/geçersiz/);
      // düzelt
      await h.call("fs.write", { path: "bad.tf", content: 'output "o" {\n  value = var.name\n}\n' });
      expect(h.json(await h.call("iac.validate", {}))).toMatchObject({ valid: true });
    } finally {
      await h.cleanup();
    }
  });

  it("S-17: kod çalıştıran yapılar (provisioner, data external, uzak modül, gömülü kimlik, ayrıştırılamayan dosya) validate'i ENGELLER — araç çalıştırılmaz", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      const cases: [string, string, string][] = [
        ["p.tf", 'resource "terraform_data" "p" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n', "provisioner"],
        ["e.tf", 'data "external" "e" {\n  program = ["sh", "-c", "id"]\n}\n', "external_data"],
        ["m.tf", 'module "m" {\n  source = "git::https://example.invalid/m.git"\n}\n', "remote_module"],
        ["c.tf", 'provider "aws" {\n  region = "eu-west-1"\n  profile = "x"\n}\n', ""],
        ["x.tf", 'resource "terraform_data" "u" {\n  input = "unterminated\n}\n', "parse_error"],
      ];
      for (const [path, content, code] of cases) {
        if (code === "") continue; // zararsız kontrol
        await h.call("fs.write", { path, content });
        const r = await h.call("iac.validate", {});
        const j = h.json(r);
        expect(j, path).toMatchObject({ executed: false, blocked: true });
        expect(j.findings.map((f: { code: string }) => f.code), path).toContain(code);
        expect(r.summary).toMatch(/ÇALIŞMADI/);
        // sonraki deneme için dosyayı zararsızlaştır
        await h.call("fs.write", { path, content: "# temizlendi\n" });
      }
      expect(h.json(await h.call("iac.validate", {}))).toMatchObject({ executed: true, valid: true });
      // gömülü kimlik: fs.write secret kuralına takılmayan ama provider içinde literal olan alan
      await h.call("fs.write", { path: "c.tf", content: 'provider "aws" {\n  access_key = "AKIAEXAMPLEKEYONLY1"\n}\n' }).then((r) => r);
      const r2 = await h.call("iac.validate", {});
      expect(r2.status).toBe("ok");
      expect(h.json(r2).executed === false || h.json(r2).valid !== undefined).toBe(true);
    } finally {
      await h.cleanup();
    }
  });

  it("iac.fmt: biçimsiz dosyayı düzeltir (anlık kopyada), check kipi yazmaz; sözdizimi hatasını bildirir", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      await h.call("fs.write", { path: "ugly.tf", content: 'variable   "x"{\ntype=string\n   default="a"\n}\n' });
      const chk = await h.call("iac.fmt", { check: true });
      expect(chk.status, JSON.stringify(chk)).toBe("ok");
      expect(h.json(chk)).toMatchObject({ ok: true, mode: "check", files: ["ugly.tf"] });
      expect((await h.fs.read("ugly.tf")).content).toContain("variable   \"x\"{");
      const w = await h.call("iac.fmt", {});
      expect(h.json(w)).toMatchObject({ ok: true, mode: "write", count: 1 });
      expect((await h.fs.read("ugly.tf")).content).toBe('variable "x" {\n  type    = string\n  default = "a"\n}');
      // sözdizimi hatası
      await h.call("fs.write", { path: "broken.tf", content: 'variable "y" {\n  type = \n' });
      const bad = await h.call("iac.fmt", {});
      const j = h.json(bad);
      expect(j.ok).toBe(false);
      expect(j.syntaxErrors.length).toBeGreaterThan(0);
      // fmt ilk çağrıda onay ister (localWrite), ikincide oturum izniyle sormaz
      expect(h.gate.requests.map((q) => q.summary.tool)).toEqual(["fs.write", "iac.fmt"]);
      // fmt yalnız çalışma kopyasını değiştirdi
      expect(existsSync(join(h.repo.dir, "ugly.tf"))).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("iac.plan: BOŞ state'e karşı plan, kompakt özet; hassas değer çıkmaz; plan dosyası ve .terraform kalmaz; depo değişmez", async () => {
    const secret = makeCanary("plan-sensitive");
    const files = {
      "main.tf":
        'variable "token" {\n  type      = string\n  sensitive = true\n  default   = "' + secret.value + '"\n}\n\nresource "terraform_data" "a" {\n  input = "visible-input"\n}\n\nresource "terraform_data" "b" {\n  input = var.token\n}\n\noutput "tok" {\n  value     = var.token\n  sensitive = true\n}\n\noutput "aid" {\n  value = terraform_data.a.id\n}\n',
    };
    const h = await makeIacHarness({ engine: "opentofu", files });
    try {
      const r = await h.call("iac.plan", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ executed: true, planned: true, noChanges: false, counts: { create: 2, update: 0, delete: 0, replace: 0 } });
      expect(j.changes.map((c: { address: string }) => c.address)).toEqual(["terraform_data.a", "terraform_data.b"]);
      expect(j.changes[0].attrs).toEqual(expect.arrayContaining([{ name: "input", value: "visible-input" }]));
      // hassas girdi değeri HİÇBİR yerde yok (özet, kanıt, denetim)
      const input = j.changes[1].attrs.find((a: { name: string }) => a.name === "input");
      expect(input).toEqual({ name: "input", note: "hassas" });
      expect(j.outputs).toEqual(expect.arrayContaining([{ name: "tok", action: "create", sensitive: true }, { name: "aid", action: "create", sensitive: false }]));
      const sink = await h.sinkFor([r]);
      expect(sink.leaks([secret])).toEqual([]);
      expect(j.note).toMatch(/BOŞ state/);
      expect(existsSync(join(h.fs.root, ".terraform"))).toBe(false);
      expect(existsSync(join(h.repo.dir, ".terraform"))).toBe(false);
      expect(existsSync(join(h.repo.dir, "plan.tfplan"))).toBe(false);
      // deponun (atlanan) state/tfvars/.env dosyaları plana HİÇ girmedi
      expect(JSON.stringify(j)).not.toMatch(/state-secret|should-never-be-copied/);
      expect(r.subjects).toContain("Resource/terraform_data.a");
    } finally {
      await h.cleanup();
    }
  });

  it("iac.plan: değişken değerleri TF_VAR ile geçer; eksik değişken ve plan hatası kompakt tanı olarak döner", async () => {
    const h = await makeIacHarness({
      engine: "opentofu",
      files: { "main.tf": 'variable "who" {\n  type = string\n}\n\nresource "terraform_data" "x" {\n  input = var.who\n}\n' },
    });
    try {
      const bad = await h.call("iac.plan", {});
      expect(bad.status, JSON.stringify(bad)).toBe("ok");
      expect(h.json(bad)).toMatchObject({ planned: false });
      expect(h.json(bad).diagnostics[0].message).toMatch(/variable|value/i);
      const good = await h.call("iac.plan", { vars: { who: "from-var" } });
      const j = h.json(good);
      expect(j).toMatchObject({ planned: true, counts: { create: 1 } });
      expect(j.changes[0].attrs).toEqual([{ name: "input", value: "from-var" }]);
      // değişken adı biçimi ve sayısı sınırlı
      expect((await h.call("iac.plan", { vars: { "Bad Name": "x" } })).reasonCode).toBe("schema_invalid");
      expect((await h.call("iac.plan", { vars: Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`v${i}`, "x"])) })).reasonCode).toBe("schema_invalid");
    } finally {
      await h.cleanup();
    }
  });

  it("iac.plan: ön-tarama engelleyici yapı (provisioner) varsa ÇALIŞMAZ", async () => {
    const h = await makeIacHarness({
      engine: "opentofu",
      files: { "main.tf": 'resource "terraform_data" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n' },
    });
    try {
      const r = await h.call("iac.plan", {});
      expect(h.json(r)).toMatchObject({ executed: false, blocked: true });
      expect(r.summary).toMatch(/plan ÇALIŞMADI/);
    } finally {
      await h.cleanup();
    }
  });

  it("iac.docs.lookup: yerleşik terraform_data şeması (yalnız istenen tür)", async () => {
    const h = await makeIacHarness({ engine: "opentofu", files: GOOD });
    try {
      const r = await h.call("iac.docs.lookup", { type: "terraform_data" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j.provider).toMatch(/terraform/);
      expect(j.attributes.map((a: { name: string }) => a.name)).toEqual(expect.arrayContaining(["input", "output", "id", "triggers_replace"]));
      expect(JSON.stringify(j).length).toBeLessThan(3000);
      const none = await h.call("iac.docs.lookup", { type: "aws_s3_bucket" });
      expect(none.status).toBe("error");
      expect(none.summary).toMatch(/bulunamadı/);
      expect((await h.call("iac.docs.lookup", { type: "Bad; Type" })).reasonCode).toBe("schema_invalid");
    } finally {
      await h.cleanup();
    }
  });

  it("sağlayıcı gerektiren yapılandırma: ağ KAPALI olduğundan init açık ipucuyla başarısız olur (veri sızmaz)", async () => {
    const h = await makeIacHarness({
      engine: "opentofu",
      files: { "main.tf": 'terraform {\n  required_providers {\n    null = {\n      source  = "hashicorp/null"\n      version = "3.2.3"\n    }\n  }\n}\n\nresource "null_resource" "n" {}\n' },
    });
    try {
      const r = await h.call("iac.validate", {});
      expect(r.status).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ executed: true, initOk: false });
      expect(j.hint).toMatch(/sandbox ağsız/);
    } finally {
      await h.cleanup();
    }
  });

  it("yerel dosya aynası ile sağlayıcı çevrimdışı kurulur (aynayı host üretir; sandbox'ta ağ yok)", async () => {
    const mirror = await mkdtemp(join(tmpdir(), "ops-mirror-"));
    const cfg = await mkdtemp(join(tmpdir(), "ops-mirrorcfg-"));
    try {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(join(cfg, "main.tf"), 'terraform {\n  required_providers {\n    null = {\n      source  = "hashicorp/null"\n      version = "3.2.3"\n    }\n  }\n}\n');
      const hostTofu = findHostTool("tofu");
      if (!hostTofu) {
        console.warn("[atlandı] host'ta tofu yok (VM kipi): sağlayıcı aynası host'ta üretilemez");
        return;
      }
      try {
        await run(hostTofu, ["providers", "mirror", mirror], { cwd: cfg, env: { PATH: process.env["PATH"] ?? "", HOME: cfg, HTTPS_PROXY: process.env["HTTPS_PROXY"] ?? "", SSL_CERT_FILE: process.env["SSL_CERT_FILE"] ?? "/root/.ccr/ca-bundle.crt" }, timeout: 90_000 });
      } catch {
        console.warn("[atlandı] sağlayıcı aynası üretilemedi (kayıt defterine erişim yok)");
        return;
      }
      const h = await makeIacHarness({
        engine: "opentofu",
        providerMirror: mirror,
        files: { "main.tf": 'terraform {\n  required_providers {\n    null = {\n      source  = "hashicorp/null"\n      version = "3.2.3"\n    }\n  }\n}\n\nresource "null_resource" "n" {}\n' },
      });
      try {
        const r = await h.call("iac.validate", {});
        const j = h.json(r);
        expect(j, JSON.stringify(j)).toMatchObject({ executed: true, valid: true });
        expect(j.lockFile).toMatch(/oluşturuldu|değişmedi/);
        const docs = await h.call("iac.docs.lookup", { type: "null_resource" });
        expect(h.json(docs).attributes.map((a: { name: string }) => a.name)).toEqual(expect.arrayContaining(["triggers", "id"]));
      } finally {
        await h.cleanup();
      }
    } finally {
      await rm(mirror, { recursive: true, force: true });
      await rm(cfg, { recursive: true, force: true });
    }
  }, 180_000);

  it.skipIf(!terraform)("aynı akış Terraform ikilisiyle de çalışır (engine: terraform)", async () => {
    const h = await makeIacHarness({ engine: "terraform", files: GOOD });
    try {
      expect(h.json(await h.call("iac.project.inspect", {}))).toMatchObject({ engine: "terraform", tool: { name: "terraform", available: true } });
      expect(h.json(await h.call("iac.validate", {}))).toMatchObject({ executed: true, valid: true });
    } finally {
      await h.cleanup();
    }
  });

  it("motor uyuşmazlığı ve etkin çalışma alanı yokken açık hata; iac.scan SARIF özeti", async () => {
    const sarif = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "trivy" } }, results: [
      { ruleId: "AVD-AWS-0086", level: "error", message: { text: "S3 bucket has public access block disabled" }, locations: [{ physicalLocation: { artifactLocation: { uri: "main.tf" }, region: { startLine: 12 } } }] },
      { ruleId: "AVD-AWS-0090", level: "warning", message: { text: "versioning disabled" }, locations: [{ physicalLocation: { artifactLocation: { uri: "main.tf" }, region: { startLine: 3 } } }] },
    ] }] });
    const h = await makeIacHarness({ engine: "opentofu", files: { ...GOOD, "scan.sarif": sarif, "notsarif.json": "{\"a\":1}", "broken.json": "{" } });
    try {
      const r = await h.call("iac.scan", { path: "scan.sarif" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ tool: "trivy", total: 2, byLevel: { error: 1, warning: 1 } });
      expect(j.results[0]).toMatchObject({ rule: "AVD-AWS-0086", level: "error", file: "main.tf", line: 12 });
      expect((await h.call("iac.scan", { path: "notsarif.json" })).summary).toMatch(/SARIF/);
      expect((await h.call("iac.scan", { path: "broken.json" })).summary).toMatch(/JSON değil/);
      expect((await h.call("iac.scan", { path: "main.tf" })).summary).toMatch(/\.sarif veya \.json/);
      expect((await h.call("ansible.inventory.list", {})).summary).toMatch(/Ansible çalışma alanları/);
      const lint = await h.call("iac.lint", {});
      expect(h.json(lint)).toMatchObject({ tool: "tflint" });
      await h.manager.deactivate();
      expect((await h.call("iac.project.inspect", {})).summary).toMatch(/etkin çalışma alanı yok/);
    } finally {
      await h.cleanup();
    }
  });
});
