import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { scanTerraform } from "../src/terraform.ts";
import { findHostTool } from "./tools.ts";

const run = promisify(execFile);
const tofu = findHostTool("tofu"); // host'ta çalışır (sandbox'sız ayrıştırıcı karşılaştırması)

async function tofuParses(text: string, dir: string): Promise<boolean> {
  await writeFile(join(dir, "main.tf"), text);
  try {
    await run(tofu!, ["fmt", "-check", "-list=false", "-no-color", dir], { env: { PATH: process.env["PATH"] ?? "", HOME: dir, CHECKPOINT_DISABLE: "1" } });
    return true;
  } catch (e) {
    const code = (e as { code?: number }).code;
    return code === 3; // 3 = biçimlendirme gerekir ama sözdizimi geçerli
  }
}

const preamble = fc.constantFrom(
  "",
  "# yorum { \n",
  "// } yorum\n",
  "/* { provisioner \"local-exec\" { */\n",
  'locals { s = "}" }\n',
  'locals { s = "/*" }\n',
  'locals {\n  d = <<EOT\n}\nprovisioner "local-exec" {\nEOT\n}\n',
  'locals {\n  d = <<-EOT\n    }\n    EOT\n}\n',
  'locals { v = "${ "}" }" }\n',
  'locals { v = "$${x} %%{y}" }\n',
  'variable "a" {\n  type = string\n}\n',
  'locals {\n  l = [\n    "}", # {\n    "{",\n  ]\n}\n',
  "\uFEFF",
);
const header = fc.constantFrom('resource "null_resource" "x" {', 'resource   "null_resource"   "x"   {', 'resource "terraform_data" "x" {', 'resource null_resource x {');
const filler = fc.constantFrom("", "  triggers = { a = \"b\" }\n", "  # } {\n", "  /* } */\n", '  doc = <<EOT\n  }\nEOT\n', '  l = [\n    "}",\n  ]\n');
const prov = fc.constantFrom(
  '  provisioner "local-exec" {\n    command = "id"\n  }\n',
  '  provisioner "local-exec" { command = "id" }\n',
  '  provisioner   "remote-exec"   {\n    inline = ["id"]\n  }\n',
  '  provisioner "file" {\n    source = "a"\n    destination = "b"\n  }\n',
);
const eol = fc.constantFrom("\n", "\r\n");

describe.skipIf(!tofu)("diferansiyel: OpenTofu'nun kabul ettiği her sözdiziminde ön-tarama provisioner'ı YAKALAR (gerçek ayrıştırıcıya karşı)", () => {
  it("provisioner gizleme varyantları", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ops-diff-tf-"));
    let accepted = 0;
    try {
      await fc.assert(
        fc.asyncProperty(preamble, header, filler, prov, filler, eol, async (pre, h, f1, p, f2, nl) => {
          const text = `${pre}${h}\n${f1}${p}${f2}}\n`.replace(/\n/g, nl);
          if (!(await tofuParses(text, dir))) return true; // gerçek ayrıştırıcı reddetti → ilgisiz
          accepted++;
          const r = scanTerraform([{ path: "main.tf", text }]);
          const flagged = r.findings.some((x) => x.code === "provisioner") || r.findings.some((x) => x.code === "parse_error"); // yakalama veya fail-closed engel
          if (!flagged) throw new Error(`YAKALANMADI:\n${text}`);
          return r.blocked;
        }),
        { numRuns: 120 },
      );
      expect(accepted).toBeGreaterThan(40);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("yanlış ret (fail-closed) oranı düşük: tofu'nun kabul ettiği zararsız yapılandırmalar ayrıştırılır", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ops-diff-tf-"));
    let accepted = 0;
    let rejected = 0;
    try {
      await fc.assert(
        fc.asyncProperty(preamble, header, filler, filler, eol, async (pre, h, f1, f2, nl) => {
          const text = `${pre}${h}\n${f1}${f2}}\n`.replace(/\n/g, nl);
          if (!(await tofuParses(text, dir))) return true;
          accepted++;
          const r = scanTerraform([{ path: "main.tf", text }]);
          if (r.findings.some((x) => x.code === "parse_error")) rejected++;
          return true;
        }),
        { numRuns: 100 },
      );
      expect(accepted).toBeGreaterThan(30);
      expect(rejected).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
