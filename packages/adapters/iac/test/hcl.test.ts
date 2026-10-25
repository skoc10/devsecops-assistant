import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { HclError, parseHcl, walkBlocks } from "../src/hcl.ts";
import { scanTerraform } from "../src/terraform.ts";

const types = (src: string): string[] => [...walkBlocks(parseHcl(src).blocks)].map((x) => x.block.type);
const scan = (src: string, path = "main.tf") => scanTerraform([{ path, text: src }]);
const codes = (src: string): string[] => scan(src).findings.map((f) => f.code);

describe("parseHcl: geçerli yapılar", () => {
  it("blok, etiket, öznitelik, iç içe ve tek satırlık bloklar", () => {
    const t = parseHcl('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  tags = { a = "1", b = "2" }\n  lifecycle { prevent_destroy = true }\n}\nvariable name {}\n');
    expect(t.blocks.map((b) => [b.type, b.labels])).toEqual([["resource", ["aws_s3_bucket", "b"]], ["variable", ["name"]]]);
    const r = t.blocks[0]!;
    expect(r.attrs["bucket"]).toMatchObject({ literal: "x", line: 2 });
    expect(r.attrs["tags"]?.literal).toBeUndefined();
    expect(r.blocks[0]).toMatchObject({ type: "lifecycle" });
    expect(r.blocks[0]?.attrs["prevent_destroy"]?.text).toBe("true");
  });

  it("yorumlar, heredoc, enterpolasyon, çok satırlı listeler/nesneler, for ifadesi, koşul, CRLF, BOM", () => {
    const src = [
      "\uFEFF# yorum { } \"",
      "// başka yorum",
      "/* blok yorum { provisioner \"local-exec\" { } } */",
      'locals {',
      '  url   = "https://example.invalid/a//b"   # // string içinde',
      '  quote = "he said \\"hi\\" {"',
      '  nested = "${ lookup({a = "}"}, "a", "${var.x}") }"',
      '  esc   = "$${not interp} %%{not directive}"',
      '  dir   = "%{ if var.a }yes%{ else }no%{ endif }"',
      '  doc   = <<-EOT',
      '    } provisioner "local-exec" { ',
      '    # not a comment end',
      '  EOT',
      '  list  = [',
      '    "a",',
      '    "b", # trailing',
      '  ]',
      '  obj   = {',
      '    k = 1',
      '    v = { for k, v in var.m : k => upper(v) if v != "" }',
      '  }',
      '  cond  = var.a ? "x" : "y"',
      '  splat = aws_instance.web[*].id',
      '}',
      '',
    ].join("\r\n");
    const tree = parseHcl(src);
    expect(tree.blocks.map((b) => b.type)).toEqual(["locals"]);
    expect(Object.keys(tree.blocks[0]!.attrs)).toEqual(["url", "quote", "nested", "esc", "dir", "doc", "list", "obj", "cond", "splat"]);
    expect(tree.blocks[0]!.attrs["url"]?.literal).toBe("https://example.invalid/a//b");
    // heredoc ve yorum içindeki sahte provisioner BLOK sayılmaz
    expect(types(src)).toEqual(["locals"]);
  });

  it.each([
    ["kapanmamış dize", 'a = "x\n'],
    ["kapanmamış blok", 'resource "a" "b" {\n  x = 1\n'],
    ["fazla }", "x = 1\n}\n"],
    ["kapanmamış blok yorumu", "/* aç\nx = 1"],
    ["kapanmamış heredoc", 'a = <<EOT\nmetin\n'],
    ["kapanmamış enterpolasyon", 'a = "${ foo(\n"'],
    ["':' ayracı", "a: 1\n"],
    ["etiketsiz geçersiz karakter", "resource \"a\" ^ {\n}\n"],
    ["blok başlığı bölünmüş", 'resource "a" "b"\n{\n}\n'],
    ["rakamla başlayan ad", "1a = 2\n"],
  ])("sözdizimi hatası → HclError: %s", (_n, src) => {
    expect(() => parseHcl(src)).toThrow(HclError);
  });
});

describe("terraform ön-tarama: kod çalıştıran yapılar", () => {
  it("provisioner (her tür), data external, dynamic provisioner", () => {
    expect(codes('resource "null_resource" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n')).toContain("provisioner");
    expect(codes('resource "x" "y" { provisioner "remote-exec" { inline = ["id"] } }')).toContain("provisioner");
    expect(codes('resource "x" "y" {\n  provisioner "file" {\n    source = "a"\n  }\n}\n')).toContain("provisioner");
    expect(codes('data "external" "e" {\n  program = ["sh", "-c", "id"]\n}\n')).toContain("external_data");
    expect(codes('resource "x" "y" {\n  dynamic "provisioner" {\n    for_each = [1]\n    content {}\n  }\n}\n')).toContain("provisioner");
    expect(scan('data "external" "e" {\n  program = ["id"]\n}\n').blocked).toBe(true);
  });

  it("gizleme denemeleri: yorum/heredoc/dize içindeki parantezler tokenleştirmeyi bozmaz; gerçek provisioner yine yakalanır", () => {
    const tricks = [
      'locals {\n  doc = <<EOT\n}\nEOT\n}\nresource "x" "y" {\n  provisioner "local-exec" { command = "id" }\n}\n',
      'locals { s = "}" }\nresource "x" "y" {\n  provisioner "local-exec" { command = "id" }\n}\n',
      'locals { s = "/*" }\nresource "x" "y" {\n  provisioner "local-exec" { command = "id" }\n}\n',
      '# } \n// {\nresource "x" "y" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n',
      'locals { v = "${ "}" }" }\nresource "x" "y" {\n  provisioner "local-exec" { command = "id" }\n}\n',
      'resource "x" "y" {\n  a = <<-A\n  ${"x"}\n  A\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n',
      '\uFEFFresource "x" "y" {\r\n  provisioner "local-exec" {\r\n    command = "id"\r\n  }\r\n}\r\n',
      'resource    "x"   "y"   {   provisioner   "local-exec"   {   command   =   "id"   }   }',
      'resource "x" "y" {\n  a = [\n    "}", # { \n    "{",\n  ]\n  provisioner "local-exec" { command = "id" }\n}\n',
      'terraform {\n  required_providers {\n    a = { source = "hashicorp/a" }\n  }\n}\nresource "x" "y" { provisioner "local-exec" { command = "id" } }',
    ];
    for (const [i, t] of tricks.entries()) expect(codes(t), `hile ${i}`).toContain("provisioner");
  });

  it("uzak modül, dinamik modül, sağlayıcı kaynağı, gömülü kimlik, JSON sözdizimi, ayrıştırılamayan dosya → engel", () => {
    for (const src of ["git::https://x.invalid/m.git", "github.com/org/repo", "https://x.invalid/m.zip", "s3::https://s3.x/m.zip", "git@github.com:org/m.git", "app.terraform.io/org/name/provider", "hg::http://x/m"]) {
      const s = scan(`module "m" {\n  source = "${src}"\n}\n`);
      expect(s.findings.map((f) => f.code), src).toContain("remote_module");
      expect(s.blocked, src).toBe(true);
    }
    expect(codes('module "m" {\n  source = var.src\n}\n')).toContain("module_source_dynamic");
    expect(codes('module "m" {\n  source = "./local"\n}\n')).toEqual([]);
    expect(scan('module "m" {\n  source = "../up/mod"\n}\n', "envs/prod/main.tf").findings).toEqual([]);
    const reg = scan('module "m" {\n  source = "terraform-aws-modules/vpc/aws"\n  version = "5.0.0"\n}\n');
    expect(reg.findings.map((f) => f.code)).toEqual(["registry_module"]);
    expect(reg.blocked).toBe(false);
    expect(codes('module "m" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n')).toEqual(["registry_module", "module_unpinned"]);

    expect(codes('terraform {\n  required_providers {\n    evil = { source = "evil.invalid/ns/evil", version = "1.0.0" }\n  }\n}\n')).toContain("provider_source_untrusted");
    expect(codes('terraform {\n  required_providers {\n    ok = { source = "registry.opentofu.org/ns/ok", version = "1.0.0" }\n  }\n}\n')).toEqual([]);
    expect(codes('terraform {\n  required_providers {\n    a = { source = "hashicorp/a" }\n  }\n}\n')).toEqual(["provider_unpinned"]);
    expect(codes('terraform {\n  required_providers {\n    a = { source = "a/b/c/d", version = "1" }\n  }\n}\n')).toContain("provider_source_invalid");

    expect(codes('provider "aws" {\n  access_key = "AKIAEXAMPLE"\n  region = "eu-west-1"\n}\n')).toEqual(["embedded_credential"]);
    expect(codes('provider "aws" {\n  access_key = var.key\n  token = local.t\n}\n')).toEqual([]);
    expect(codes('provider "x" {\n  assume_role { token = "abc" }\n}\n')).toEqual(["embedded_credential"]);
    expect(codes('provider "x" {\n  password = ""\n}\n')).toEqual([]);
    // bulgu mesajı DEĞERİ içermez
    expect(scan('provider "aws" {\n  secret_key = "TOPSECRETVALUE"\n}\n').findings.map((f) => f.message).join()).not.toContain("TOPSECRETVALUE");

    const json = scanTerraform([{ path: "x.tf.json", text: "{}" }]);
    expect(json.findings[0]).toMatchObject({ severity: "block", code: "json_syntax_unsupported" });
    const bad = scan('resource "a" "b" {\n  x = "unterminated\n}\n');
    expect(bad.findings[0]).toMatchObject({ severity: "block", code: "parse_error", line: 2 });
    expect(bad.blocked).toBe(true);
  });

  it("yerel modül kaynağı çalışma alanı kökünün dışına çıkarsa ENGEL; kök içinde kalan ../ yolları serbest", () => {
    const mod = (src: string): string => `module "m" {\n  source = "${src}"\n}\n`;
    const outside: [string, string][] = [
      ["main.tf", "./../.."],
      ["main.tf", "../up/mod"],
      ["main.tf", "./.."],
      ["envs/prod/main.tf", "../../../outside"],
      ["a/main.tf", "./x/../../../y"],
      ["a/main.tf", "../..//b"],
    ];
    for (const [path, src] of outside) {
      const s = scan(mod(src), path);
      expect(s.findings.map((f) => f.code), `${path}: ${src}`).toEqual(["local_module_outside"]);
      expect(s.findings[0], `${path}: ${src}`).toMatchObject({ severity: "block", file: path, line: 1 });
      expect(s.blocked).toBe(true);
      expect(s.model.modules[0]).toMatchObject({ kind: "local", source: src });
    }
    const inside: [string, string][] = [
      ["envs/prod/main.tf", "../../modules/vpc"],
      ["main.tf", "./modules/vpc"],
      ["modules/a/main.tf", "../b"],
      ["main.tf", "./"],
      ["a/main.tf", "./.."],
      ["a/b/main.tf", "./x/../../c//d"],
    ];
    for (const [path, src] of inside) expect(scan(mod(src), path).findings, `${path}: ${src}`).toEqual([]);
  });

  it("zararsız yapılar engel doğurmaz; model çıkarılır (değişkenler, çıktılar, kaynaklar, sağlayıcılar, backend)", () => {
    const src = [
      'terraform {',
      '  required_version = ">= 1.6"',
      '  required_providers {',
      '    aws = { source = "hashicorp/aws", version = "~> 5.0" }',
      '  }',
      '  backend "s3" {}',
      '}',
      'provider "aws" { region = "eu-west-1" }',
      'variable "name" {',
      '  type = string',
      '  default = "x"',
      '}',
      'variable "token" {',
      '  type = string',
      '  sensitive = true',
      '}',
      'resource "aws_s3_bucket" "a" {}',
      'resource "aws_s3_bucket" "b" {}',
      'data "aws_caller_identity" "me" {}',
      'output "id" { value = aws_s3_bucket.a.id }',
      'output "pw" {',
      '  value = var.token',
      '  sensitive = true',
      '}',
    ].join("\n");
    const s = scan(src);
    expect(s.blocked).toBe(false);
    expect(s.findings).toEqual([]);
    expect(s.model).toMatchObject({
      files: 1,
      providers: [{ name: "aws", source: "hashicorp/aws", version: "~> 5.0" }],
      providerConfigs: ["aws"],
      dirs: { ".": { variables: [{ name: "name", type: "string", hasDefault: true, sensitive: false }, { name: "token", type: "string", hasDefault: false, sensitive: true }], outputs: [{ name: "id", sensitive: false }, { name: "pw", sensitive: true }], resources: { aws_s3_bucket: 2 }, dataSources: { aws_caller_identity: 1 } } },
      resources: { aws_s3_bucket: 2 },
      dataSources: { aws_caller_identity: 1 },
      backend: "s3",
      requiredVersion: ">= 1.6",
    });
  });

  it("özellik: rastgele metin tarayıcıyı ASLA çökertmez (hata → block bulgusu)", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), (s) => {
        const r = scanTerraform([{ path: "a.tf", text: s }]);
        return Array.isArray(r.findings) && typeof r.blocked === "boolean";
      }),
      { numRuns: 3000 },
    );
    fc.assert(
      fc.property(fc.array(fc.constantFrom('resource "a" "b" {', "}", "{", '"', "<<EOT", "EOT", "#", "//", "/*", "*/", "${", "provisioner \"local-exec\" {", "\n", " ", "x = 1", "="), { maxLength: 40 }), (parts) => {
        const r = scanTerraform([{ path: "a.tf", text: parts.join("") }]);
        return Array.isArray(r.findings);
      }),
      { numRuns: 3000 },
    );
  });
});
