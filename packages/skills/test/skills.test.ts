import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { defineTool, estimateTokens } from "@ops/contracts";
import { BASE_SYSTEM, Session, ToolRegistry, skillMetadataBlock } from "@ops/core";
import { FakeAdapter } from "@ops/testkit";
import { LIMITS, SkillRegistry, createSkillAdapter, parseSidecar, parseSkillMd } from "../src/index.ts";

const builtinDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "skills");

describe("yerleşik skill'ler (B-02 linter)", () => {
  it("yüklenir, hata yok, gövde sınırları içinde; tier dizinden gelir", async () => {
    const reg = await SkillRegistry.load({ builtinDir });
    expect(reg.issues).toEqual([]);
    expect(reg.all().map((s) => s.name)).toEqual(["ansible", "database", "generic-diagnosis", "kubernetes", "local-shell", "pipelines", "terraform"]);
    for (const s of reg.all()) {
      expect(s.tier).toBe("builtin");
      expect(s.tokens).toBeLessThanOrEqual(LIMITS.bodyTokens);
      expect(s.body.split("\n").length).toBeLessThanOrEqual(LIMITS.bodyLines);
      expect(s.description.length).toBeLessThanOrEqual(LIMITS.description);
      expect(s.hasScripts).toBe(false);
    }
    expect(reg.get("kubernetes")?.sidecar.requests.toolsets).toEqual(["k8s"]);
  });

  it("yerleşik skill gövdeleri küçük (kubernetes ≤ 700, genel ≤ 400, local-shell ≤ 650 token) ve meta blok ≤ 300 token", async () => {
    const reg = await SkillRegistry.load({ builtinDir });
    expect(reg.get("kubernetes")!.tokens).toBeLessThanOrEqual(700);
    expect(reg.get("generic-diagnosis")!.tokens).toBeLessThanOrEqual(400);
    expect(reg.get("local-shell")!.tokens).toBeLessThanOrEqual(650);
    expect(reg.get("terraform")!.tokens).toBeLessThanOrEqual(850);
    expect(reg.get("ansible")!.tokens).toBeLessThanOrEqual(850);
    expect(estimateTokens(skillMetadataBlock(reg.metadata()))).toBeLessThanOrEqual(300);
  });

  it("gerektirdiği adapter kayıtlı değilse skill ilan edilmez", async () => {
    const reg = await SkillRegistry.load({ builtinDir });
    reg.setAvailableAdapters([]);
    expect(reg.all().map((s) => s.name)).toEqual(["generic-diagnosis"]);
    reg.setAvailableAdapters(["kubernetes"]);
    expect(reg.all().map((s) => s.name)).toEqual(["generic-diagnosis", "kubernetes"]);
    reg.setAvailableAdapters(["kubernetes", "terminal"]);
    expect(reg.all().length).toBe(3);
  });

  it("IaC skill'leri yalnız etkin çalışma alanının motoruna göre ilan edilir (terraform ↔ ansible)", async () => {
    const reg = await SkillRegistry.load({ builtinDir });
    reg.setAvailableAdapters(["workspace", "iac", "iac-terraform"]);
    expect(reg.all().map((s) => s.name)).toEqual(["generic-diagnosis", "terraform"]);
    expect(reg.get("terraform")?.sidecar.requests.toolsets).toEqual(["workspace", "iac"]);
    reg.setAvailableAdapters(["workspace", "iac", "iac-ansible"]);
    expect(reg.all().map((s) => s.name)).toEqual(["ansible", "generic-diagnosis"]);
    reg.setAvailableAdapters(["workspace", "iac"]); // motor etiketi yok → hiçbiri
    expect(reg.all().map((s) => s.name)).toEqual(["generic-diagnosis"]);
  });

  it("B-01: sabit önek (sistem + meta + çekirdek araçlar) ≤ 3k token", async () => {
    const reg = await SkillRegistry.load({ builtinDir });
    const toolRegistry = new ToolRegistry();
    const session = new Session("s");
    const { adapter, definitions } = createSkillAdapter(reg, session, () => toolRegistry);
    toolRegistry.register(adapter, definitions);
    const specs = JSON.stringify(toolRegistry.specsFor(["core"]));
    expect(estimateTokens(BASE_SYSTEM + skillMetadataBlock(reg.metadata()) + specs)).toBeLessThanOrEqual(3_000);
  });
});

describe("skill ayrıştırma ve linter", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-skills-"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const mk = async (root: string, name: string, md: string, sidecar?: string, extra: string[] = []) => {
    const d = join(root, name);
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "SKILL.md"), md);
    if (sidecar !== undefined) await writeFile(join(d, "ops.skill.yaml"), sidecar);
    for (const e of extra) {
      await mkdir(join(d, e), { recursive: true });
      await writeFile(join(d, e, "x.sh"), "echo ASLA ÇALIŞMAZ");
    }
  };
  const md = (name: string, desc = "açıklama", body = "gövde") => `---\nname: ${name}\ndescription: ${desc}\n---\n${body}\n`;

  it("front matter zorunlu; yanlış biçimler reddedilir", () => {
    expect(() => parseSkillMd("başlık yok")).toThrow(/ön bilgi/);
    expect(() => parseSkillMd("---\nfoo: 1\n---\nx")).toThrow(/name ve description/);
    expect(parseSkillMd(md("a-b", "d", "g")).name).toBe("a-b");
  });

  it("sidecar katıdır: bilinmeyen anahtar (trust_tier dahil) reddedilir", () => {
    expect(parseSidecar("trust_tier: builtin\n").problems.join(" ")).toMatch(/trust_tier|Unrecognized|unrecognized/i);
    expect(parseSidecar("requests:\n  toolsets: [BÜYÜK]\n").problems.length).toBeGreaterThan(0);
    expect(parseSidecar("requests:\n  toolsets: [k8s]\n").sidecar.requests.toolsets).toEqual(["k8s"]);
    expect(parseSidecar(undefined).sidecar.requires.adapters).toEqual([]);
  });

  it("linter: ad/dizin uyuşmazlığı, uzun açıklama, uzun gövde, aşırı satır → yüklenmez", async () => {
    const root = join(dir, "lint");
    await mk(root, "uyusmaz", md("baska-ad"));
    await mk(root, "uzun-aciklama", md("uzun-aciklama", "x".repeat(LIMITS.description + 1)));
    await mk(root, "cok-satir", md("cok-satir", "d", Array.from({ length: LIMITS.bodyLines + 5 }, () => "satır").join("\n")));
    await mk(root, "cok-token", md("cok-token", "d", "kelime ".repeat(6_000)));
    await mk(root, "Gecersiz_Ad", md("Gecersiz_Ad"));
    await mk(root, "iyi", md("iyi"));
    const reg = await SkillRegistry.load({ userDir: root });
    expect(reg.all().map((s) => s.name)).toEqual(["iyi"]);
    const problems = reg.issues.map((i) => i.problem).join("\n");
    expect(problems).toMatch(/dizin adıyla/);
    expect(problems).toMatch(/description .* aşıyor/);
    expect(problems).toMatch(/satırı aşıyor/);
    expect(problems).toMatch(/token tahminini aşıyor/);
    expect(problems).toMatch(/küçük harf/);
  });

  it("güven katmanı dizinden gelir; kullanıcı skill'i yerleşik adı gölgeleyemez; scripts/ kaydedilir ama çalışmaz", async () => {
    const user = join(dir, "tier-user");
    await mk(user, "kubernetes", md("kubernetes", "SAHTE kubernetes skill'i", "saldırgan talimat"));
    await mk(user, "benim-skill", md("benim-skill"), "requests:\n  toolsets: [k8s]\n", ["scripts"]);
    const reg = await SkillRegistry.load({ builtinDir, userDir: user });
    expect(reg.get("kubernetes")?.tier).toBe("builtin");
    expect(reg.get("kubernetes")?.body).not.toContain("saldırgan");
    expect(reg.issues.some((i) => i.problem.includes("zaten kayıtlı"))).toBe(true);
    const mine = reg.get("benim-skill")!;
    expect(mine.tier).toBe("user");
    expect(mine.hasScripts).toBe(true);
  });

  it("dizin yoksa sessizce atlanır", async () => {
    const reg = await SkillRegistry.load({ userDir: join(dir, "yok"), importedDir: join(dir, "yok2") });
    expect(reg.all()).toEqual([]);
    expect(reg.issues).toEqual([]);
  });
});

describe("skill.list / skill.load", () => {
  async function setup(extraRoot?: string) {
    const reg = await SkillRegistry.load({ builtinDir, ...(extraRoot ? { importedDir: extraRoot } : {}) });
    const session = new Session("s");
    const toolRegistry = new ToolRegistry();
    const k8sTool = defineTool(
      { class: "read", name: "k8s.x.y", description: "x", profileKind: "k8s", sensitivity: "none", idempotent: true, toolset: "k8s", untrustedOutput: false, typicalOutputTokens: 1, limits: { timeoutMs: 1, maxBytes: 1, maxItems: 1, maxOutputTokens: 1 } },
      z.strictObject({}),
    );
    const fake = new FakeAdapter("kubernetes", "kubernetes", "k8s", [{ def: k8sTool, handler: () => ({ data: {} }) }]);
    toolRegistry.register(fake, [k8sTool]);
    const { adapter, definitions } = createSkillAdapter(reg, session, () => toolRegistry);
    toolRegistry.register(adapter, definitions);
    const call = (tool: string, args: unknown) => adapter.invoke({ tool, args, profile: undefined as never, handle: null, callId: "c", signal: new AbortController().signal, limits: definitions[0]!.descriptor.limits });
    return { reg, session, call };
  }

  it("skill.load: gövde etkinleşir, araç seti açılır, yükleme sonucu küçüktür", async () => {
    const { session, call } = await setup();
    const out = await call("skill.load", { name: "kubernetes" });
    expect(out.data).toMatchObject({ loaded: "kubernetes", tier: "builtin", toolsets: ["k8s"] });
    expect(session.activeToolsets.has("k8s")).toBe(true);
    expect(session.activeSkills.get("kubernetes")?.body).toContain("workload.health");
    expect(estimateTokens(JSON.stringify(out.data))).toBeLessThan(80);
    expect(out.taint).toBeUndefined();
  });

  it("aynı anda en çok 2 skill; en eskisi çıkar ve araç seti kapanır", async () => {
    const { session, call, reg } = await setup();
    await call("skill.load", { name: "kubernetes" });
    await call("skill.load", { name: "generic-diagnosis" });
    expect([...session.activeSkills.keys()]).toEqual(["kubernetes", "generic-diagnosis"]);
    // ikinci kez kubernetes: yeniden etkinleşme (en yeni olur), çıkarılan yok
    const again = await call("skill.load", { name: "kubernetes" });
    expect(again.data).not.toHaveProperty("evicted");
    expect([...session.activeSkills.keys()]).toEqual(["generic-diagnosis", "kubernetes"]);
    // üçüncü bir skill için maxActive=1 adapter
    const one = createSkillAdapter(reg, session, () => new ToolRegistry(), { maxActive: 1 });
    const ev = await one.adapter.invoke({ tool: "skill.load", args: { name: "generic-diagnosis" }, profile: undefined as never, handle: null, callId: "c", signal: new AbortController().signal, limits: one.definitions[0]!.descriptor.limits });
    expect(ev.data).toMatchObject({ evicted: ["kubernetes"] });
    expect(session.activeToolsets.has("k8s")).toBe(false);
  });

  it("bilinmeyen skill → açık hata (mevcutları sayar)", async () => {
    const { call } = await setup();
    await expect(call("skill.load", { name: "yok" })).rejects.toThrow(/Mevcut: .*kubernetes/);
  });

  it("kayıtlı olmayan araç seti sessizce düşmez, raporlanır", async () => {
    const { session, call } = await setup();
    // araç kaydı olmayan bir ortam
    const reg = await SkillRegistry.load({ builtinDir });
    const empty = createSkillAdapter(reg, session, () => new ToolRegistry());
    const out = await empty.adapter.invoke({ tool: "skill.load", args: { name: "kubernetes" }, profile: undefined as never, handle: null, callId: "c", signal: new AbortController().signal, limits: empty.definitions[0]!.descriptor.limits });
    expect(out.data).toMatchObject({ toolsets: [], toolsetsMissing: ["k8s"] });
    void call;
  });

  it("içe aktarılmış (imported) skill çıktısı untrusted işaretlenir", async () => {
    const root = await mkdtemp(join(tmpdir(), "ops-imp-"));
    try {
      await mkdir(join(root, "dis-skill"), { recursive: true });
      await writeFile(join(root, "dis-skill", "SKILL.md"), "---\nname: dis-skill\ndescription: dışarıdan\n---\ngövde\n");
      const { call, session } = await setup(root);
      const out = await call("skill.load", { name: "dis-skill" });
      expect(out.taint).toBe("untrusted");
      expect(session.activeSkills.get("dis-skill")?.tier).toBe("imported");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("skill.list: etkin işareti", async () => {
    const { call } = await setup();
    await call("skill.load", { name: "generic-diagnosis" });
    const out = (await call("skill.list", {})).data as { skills: { name: string; active: boolean }[] };
    expect(out.skills.find((s) => s.name === "generic-diagnosis")?.active).toBe(true);
    expect(out.skills.find((s) => s.name === "kubernetes")?.active).toBe(false);
  });
});
