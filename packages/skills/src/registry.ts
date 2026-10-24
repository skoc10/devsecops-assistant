import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { estimateTokens } from "@ops/contracts";
import type { SkillCatalog, SkillMeta } from "@ops/core";
import { SKILL_NAME, parseSidecar, parseSkillMd } from "./parse.ts";
import type { Sidecar } from "./parse.ts";

export type SkillTier = "builtin" | "user" | "imported";

export interface Skill {
  readonly name: string;
  readonly description: string;
  readonly body: string;
  readonly tokens: number;
  readonly tier: SkillTier;
  readonly sidecar: Sidecar;
  /** `scripts/` dizini var mı? ASLA çalıştırılmaz (yalnız bilgi). */
  readonly hasScripts: boolean;
  readonly dir: string;
}

export interface SkillIssue {
  readonly dir: string;
  readonly problem: string;
}

export const LIMITS = { bodyLines: 500, bodyTokens: 5_000, description: 1_024 } as const;

export interface LoadOptions {
  readonly builtinDir?: string;
  readonly userDir?: string;
  readonly importedDir?: string;
}

/**
 * Skill kayıt defteri. Güven katmanı (`trust_tier`) DOSYADAN değil, yüklendiği dizinden gelir:
 * kullanıcı skill'i kendini `builtin` ilan edemez. Aynı adlı skill'de yerleşik olan kazanır.
 * Linter hatası olan skill yüklenmez (sebep `issues`'ta).
 */
export class SkillRegistry implements SkillCatalog {
  private readonly skills = new Map<string, Skill>();
  readonly issues: SkillIssue[] = [];
  private available: ReadonlySet<string> | null = null;
  private provider: (() => Iterable<string>) | null = null;

  static async load(opts: LoadOptions): Promise<SkillRegistry> {
    const reg = new SkillRegistry();
    // sıra önemli: yerleşik önce (ad çakışmasında kazanır)
    if (opts.builtinDir) await reg.scan(opts.builtinDir, "builtin");
    if (opts.userDir) await reg.scan(opts.userDir, "user");
    if (opts.importedDir) await reg.scan(opts.importedDir, "imported");
    return reg;
  }

  /** Kayıtlı adapter kimlikleri: gerektirdiği adapter yoksa skill ilan edilmez. */
  setAvailableAdapters(ids: Iterable<string>): void {
    this.available = new Set(ids);
  }

  /**
   * Kullanılabilirlik her sorguda yeniden hesaplanır (ör. profil eklendikçe/bağlı alan değiştikçe): skill
   * yalnız gerçekten kullanılabilecekse ilan edilir → gereksiz meta token yok (D15).
   */
  setAvailabilityProvider(fn: () => Iterable<string>): void {
    this.provider = fn;
  }

  private isAvailable(s: Skill): boolean {
    const av = this.provider ? new Set(this.provider()) : this.available;
    if (av === null) return true;
    const r = s.sidecar.requires;
    return r.adapters.every((a) => av.has(a)) && (r.anyOf.length === 0 || r.anyOf.some((a) => av.has(a)));
  }

  private async scan(root: string, tier: SkillTier): Promise<void> {
    let names: string[];
    try {
      names = (await readdir(root)).sort();
    } catch {
      return; // dizin yoksa sorun değil
    }
    for (const dirName of names) {
      const dir = join(root, dirName);
      try {
        if (!(await stat(dir)).isDirectory()) continue;
      } catch {
        continue;
      }
      let md: string;
      try {
        md = await readFile(join(dir, "SKILL.md"), "utf8");
      } catch {
        continue; // SKILL.md yoksa skill değil
      }
      const problems: string[] = [];
      let parsed;
      try {
        parsed = parseSkillMd(md);
      } catch (e) {
        this.issues.push({ dir, problem: (e as Error).message });
        continue;
      }
      let sidecarText: string | undefined;
      try {
        sidecarText = await readFile(join(dir, "ops.skill.yaml"), "utf8");
      } catch {
        sidecarText = undefined;
      }
      const { sidecar, problems: sp } = parseSidecar(sidecarText);
      problems.push(...sp);
      if (!SKILL_NAME.test(parsed.name) || parsed.name.length > 64) problems.push("name küçük harf-rakam-tire olmalı (≤64)");
      if (parsed.name !== dirName) problems.push(`name ('${parsed.name}') dizin adıyla ('${dirName}') aynı olmalı`);
      if (!parsed.description) problems.push("description boş");
      if (parsed.description.length > LIMITS.description) problems.push(`description ${LIMITS.description} karakteri aşıyor`);
      const lines = parsed.body.split("\n").length;
      const tokens = estimateTokens(parsed.body);
      if (lines > LIMITS.bodyLines) problems.push(`gövde ${LIMITS.bodyLines} satırı aşıyor (${lines})`);
      if (tokens > LIMITS.bodyTokens) problems.push(`gövde ${LIMITS.bodyTokens} token tahminini aşıyor (${tokens})`);
      if (this.skills.has(parsed.name)) problems.push(`'${parsed.name}' adı zaten kayıtlı (${this.skills.get(parsed.name)?.tier}); yerleşik/önceki skill kazanır`);
      if (problems.length > 0) {
        for (const p of problems) this.issues.push({ dir, problem: p });
        continue;
      }
      let hasScripts = false;
      try {
        hasScripts = (await stat(join(dir, "scripts"))).isDirectory();
      } catch {
        hasScripts = false;
      }
      this.skills.set(parsed.name, { name: parsed.name, description: parsed.description, body: parsed.body, tokens, tier, sidecar, hasScripts, dir });
    }
  }

  get(name: string): Skill | undefined {
    const s = this.skills.get(name);
    return s && this.isAvailable(s) ? s : undefined;
  }

  all(): Skill[] {
    return [...this.skills.values()].filter((s) => this.isAvailable(s)).sort((a, b) => a.name.localeCompare(b.name));
  }

  metadata(): readonly SkillMeta[] {
    return this.all().map((s) => ({ name: s.name, description: s.description, tier: s.tier }));
  }
}
