import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { estimateTokens } from "@ops/contracts";
import type { SkillCatalog, SkillMeta } from "@ops/core";
import { LIMITS, lintSkillDir } from "./lint.ts";
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

export { LIMITS };

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
      // Denetim `ops skill lint` ile AYNI koddur (lint.ts): hata bulgusu olan skill yüklenmez, uyarılar yüklemeyi engellemez.
      const linted = await lintSkillDir(dir, dirName);
      if (!linted) continue; // SKILL.md yoksa skill değil
      const problems = linted.lint.findings.filter((f) => f.severity === "error").map((f) => f.message);
      const parsed = linted.parsed;
      if (parsed && this.skills.has(parsed.name)) problems.push(`'${parsed.name}' adı zaten kayıtlı (${this.skills.get(parsed.name)?.tier}); yerleşik/önceki skill kazanır`);
      if (problems.length > 0 || !parsed || !linted.sidecar) {
        for (const p of problems) this.issues.push({ dir, problem: p });
        continue;
      }
      this.skills.set(parsed.name, {
        name: parsed.name,
        description: parsed.description,
        body: parsed.body,
        tokens: linted.lint.tokens ?? estimateTokens(parsed.body),
        tier,
        sidecar: linted.sidecar,
        hasScripts: linted.hasScripts,
        dir,
      });
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
