import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { parse } from "yaml";
import { estimateTokens } from "@ops/contracts";
import { SKILL_NAME, parseSidecar, parseSkillMd } from "./parse.ts";
import type { ParsedSkillMd, Sidecar } from "./parse.ts";

export type LintSeverity = "error" | "warn" | "info";

export interface LintFinding {
  readonly severity: LintSeverity;
  readonly code: string;
  readonly message: string;
}

export interface ScriptFile {
  readonly path: string;
  readonly sha256: string;
}

export interface SkillLint {
  readonly dirName: string;
  readonly name?: string;
  readonly findings: readonly LintFinding[];
  /** Hata yok mu? (uyarılar yüklemeyi engellemez) */
  readonly ok: boolean;
  readonly lines?: number;
  readonly tokens?: number;
  /** SKILL.md + ops.skill.yaml + scripts/ içeriği üzerinde SHA-256: ithal/kullanıcı skill'ini sabitlemek (pin) için. */
  readonly hash?: string;
  readonly scripts: readonly ScriptFile[];
}

export interface LintContext {
  /** Bilinen araç setleri (kayıtlı araçlardan); verilirse bilinmeyen talep UYARI olur. */
  readonly knownToolsets?: ReadonlySet<string>;
  /** Bilinen adapter kimlikleri. */
  readonly knownAdapters?: ReadonlySet<string>;
}

export const LIMITS = { bodyLines: 500, bodyTokens: 5_000, description: 1_024 } as const;

/** Agent Skills açık standardının ön bilgi anahtarları. */
const FRONT_MATTER_KEYS = new Set(["name", "description", "license", "compatibility", "metadata", "allowed-tools"]);

// Trojan Source / görünmez karakterler: talimat metninde meşru kullanımı yoktur.
const INVISIBLE = /[‪-‮⁦-⁩​-‏⁠﻿]/;
const INJECTION = /ignore (?:all )?(?:the )?(?:previous|prior|above) (?:instructions|rules)|disregard (?:all )?(?:previous|prior|the) |önceki (?:tüm )?(?:talimat|kural)\w* (?:unut|yok say|geçersiz)|you are now|talimatları unut/i;
const URL = /https?:\/\/[^\s)>\]"']+/i;
const PIPE_TO_SHELL = /(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i;
const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/;

async function listFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, depth: number): Promise<void> => {
    if (depth > 4 || out.length > 200) return;
    let ents;
    try {
      ents = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents.sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p, depth + 1);
      else if (e.isFile()) out.push(p);
    }
  };
  await walk(root, 0);
  return out;
}

export interface LintedSkill {
  readonly lint: SkillLint;
  readonly parsed?: ParsedSkillMd;
  readonly sidecar?: Sidecar;
  readonly hasScripts: boolean;
}

/**
 * Tek skill dizinini denetler (B-02). Kayıt defteri yüklemesi ve `ops skill lint` AYNI denetimi kullanır:
 * `error` bulgusu olan skill yüklenmez. Sezgisel bulgular (`warn`) enjeksiyon/tedarik zinciri işaretleridir —
 * Best-effort: temiz çıkması güven vermez, yalnız bariz kalıpları yakalar.
 */
export async function lintSkillDir(dir: string, dirName: string, ctx: LintContext = {}): Promise<LintedSkill | null> {
  let md: string;
  try {
    md = await readFile(join(dir, "SKILL.md"), "utf8");
  } catch {
    return null; // SKILL.md yoksa skill değil
  }
  const findings: LintFinding[] = [];
  const add = (severity: LintSeverity, code: string, message: string): void => void findings.push({ severity, code, message });

  let parsed: ParsedSkillMd | undefined;
  try {
    parsed = parseSkillMd(md);
  } catch (e) {
    add("error", "front_matter", (e as Error).message);
  }

  let sidecarText: string | undefined;
  try {
    sidecarText = await readFile(join(dir, "ops.skill.yaml"), "utf8");
  } catch {
    sidecarText = undefined;
  }
  const { sidecar, problems } = parseSidecar(sidecarText);
  for (const p of problems) add("error", "sidecar_invalid", p);

  // scripts/ : ASLA çalıştırılmaz; yalnız içeriğin hash'i listelenir
  const scripts: ScriptFile[] = [];
  let hasScripts = false;
  try {
    hasScripts = (await stat(join(dir, "scripts"))).isDirectory();
  } catch {
    hasScripts = false;
  }
  if (hasScripts) {
    for (const f of await listFiles(join(dir, "scripts"))) {
      const bytes = await readFile(f).catch(() => Buffer.alloc(0));
      scripts.push({ path: relative(dir, f), sha256: createHash("sha256").update(bytes).digest("hex") });
    }
    add("info", "scripts_present", `scripts/ var (${scripts.length} dosya): ÇALIŞTIRILMAZ; hash'leri listelendi`);
  }

  let lines: number | undefined;
  let tokens: number | undefined;
  if (parsed) {
    const p = parsed;
    if (!SKILL_NAME.test(p.name) || p.name.length > 64) add("error", "name_invalid", "name küçük harf-rakam-tire olmalı (≤64)");
    if (p.name !== dirName) add("error", "name_dir_mismatch", `name ('${p.name}') dizin adıyla ('${dirName}') aynı olmalı`);
    if (!p.description) add("error", "description_empty", "description boş");
    if (p.description.length > LIMITS.description) add("error", "description_too_long", `description ${LIMITS.description} karakteri aşıyor`);
    else if (p.description && p.description.length < 30) add("warn", "description_short", "description çok kısa: 'ne yapar + ne zaman kullanılır' yazın (yönlendirme buna dayanır)");
    lines = p.body.split("\n").length;
    tokens = estimateTokens(p.body);
    if (lines > LIMITS.bodyLines) add("error", "body_lines", `gövde ${LIMITS.bodyLines} satırı aşıyor (${lines})`);
    if (tokens > LIMITS.bodyTokens) add("error", "body_tokens", `gövde ${LIMITS.bodyTokens} token tahminini aşıyor (${tokens})`);

    // ön bilgi anahtarları (Agent Skills standardı)
    try {
      const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(md)?.[1];
      const raw = fm ? (parse(fm) as Record<string, unknown> | null) : null;
      if (raw && typeof raw === "object") {
        for (const k of Object.keys(raw)) if (!FRONT_MATTER_KEYS.has(k)) add("warn", "frontmatter_unknown_key", `ön bilgide standart dışı anahtar: '${k.slice(0, 40)}' (ürün alanları ops.skill.yaml'a yazılır)`);
        const meta = raw["metadata"];
        if (meta !== undefined && !(meta !== null && typeof meta === "object" && !Array.isArray(meta) && Object.values(meta as object).every((v) => typeof v === "string"))) {
          add("warn", "metadata_not_string_map", "metadata yalnız string→string olabilir");
        }
        if (raw["allowed-tools"] !== undefined) add("info", "allowed_tools_ignored", "allowed-tools yalnız TALEPTİR: yetki vermez, PEP karar verir (araç setleri ops.skill.yaml'daki requests ile açılır)");
      }
    } catch {
      /* ön bilgi zaten parseSkillMd ile doğrulandı */
    }

    // içerik sezgileri (Best-effort)
    const texts: [string, string][] = [["SKILL.md", `${p.description}\n${p.body}`]];
    if (sidecar.runbook) texts.push(["ops.skill.yaml runbook", sidecar.runbook.join("\n")]);
    for (const [where, t] of texts) {
      if (INVISIBLE.test(t.replace(/^﻿/, ""))) add("error", "hidden_unicode", `${where}: görünmez/çift yönlü Unicode karakteri (Trojan Source) — talimatta meşru kullanımı yok`);
      if (INJECTION.test(t)) add("warn", "injection_phrase", `${where}: model talimatını geçersiz kılmaya çalışan kalıp (ör. 'önceki talimatları unut')`);
      if (PIPE_TO_SHELL.test(t)) add("warn", "pipe_to_shell", `${where}: 'curl | sh' benzeri uzaktan kod çalıştırma kalıbı`);
      const u = URL.exec(t);
      if (u) add("warn", "external_url", `${where}: dış bağlantı (${u[0].slice(0, 60)}) — skill veri dışarı taşımamalı; yalnız başvuru bağlantısıysa yok sayın`);
      if (BASE64_BLOB.test(t)) add("warn", "base64_blob", `${where}: uzun base64 benzeri blok (gizlenmiş içerik?)`);
    }
  }

  // araç seti / adapter talepleri
  if (ctx.knownToolsets) {
    for (const t of sidecar.requests.toolsets) if (!ctx.knownToolsets.has(t)) add("warn", "toolset_unknown", `bilinmeyen araç seti talebi: '${t}' (bu kurulumda kayıtlı değil; açılmaz)`);
  }
  if (ctx.knownAdapters) {
    for (const a of [...sidecar.requires.adapters, ...sidecar.requires.anyOf]) if (!ctx.knownAdapters.has(a)) add("warn", "adapter_unknown", `bilinmeyen adapter: '${a}' (skill hiç ilan edilmeyebilir)`);
  }

  const h = createHash("sha256");
  h.update(`SKILL.md\0${md}\0ops.skill.yaml\0${sidecarText ?? ""}`);
  for (const s of scripts) h.update(`\0${s.path}\0${s.sha256}`);

  const lint: SkillLint = {
    dirName,
    ...(parsed ? { name: parsed.name } : {}),
    findings,
    ok: !findings.some((f) => f.severity === "error"),
    ...(lines !== undefined ? { lines } : {}),
    ...(tokens !== undefined ? { tokens } : {}),
    hash: h.digest("hex"),
    scripts,
  };
  return { lint, ...(parsed ? { parsed } : {}), sidecar, hasScripts };
}

/** Bir kök dizindeki tüm skill dizinlerini denetler (`ops skill lint`). */
export async function lintSkillRoot(root: string, ctx: LintContext = {}): Promise<SkillLint[]> {
  let names: string[];
  try {
    names = (await readdir(root)).sort();
  } catch {
    return [];
  }
  const out: SkillLint[] = [];
  for (const n of names) {
    const dir = join(root, n);
    try {
      if (!(await stat(dir)).isDirectory()) continue;
    } catch {
      continue;
    }
    const r = await lintSkillDir(dir, n, ctx);
    if (r) out.push(r.lint);
  }
  return out;
}

export function renderLint(results: readonly SkillLint[]): string {
  const out: string[] = [];
  for (const r of results) {
    out.push(`${r.ok ? "✓" : "✗"} ${r.dirName}${r.tokens !== undefined ? ` — ${r.lines} satır, ~${r.tokens} token` : ""}${r.hash ? ` — sha256:${r.hash.slice(0, 16)}` : ""}`);
    for (const f of r.findings) out.push(`    [${f.severity}] ${f.code}: ${f.message}`);
    for (const s of r.scripts) out.push(`    script ${s.path} sha256:${s.sha256.slice(0, 16)}`);
  }
  const errors = results.filter((r) => !r.ok).length;
  const warns = results.reduce((n, r) => n + r.findings.filter((f) => f.severity === "warn").length, 0);
  out.push(`${results.length} skill, ${errors} hatalı, ${warns} uyarı`);
  return out.join("\n");
}
