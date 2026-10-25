import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";
import { OpsError, TOOL_NAME_PATTERN, estimateTokens } from "@ops/contracts";
import { SKILL_NAME } from "./parse.ts";
import { hasInvisible, hasVariationRun } from "./unicode.ts";

/**
 * Runbook (tasarım §4.4): KULLANICININ getirdiği markdown. Deterministik olarak PLANA çevrilir; plan kullanıcıya
 * gösterilir, her araç adımı yine PEP'ten geçer. Biçim:
 *
 *   ---
 *   title: Payments API CrashLoop
 *   description: payments api CrashLoopBackOff olduğunda
 *   params: { namespace: payments, name: api }
 *   ---
 *   1. Workload sağlığına bak. `k8s.workload.health {"kind":"Deployment","name":"{{name}}","namespace":"{{namespace}}"}`
 *   2. Uyarı olaylarını oku. `k8s.events.list {"namespace":"{{namespace}}","since":"2h","type":"Warning"}`
 *   3. Bellek sınırını gözden geçir ve öneri yaz.            ← araçsız adım: elle/model
 *
 * Bir adımda EN FAZLA bir araç çağrısı vardır: `` `araç.adı {JSON argümanlar}` ``. `{{param}}` yalnız JSON
 * string DEĞERLERİNDE yerine konur (yapı enjekte edilemez). Runbook yetki taşımaz.
 */

export const RUNBOOK_LIMITS = { chars: 20_000, steps: 30, stepText: 300, params: 10, paramValue: 200 } as const;
const PARAM_KEY = /^[a-z_][a-z0-9_]{0,40}$/;
const STEP_START = /^\s{0,3}(\d{1,2})[.)]\s+(.*)$/;
const TOOL_SPAN = /`([a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+)(?:\s+([^`]*))?`/;

export interface RunbookStepDef {
  readonly n: number;
  readonly text: string;
  readonly tool?: string;
  /** `{{param}}` yer tutucuları DAHİL, ayrıştırılmış JSON argümanlar. */
  readonly args?: Record<string, unknown>;
}

export interface Runbook {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly params: Readonly<Record<string, string>>;
  readonly steps: readonly RunbookStepDef[];
  readonly tokens: number;
}

export function parseRunbook(name: string, text: string): Runbook {
  const bad = (msg: string): never => {
    throw new OpsError("runbook_invalid", `runbook '${name}': ${msg}`);
  };
  if (!SKILL_NAME.test(name) || name.length > 64) bad("dosya adı küçük harf-rakam-tire olmalı (≤64)");
  if (text.length > RUNBOOK_LIMITS.chars) bad(`${RUNBOOK_LIMITS.chars} karakteri aşıyor`);
  if (hasInvisible(text) || hasVariationRun(text)) bad("görünmez/çift yönlü/etiket Unicode karakteri var (Trojan Source / ASCII smuggling)");

  let title = name;
  let description = "";
  const params: Record<string, string> = {};
  let body = text;
  const fm = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (fm) {
    let raw: unknown;
    try {
      raw = parse(fm[1] as string);
    } catch {
      return bad("ön bilgi YAML olarak okunamadı");
    }
    if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
      const r = raw as Record<string, unknown>;
      for (const k of Object.keys(r)) if (!["title", "description", "params"].includes(k)) bad(`ön bilgide bilinmeyen anahtar: '${k.slice(0, 30)}'`);
      if (typeof r["title"] === "string") title = r["title"].trim().slice(0, 120);
      if (typeof r["description"] === "string") description = r["description"].trim().slice(0, 400);
      const p = r["params"];
      if (p !== undefined) {
        if (p === null || typeof p !== "object" || Array.isArray(p)) bad("params bir eşleme olmalı");
        const entries = Object.entries(p as Record<string, unknown>);
        if (entries.length > RUNBOOK_LIMITS.params) bad(`en çok ${RUNBOOK_LIMITS.params} parametre`);
        for (const [k, v] of entries) {
          if (!PARAM_KEY.test(k)) bad(`parametre adı geçersiz: '${k.slice(0, 30)}'`);
          if (!["string", "number", "boolean"].includes(typeof v)) bad(`parametre '${k}' skaler olmalı`);
          const sv = String(v);
          if (sv.length > RUNBOOK_LIMITS.paramValue) bad(`parametre '${k}' çok uzun`);
          params[k] = sv;
        }
      }
    }
    body = fm[2] as string;
  }

  const steps: RunbookStepDef[] = [];
  let cur: { lines: string[] } | null = null;
  const flush = (): void => {
    if (!cur) return;
    const raw = cur.lines.join(" ").replace(/\s+/g, " ").trim();
    cur = null;
    const n = steps.length + 1;
    let tool: string | undefined;
    let args: Record<string, unknown> | undefined;
    let textOnly = raw;
    const m = TOOL_SPAN.exec(raw);
    if (m) {
      const t = m[1] as string;
      if (!TOOL_NAME_PATTERN.test(t)) bad(`adım ${n}: araç adı geçersiz`);
      tool = t;
      const a = (m[2] ?? "").trim();
      if (a !== "") {
        let j: unknown;
        try {
          j = JSON.parse(a);
        } catch {
          return bad(`adım ${n}: argümanlar geçerli JSON nesnesi olmalı (\`${t} {"anahtar":"değer"}\`)`);
        }
        if (j === null || typeof j !== "object" || Array.isArray(j)) bad(`adım ${n}: argümanlar bir JSON nesnesi olmalı`);
        args = j as Record<string, unknown>;
      }
      textOnly = raw.replace(TOOL_SPAN, "").replace(/\s+/g, " ").replace(/\s+([.,;:])/g, "$1").trim();
    }
    if (textOnly.length > RUNBOOK_LIMITS.stepText) bad(`adım ${n}: açıklama ${RUNBOOK_LIMITS.stepText} karakteri aşıyor`);
    if (textOnly === "" && !tool) bad(`adım ${n} boş`);
    steps.push({ n, text: textOnly || (tool ?? ""), ...(tool ? { tool } : {}), ...(args ? { args } : {}) });
    if (steps.length > RUNBOOK_LIMITS.steps) bad(`en çok ${RUNBOOK_LIMITS.steps} adım`);
  };
  for (const line of body.split(/\r?\n/)) {
    const s = STEP_START.exec(line);
    if (s) {
      flush();
      cur = { lines: [s[2] as string] };
    } else if (cur && line.trim() !== "" && /^\s{2,}\S/.test(line)) {
      cur.lines.push(line.trim());
    } else {
      flush();
    }
  }
  flush();
  if (steps.length === 0) bad("numaralı adım (1. …) bulunamadı");
  return { name, title, description: description || title, params, steps, tokens: estimateTokens(body) };
}

const PLACEHOLDER = /\{\{\s*([a-z_][a-z0-9_]{0,40})\s*\}\}/g;

/** Yer tutucuları YALNIZ string değerlerde yerine koyar; eksik parametreleri döndürür. Yapıyı (anahtarlar, tür) değiştirmez. */
export function substituteArgs(args: Record<string, unknown>, params: Readonly<Record<string, string>>): { args: Record<string, unknown>; missing: string[] } {
  const missing = new Set<string>();
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      return v.replace(PLACEHOLDER, (_m, k: string) => {
        const val = Object.hasOwn(params, k) ? params[k] : undefined;
        if (val === undefined) {
          missing.add(k);
          return "";
        }
        return val;
      });
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return { args: walk(args) as Record<string, unknown>, missing: [...missing] };
}

export interface RunbookIssue {
  readonly file: string;
  readonly problem: string;
}

/** `OPS_HOME/runbooks/*.md`. Güven katmanı: kullanıcı (kendi dosyası); hatalı runbook yüklenmez. */
export class RunbookRegistry {
  private readonly items = new Map<string, Runbook>();
  readonly issues: RunbookIssue[] = [];

  static async load(dir: string): Promise<RunbookRegistry> {
    const reg = new RunbookRegistry();
    let names: string[];
    try {
      names = (await readdir(dir)).filter((n) => n.endsWith(".md")).sort();
    } catch {
      return reg;
    }
    for (const file of names) {
      const path = join(dir, file);
      try {
        if (!(await stat(path)).isFile()) continue;
        const rb = parseRunbook(file.slice(0, -3), await readFile(path, "utf8"));
        reg.items.set(rb.name, rb);
      } catch (e) {
        reg.issues.push({ file, problem: e instanceof Error ? e.message : String(e) });
      }
    }
    return reg;
  }

  get count(): number {
    return this.items.size;
  }
  get(name: string): Runbook | undefined {
    return this.items.get(name);
  }
  all(): Runbook[] {
    return [...this.items.values()].sort((a, b) => a.name.localeCompare(b.name));
  }
}
