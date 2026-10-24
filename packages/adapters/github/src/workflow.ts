import { parse } from "yaml";
import { OpsError } from "@ops/contracts";
import { safeName } from "./safe.ts";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** Bağlam ifadeleri: bunlar saldırgan denetimli metin taşıyabilir (başlık, gövde, dal adı...). */
const UNTRUSTED_CTX = /\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|review_comment|pages|commits|head_commit|workflow_run)\.[\w.\[\]*]*(?:title|body|label|name|email|message|ref|default_branch|head_ref)\b[\w.\[\]*]*|github\.head_ref|github\.event\.pull_request\.head\.[\w.]+)\s*\}\}/gi;

export interface WorkflowFacts {
  readonly path: string;
  readonly name?: string;
  readonly triggers: string[];
  readonly riskyTriggers: string[];
  readonly permissions: string | Record<string, string> | "belirtilmedi";
  readonly jobs: {
    readonly id: string;
    readonly runsOn: string;
    readonly selfHosted: boolean;
    readonly permissions?: string | Record<string, string>;
    readonly needs?: string[];
    readonly uses: { readonly ref: string; readonly pinned: boolean; readonly kind: "action" | "reusable-workflow" | "docker" | "local" }[];
  }[];
  /** Başvurulan Actions secret ADLARI (M1 `secret` anahtar adını maskeleyeceğinden alan adı bilerek nötr). */
  readonly storedValueNames: string[];
  /** `run:` içinde doğrudan enterpolasyonla kullanılan saldırgan denetimli bağlamlar (betik enjeksiyonu). */
  readonly expressionInjection: string[];
  readonly lines: number;
}

const RISKY = new Set(["pull_request_target", "workflow_run", "issue_comment", "issues", "pull_request_review_comment", "pull_request_review", "discussion", "discussion_comment", "fork", "watch"]);

function triggersOf(on: unknown): string[] {
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.filter((x): x is string => typeof x === "string");
  if (isObj(on)) return Object.keys(on);
  return [];
}

function permsOf(p: unknown): string | Record<string, string> | undefined {
  if (typeof p === "string") return safeName(p, 20);
  if (isObj(p)) {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(p).slice(0, 30)) out[safeName(k, 40) ?? "?"] = safeName(v, 20) ?? "?";
    return out;
  }
  return undefined;
}

function useKind(ref: string, job: boolean): "action" | "reusable-workflow" | "docker" | "local" {
  if (ref.startsWith("./")) return "local";
  if (ref.startsWith("docker://")) return "docker";
  return job ? "reusable-workflow" : "action";
}

/**
 * Workflow dosyasından DETERMİNİSTİK olgular çıkarır (yorum/yargı yok: pinsiz action, geniş izin,
 * riskli tetikleyici gibi kuralların yorumu skill + kural dosyasındadır). Değişken DEĞERLERİ
 * (env, with) çıktıya GİRMEZ; yalnız secret ADLARI.
 */
export function workflowFacts(path: string, text: string): WorkflowFacts {
  if (text.length > 300_000) throw new OpsError("workflow_too_large", "workflow dosyası çok büyük");
  let doc: unknown;
  try {
    doc = parse(text, { maxAliasCount: 50, strict: false, uniqueKeys: false });
  } catch {
    throw new OpsError("workflow_invalid", "workflow YAML olarak ayrıştırılamadı");
  }
  if (!isObj(doc)) throw new OpsError("workflow_invalid", "workflow bir YAML eşlemesi olmalı");
  // YAML 1.1: `on:` bazı ayrıştırıcılarda `true` anahtarı olur
  const on = doc["on"] ?? doc["true" as string];
  const triggers = triggersOf(on).map((t) => safeName(t, 40) ?? "?");
  const jobsRaw = isObj(doc["jobs"]) ? doc["jobs"] : {};
  const injection = new Set<string>();
  const jobs = Object.entries(jobsRaw)
    .slice(0, 50)
    .map(([id, j]) => {
      const job = isObj(j) ? j : {};
      const uses: WorkflowFacts["jobs"][number]["uses"] = [];
      if (typeof job["uses"] === "string") uses.push({ ref: safeName(job["uses"], 140) ?? "?", pinned: /@[0-9a-f]{40}$/.test(job["uses"]), kind: useKind(job["uses"], true) });
      const steps = Array.isArray(job["steps"]) ? job["steps"] : [];
      for (const s of steps.slice(0, 200)) {
        if (!isObj(s)) continue;
        if (typeof s["uses"] === "string") uses.push({ ref: safeName(s["uses"], 140) ?? "?", pinned: /@[0-9a-f]{40}$/.test(s["uses"]) || s["uses"].startsWith("docker://") && /@sha256:[0-9a-f]{64}$/.test(s["uses"]), kind: useKind(s["uses"], false) });
        if (typeof s["run"] === "string") for (const m of s["run"].matchAll(UNTRUSTED_CTX)) injection.add(safeName(m[1], 80) ?? "?");
      }
      const runsOnRaw = job["runs-on"];
      const runsOn = typeof runsOnRaw === "string" ? runsOnRaw : Array.isArray(runsOnRaw) ? runsOnRaw.filter((x) => typeof x === "string").join(",") : isObj(runsOnRaw) ? "grup/etiket" : "?";
      const perms = permsOf(job["permissions"]);
      const needs = typeof job["needs"] === "string" ? [job["needs"]] : Array.isArray(job["needs"]) ? job["needs"].filter((x): x is string => typeof x === "string") : [];
      return {
        id: safeName(id, 60) ?? "?",
        runsOn: safeName(runsOn, 80) ?? "?",
        selfHosted: /self-hosted/i.test(runsOn),
        ...(perms !== undefined ? { permissions: perms } : {}),
        ...(needs.length ? { needs: needs.slice(0, 20).map((n) => safeName(n, 60) ?? "?") } : {}),
        uses,
      };
    });
  const storedValueNames = [...new Set([...text.matchAll(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]{0,60})/g)].map((m) => m[1] as string))].sort().slice(0, 40);
  const topPerms = permsOf(doc["permissions"]);
  const name = safeName(doc["name"], 80);
  return {
    path,
    ...(name ? { name } : {}),
    triggers,
    riskyTriggers: triggers.filter((t) => RISKY.has(t)),
    permissions: topPerms ?? "belirtilmedi",
    jobs,
    storedValueNames,
    expressionInjection: [...injection].slice(0, 20),
    lines: text.split("\n").length,
  };
}
