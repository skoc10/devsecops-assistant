import type { RiskClass } from "@ops/contracts";
import type { CommandCatalog, CommandEntryT, SubcommandT } from "./catalog.ts";
import { parseShell } from "./shell-parse.ts";
import type { Connector } from "./shell-parse.ts";

/** Kimlik/secret yolu parçaları: iş alanı içinde bile okunmaz (T15/T20). */
const SECRET_SEGMENT =
  /^(?:\.ssh|\.aws|\.kube|\.azure|\.gnupg|\.docker|\.netrc|\.npmrc|\.git-credentials|\.config|\.cursor|\.terraform|\.git|id_rsa|id_ed25519|id_ecdsa|id_dsa|credentials|\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|tfstate|tfvars)|.*\.tfstate\..*)$/i;
const REF = /^[A-Za-z0-9_./^~@{}:-]{1,100}$/;

export interface ResolvedCommand {
  readonly binary: string;
  /** Çalıştırılacak nihai argümanlar (sertleştirme dahil), ikili hariç. */
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly class: RiskClass;
  readonly network: "none" | "allowlisted" | "open";
}

export interface ExecPlan {
  /** Her boru hattı `|` ile bağlı aşamalardan oluşur. */
  readonly pipelines: readonly (readonly ResolvedCommand[])[];
  /** Boru hatları arası bağlaçlar (`&&`, `||`, `;`). */
  readonly links: readonly ("&&" | "||" | ";")[];
}

export type ClassifyResult =
  | { readonly ok: true; readonly class: RiskClass; readonly plan: ExecPlan }
  | { readonly ok: false; readonly reason: string };

const no = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

export function checkJailedPath(p: string, jailRoot: string): string | null {
  if (p.length === 0 || p.length > 300) return "yol uzunluğu geçersiz";
  if (p.startsWith("~")) return "'~' ile başlayan yol";
  if (p.includes("\0")) return "NUL içeren yol";
  const segs = p.split("/");
  if (segs.includes("..")) return "'..' içeren yol";
  if (p.startsWith("/")) {
    const root = jailRoot.replace(/\/+$/, "");
    if (!(p === root || p.startsWith(`${root}/`))) return "iş alanı dışında mutlak yol";
  }
  for (const s of segs) if (s !== "" && s !== "." && SECRET_SEGMENT.test(s)) return `kimlik/secret yolu deseni: ${s.slice(0, 40)}`;
  return null;
}

function pickSub(entry: CommandEntryT, tokens: readonly string[]): { sub: SubcommandT; consumed: number } | null {
  const subs = [...entry.subcommands].sort((a, b) => b.path.length - a.path.length);
  for (const s of subs) {
    if (s.path.every((p, i) => tokens[i] === p)) return { sub: s, consumed: s.path.length };
  }
  return null;
}

export function classifyCommand(argv: readonly string[], catalog: CommandCatalog, jailRoot: string): { ok: true; cmd: ResolvedCommand } | { ok: false; reason: string } {
  const bin = argv[0] as string;
  if (!/^[a-z][a-z0-9_.-]*$/.test(bin)) return no("ikili adı yol veya geçersiz biçim (yalnız katalogdaki çıplak ad)");
  const entry = catalog.commands.find((c) => c.binary === bin);
  if (!entry) return no(`'${bin.slice(0, 40)}' komut kataloğunda yok`);
  const tokens = argv.slice(1);
  const picked = pickSub(entry, tokens);
  if (!picked) return no(`'${bin}' için izinli alt komut yok`);
  const { sub, consumed } = picked;
  const rest = tokens.slice(consumed);

  const flagSet = new Set(sub.flags);
  const valueFlagSet = new Set(sub.valueFlags);
  const valueRe = new RegExp(sub.valuePattern);
  const kept: string[] = [];
  let afterDD = false;
  const positionals: string[] = [];

  for (let i = 0; i < rest.length; i++) {
    const t = rest[i] as string;
    if (!afterDD && t === "--") {
      afterDD = true;
      kept.push(t);
      continue;
    }
    if (!afterDD && t.startsWith("-")) {
      if (flagSet.has(t)) {
        kept.push(t);
        continue;
      }
      const eq = t.indexOf("=");
      if (eq > 0 && t.startsWith("--") && valueFlagSet.has(t.slice(0, eq))) {
        if (!valueRe.test(t.slice(eq + 1))) return no(`${t.slice(0, eq)} değeri geçersiz`);
        kept.push(t);
        continue;
      }
      if (valueFlagSet.has(t)) {
        const v = rest[i + 1];
        if (v === undefined || !valueRe.test(v)) return no(`${t} değeri eksik veya geçersiz`);
        kept.push(t, v);
        i += 1;
        continue;
      }
      // kısa bayrak kümesi (-la): her harf ayrı izinli bayrak olmalı
      if (/^-[A-Za-z0-9]{2,}$/.test(t) && [...t.slice(1)].every((ch) => flagSet.has(`-${ch}`))) {
        kept.push(t);
        continue;
      }
      return no(`izin verilmeyen bayrak: ${t.split("=")[0]?.slice(0, 30)}`);
    }
    // konumsal
    const kind = afterDD ? (sub.positional.afterDoubleDash ?? sub.positional.kind) : sub.positional.kind;
    if (kind === "none") return no("bu komut konumsal argüman almaz");
    const isPattern = sub.positional.firstIsPattern && positionals.length === 0 && !afterDD;
    if (isPattern) {
      if (t.length > 200) return no("desen çok uzun");
    } else if (kind === "path") {
      const bad = checkJailedPath(t, jailRoot);
      if (bad) return no(bad);
    } else if (kind === "ref") {
      if (!REF.test(t)) return no("revizyon biçimi geçersiz");
    } else if (t.length > 100) return no("argüman çok uzun");
    positionals.push(t);
    kept.push(t);
  }
  if (positionals.length < sub.positional.min) return no("zorunlu konumsal argüman eksik");
  if (positionals.length > sub.positional.max) return no("çok fazla konumsal argüman");

  const h = entry.hardening;
  const subName = sub.path.join(" ");
  const args = [...(h?.prefix ?? []), ...sub.path, ...(h?.appendAfter[subName] ?? []), ...kept];
  return { ok: true, cmd: { binary: bin, args, env: h?.env ?? {}, class: entry.class, network: entry.network } };
}

/** Kabuk dizgisini ayrıştırır, her basit komutu kataloğa göre sınıflar; sınıf = en yüksek. */
export function classifyShell(command: string, catalog: CommandCatalog, jailRoot: string): ClassifyResult {
  const parsed = parseShell(command);
  if (!parsed.ok) return no(parsed.reason);
  const resolved: ResolvedCommand[] = [];
  for (const c of parsed.commands) {
    const r = classifyCommand(c.argv, catalog, jailRoot);
    if (!r.ok) return no(r.reason);
    resolved.push(r.cmd);
  }
  // boru hatlarına böl
  const pipelines: ResolvedCommand[][] = [[resolved[0] as ResolvedCommand]];
  const links: ("&&" | "||" | ";")[] = [];
  parsed.connectors.forEach((conn: Connector, i: number) => {
    const next = resolved[i + 1] as ResolvedCommand;
    if (conn === "|") (pipelines[pipelines.length - 1] as ResolvedCommand[]).push(next);
    else {
      links.push(conn);
      pipelines.push([next]);
    }
  });
  const order: RiskClass[] = ["read", "mutate", "deploy", "destroy"];
  const cls = resolved.reduce<RiskClass>((acc, c) => (order.indexOf(c.class) > order.indexOf(acc) ? c.class : acc), "read");
  return { ok: true, class: cls, plan: { pipelines, links } };
}
