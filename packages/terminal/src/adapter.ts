import { access, constants, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { classifyShell } from "@ops/classifiers";
import type { CommandCatalog, ResolvedCommand } from "@ops/classifiers";
import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, defineTool } from "@ops/contracts";
import type { Adapter, AdapterCall, AdapterManifest, Profile, RawToolOutput, Target } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";

export const shellRun = defineTool(
  {
    name: "shell.run",
    description: "Katalogdaki salt okunur komutları iş alanında çalıştırır (git, ls, cat, grep, jq...). Boru, &&, ||, ; serbest; yönlendirme, glob, değişken, $() YOK.",
    class: "read",
    scope: "local",
    localWrite: false,
    network: "none",
    profileKind: null,
    sensitivity: "internal",
    idempotent: true,
    limits: { timeoutMs: 30_000, maxBytes: 200_000, maxItems: 1_000, maxOutputTokens: 1_500 },
    untrustedOutput: true,
    toolset: "shell",
    typicalOutputTokens: 500,
  },
  z.strictObject({ command: z.string().min(1).max(4096) }),
);

export interface TerminalOptions {
  /** `null`/`none`: sandbox yok → araç ÇALIŞMAZ (fail-closed). */
  readonly sandbox: Sandbox | null;
  readonly catalog: CommandCatalog;
  /** İş alanı (host yolu); sandbox'a salt-okunur, AYNI yolda bağlanır. Ev dizini veya üstü olamaz. */
  readonly workdir: string;
  readonly resolveBinary?: (name: string) => Promise<string | null>;
  readonly stageTimeoutMs?: number;
}

const SYSTEM_BIN_DIRS = ["/usr/local/bin", "/usr/bin", "/bin"];
const STAGE_STDOUT_CAP = 1_000_000;
const STDERR_CAP = 8_000;
const SHELL_HOME = "/home/ops-shell";

async function defaultResolve(name: string): Promise<string | null> {
  for (const d of SYSTEM_BIN_DIRS) {
    const p = join(d, name);
    try {
      await access(p, constants.X_OK);
      return p;
    } catch {
      /* sonraki */
    }
  }
  return null;
}

/** İş alanı ev dizini, kökü veya bunların üstü olamaz (`~/.ssh`, `~/.aws` bağlanmasın). */
export async function assertSafeWorkdir(workdir: string, home: string = homedir()): Promise<string> {
  if (!workdir.startsWith("/")) throw new OpsError("workdir_invalid", "iş alanı mutlak yol olmalı");
  let real: string;
  try {
    real = await realpath(workdir);
  } catch {
    throw new OpsError("workdir_invalid", "iş alanı bulunamadı");
  }
  const h = await realpath(home).catch(() => home);
  const isAncestorOrSelf = (a: string, b: string): boolean => a === b || b.startsWith(`${a.replace(/\/+$/, "")}/`);
  if (real === "/" || isAncestorOrSelf(real, h)) {
    throw new OpsError("workdir_invalid", "iş alanı kök, ev dizini veya bunların üstü olamaz: kimlik dizinleri (.ssh, .aws, .kube) görünür olurdu; ayrı bir proje dizini seçin");
  }
  return real;
}

/**
 * `shell.run`: kimliksiz, sandbox'lı, katalog tabanlı. Kabuk ÇALIŞTIRILMAZ: ayrıştırılmış argv
 * doğrudan exec edilir; boru/bağlaç burada uygulanır. PEP sınıflandırır; adapter savunma
 * derinliği için TEKRAR sınıflar (güvenmez).
 */
export class TerminalAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  readonly definitions = [shellRun];
  private readonly o: TerminalOptions;

  constructor(opts: TerminalOptions) {
    this.o = opts;
    this.manifest = AdapterManifestSchema.parse({
      id: "terminal",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "cli",
      profileKinds: [],
      credentialKinds: [],
      capabilities: [],
      tools: [shellRun.descriptor],
    });
  }

  validateProfile(): string[] {
    return ["terminal adapter profil kullanmaz"];
  }
  resolveTarget(_t: string, _a: unknown, p: Profile): Target {
    throw new OpsError("target_unresolved", `terminal aracı profil kullanmaz (${p.id})`);
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const sb = this.o.sandbox;
    if (!sb || sb.kind === "none") throw new OpsError("sandbox_unavailable", "OS sandbox yok (bubblewrap/seatbelt): shell.run çalıştırılamaz");
    const { command } = call.args as { command: string };
    const cls = classifyShell(command, this.o.catalog, this.o.workdir);
    if (!cls.ok) throw new OpsError("unclassified", `komut sınıflanamadı: ${cls.reason}`);
    if (cls.class !== "read") throw new OpsError("ceiling_exceeded", "shell.run yalnız read sınıfı komut çalıştırır");

    const resolve = this.o.resolveBinary ?? defaultResolve;
    const stdout: string[] = [];
    let stderr = "";
    let lastExit = 0;
    let totalOut = 0;
    let truncated = false;
    const t0 = Date.now();

    const runStage = async (st: ResolvedCommand, stdin: Buffer | undefined): Promise<{ code: number; out: Buffer }> => {
      const abs = await resolve(st.binary);
      if (!abs) {
        stderr += `${st.binary}: komut bulunamadı\n`;
        return { code: 127, out: Buffer.alloc(0) };
      }
      const remaining = Math.max(1_000, call.limits.timeoutMs - (Date.now() - t0));
      const r = await sb.run({
        argv: [abs, ...st.args],
        env: { LANG: "C", LC_ALL: "C", ...st.env },
        roBinds: [this.o.workdir],
        network: "none",
        home: SHELL_HOME,
        cwd: this.o.workdir,
        ...(stdin ? { stdin } : {}),
        timeoutMs: Math.min(this.o.stageTimeoutMs ?? 15_000, remaining),
        maxOutputBytes: STAGE_STDOUT_CAP,
      });
      if (r.timedOut) stderr += `${st.binary}: zaman aşımı\n`;
      if (r.truncated) {
        truncated = true;
        stderr += `${st.binary}: çıktı sınırı aşıldı\n`;
      }
      if (stderr.length < STDERR_CAP) stderr += r.stderr.toString("utf8").slice(0, STDERR_CAP - stderr.length);
      return { code: r.timedOut ? 124 : (r.code ?? 1), out: r.stdout };
    };

    for (let i = 0; i < cls.plan.pipelines.length; i++) {
      if (i > 0) {
        const link = cls.plan.links[i - 1];
        if (link === "&&" && lastExit !== 0) continue;
        if (link === "||" && lastExit === 0) continue;
      }
      let input: Buffer | undefined;
      let last: { code: number; out: Buffer } = { code: 0, out: Buffer.alloc(0) };
      for (const stage of cls.plan.pipelines[i] as readonly ResolvedCommand[]) {
        last = await runStage(stage, input);
        input = last.out;
      }
      lastExit = last.code;
      totalOut += last.out.length;
      stdout.push(last.out.toString("utf8"));
      if (totalOut > call.limits.maxBytes) {
        truncated = true;
        break;
      }
    }
    const out = stdout.join("");
    return {
      data: { exit: lastExit, stdout: out, ...(stderr ? { stderr } : {}) },
      summary: `${command.slice(0, 80)} → çıkış ${lastExit}, ${Buffer.byteLength(out)} bayt`,
      truncated,
    };
  }
}
