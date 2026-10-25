import { rm } from "node:fs/promises";
import { join } from "node:path";
import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError } from "@ops/contracts";
import type { Adapter, AdapterCall, AdapterManifest, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import type { WorkspaceManager } from "@ops/workspace";
import { parseInventory, scanAnsible } from "./ansible.ts";
import type { AnsibleScan } from "./ansible.ts";
import { IAC_HOME, cleanWorkDir, ensureDir, readIfExists, resolveTool, runInSandbox, writeTfRc } from "./runner.ts";
import type { ResolvedTool } from "./runner.ts";
import { summarizePlan } from "./plan.ts";
import { scanTerraform } from "./terraform.ts";
import type { PrescanFinding, TerraformScan } from "./terraform.ts";
import { IAC_TOOLS } from "./tools.ts";

type Args = Record<string, unknown>;
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const line1 = (s: string, max = 200): string => (s.split("\n").find((l) => l.trim() !== "") ?? "").trim().slice(0, max);
/** Ansible hata çıktısından anlamlı satır: `ERROR!`/`[ERROR]` satırı; yoksa ilk UYARI-OLMAYAN satır. */
function ansibleMessage(text: string, max = 240): string {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const err = lines.find((l) => /^(ERROR!|\[ERROR\]|fatal:)/i.test(l)) ?? lines.find((l) => !/^\[?(WARNING|DEPRECATION WARNING)/i.test(l)) ?? lines[0] ?? "";
  const where = lines.find((l) => /^The error appears to be in /i.test(l));
  return (where ? `${err} (${where.replace(/^The error appears to be in /i, "")})` : err).slice(0, max);
}
const clip = (s: unknown, max = 200): string | undefined => (typeof s === "string" && s !== "" ? s.replace(/\s+/g, " ").trim().slice(0, max) : undefined);

interface AnsibleRecap {
  host: string;
  ok: number;
  changed: number;
  unreachable: number;
  failed: number;
  skipped: number;
}

/** Varsayılan geri çağrının (`default` stdout callback) görev düzeyi sonuçları + PLAY RECAP. Diff/ayrıntı alınmaz. */
function parseAnsibleRun(out: string): { recap: AnsibleRecap[]; tasks: { task: string; host: string; status: string; msg?: string }[] } {
  const recap: AnsibleRecap[] = [];
  const tasks: { task: string; host: string; status: string; msg?: string }[] = [];
  let task = "";
  let inRecap = false;
  for (const raw of out.split("\n")) {
    const line = raw.trimEnd();
    const t = /^TASK \[(.*)\] \*+$/.exec(line);
    if (t) {
      task = (t[1] as string).slice(0, 100);
      continue;
    }
    if (/^PLAY RECAP \*+$/.test(line)) {
      inRecap = true;
      continue;
    }
    if (inRecap) {
      const m = /^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)/.exec(line);
      if (m) recap.push({ host: (m[1] as string).slice(0, 80), ok: Number(m[2]), changed: Number(m[3]), unreachable: Number(m[4]), failed: Number(m[5]), skipped: Number(m[6]) });
      continue;
    }
    const r = /^(ok|changed|skipping|failed|fatal|unreachable): \[([^\]]+)\](?::\s*(?:FAILED|UNREACHABLE)! => (.*))?/.exec(line);
    if (r && task) {
      let msg: string | undefined;
      if (r[3]) {
        const mm = /"msg":\s*"((?:[^"\\]|\\.)*)"/.exec(r[3]);
        msg = (mm?.[1] ?? "").replace(/\\n/g, " ").slice(0, 200) || undefined;
      }
      tasks.push({ task, host: (r[2] as string).slice(0, 80), status: r[1] === "fatal" ? "failed" : (r[1] as string), ...(msg ? { msg } : {}) });
    }
  }
  const rank = (s: string): number => (s === "failed" || s === "unreachable" ? 0 : s === "changed" ? 1 : s === "ok" ? 2 : 3);
  tasks.sort((a, b) => rank(a.status) - rank(b.status));
  return { recap, tasks };
}

export interface IacAdapterOptions {
  readonly manager: WorkspaceManager;
  readonly sandbox: Sandbox | null;
  /** İkili aranacak dizinler (kullanıcı yapılandırır; PATH'e güvenilmez). */
  readonly toolDirs?: readonly string[];
  /** Sağlayıcıların bulunduğu yerel dosya aynası (salt-okunur bağlanır). */
  readonly providerMirror?: string;
}

const ENGINE_BIN = { terraform: "terraform", opentofu: "tofu" } as const;

function summarizeFindings(f: readonly PrescanFinding[]): { blocking: PrescanFinding[]; other: PrescanFinding[] } {
  return { blocking: f.filter((x) => x.severity === "block"), other: f.filter((x) => x.severity !== "block") };
}

const findingOut = (f: PrescanFinding): Obj => ({ severity: f.severity, code: f.code, message: f.message, file: f.file, line: f.line });

/**
 * IaC araçları (Terraform/OpenTofu ve Ansible): etkin çalışma alanının ANLIK KOPYASI üzerinde, OS
 * sandbox içinde, ağsız ve kimliksiz çalışır. Çalıştırma araçlarından (init/validate/lint) ÖNCE
 * deterministik ön-tarama (HCL/Ansible) yapılır: kod çalıştıran yapı → ÇALIŞMAZ (fail-closed).
 */
export class IacAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  private readonly o: IacAdapterOptions;

  constructor(opts: IacAdapterOptions) {
    this.o = opts;
    this.manifest = AdapterManifestSchema.parse({
      id: "iac",
      version: "0.1.0",
      contract: ADAPTER_CONTRACT,
      kind: "iac",
      profileKinds: [],
      credentialKinds: [],
      capabilities: ["prescan", "sandboxed-exec", "offline"],
      tools: IAC_TOOLS.map((t) => t.descriptor),
    });
  }

  get definitions(): readonly ToolDefinition[] {
    return IAC_TOOLS;
  }

  validateProfile(): string[] {
    return ["iac adapter profil kullanmaz"];
  }

  resolveTarget(_t: string, _a: unknown, profile: Profile): Target {
    return { profileId: profile.id, kind: profile.kind, endpoint: profile.targetPin.endpoint, scopes: [], refs: [] };
  }

  private current() {
    const cur = this.o.manager.current();
    if (!cur) throw new OpsError("workspace_inactive", "etkin çalışma alanı yok: `ops chat --workspace ID` ile başlatın");
    return cur;
  }

  private requireSandbox(): Sandbox {
    if (!this.o.sandbox || this.o.sandbox.kind === "none") throw new OpsError("sandbox_required", "IaC araçları için OS sandbox gerekir (bubblewrap/seatbelt)");
    return this.o.sandbox;
  }

  private async tool(name: string): Promise<ResolvedTool> {
    const t = await resolveTool(name, this.o.toolDirs ?? []);
    if (!t) throw new OpsError("tool_missing", `'${name}' bulunamadı: kurun veya yapılandırılmış araç dizinlerine ekleyin (OPS_TOOL_DIRS)`);
    return t;
  }

  private async texts(files: readonly string[], match: RegExp, fsRead: (p: string) => Promise<string>): Promise<{ path: string; text: string }[]> {
    const out: { path: string; text: string }[] = [];
    for (const f of files) {
      if (!match.test(f)) continue;
      try {
        out.push({ path: f, text: await fsRead(f) });
      } catch {
        /* büyük/ikili: atla */
      }
    }
    return out;
  }

  private async scanTf(cur: ReturnType<IacAdapter["current"]>): Promise<TerraformScan> {
    const files = await cur.fs.listFiles();
    return scanTerraform(await this.texts(files, /\.(tf|tofu)(\.json)?$/, (p) => cur.fs.readText(p)));
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    const cur = this.current();
    const a = (call.args ?? {}) as Args;
    switch (call.tool) {
      case "iac.project.inspect":
        return this.inspect(cur);
      case "iac.fmt":
        return this.fmt(cur, a["check"] === true);
      case "iac.validate":
        return this.validate(cur);
      case "iac.lint":
        return this.lint(cur, typeof a["playbook"] === "string" ? a["playbook"] : undefined);
      case "iac.scan":
        return this.scanSarif(cur, a["path"] as string, typeof a["maxResults"] === "number" ? (a["maxResults"] as number) : 20);
      case "iac.docs.lookup":
        return this.docs(cur, a["type"] as string, (a["kind"] as "resource" | "data" | undefined) ?? "resource");
      case "ansible.inventory.list":
        return this.inventory(cur, typeof a["path"] === "string" ? a["path"] : undefined);
      case "iac.plan":
        return this.plan(cur, a["vars"] as Record<string, string> | undefined);
      case "ansible.check":
        return this.ansibleCheck(cur, a["playbook"] as string, typeof a["inventory"] === "string" ? a["inventory"] : undefined, typeof a["limit"] === "string" ? a["limit"] : undefined);
      default:
        throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
    }
  }

  // ---- inspect ------------------------------------------------------------------------------

  private async inspect(cur: ReturnType<IacAdapter["current"]>): Promise<RawToolOutput> {
    const engine = cur.ws.engine;
    const bin = engine === "ansible" ? "ansible-playbook" : ENGINE_BIN[engine];
    const available = (await resolveTool(bin, this.o.toolDirs ?? [])) !== null;
    if (engine === "ansible") {
      const files = await cur.fs.listFiles();
      const an = scanAnsible(await this.collectAnsible(cur, files));
      const { blocking, other } = summarizeFindings(an.findings);
      return {
        data: { engine, tool: { name: bin, available }, ...an.model, blocked: an.blocked, findings: [...blocking, ...other].slice(0, 20).map(findingOut), skipped: cur.fs.snapshot.manifest.skipped.length },
        summary: `Ansible: ${an.model.playbooks.length} playbook, ${an.model.roles.length} rol, ${an.model.taskCount} görev (en yüksek sınıf ${an.model.maxClass})`,
        subjects: [`Workspace/${cur.ws.id}`],
      };
    }
    const tf = await this.scanTf(cur);
    const { blocking, other } = summarizeFindings(tf.findings);
    const m = tf.model;
    return {
      data: {
        engine,
        tool: { name: bin, available },
        files: m.files,
        requiredVersion: m.requiredVersion,
        backend: m.backend,
        providers: m.providers,
        modules: m.modules,
        dirs: Object.fromEntries(
          Object.entries(m.dirs)
            .sort(([a], [b]) => (a === "." ? -1 : b === "." ? 1 : a.localeCompare(b)))
            .slice(0, 30)
            .map(([d, x]) => [d, { variables: x.variables.map((v) => `${v.name}${v.type ? `:${v.type}` : ""}${v.hasDefault ? "=" : ""}${v.sensitive ? " [hassas]" : ""}`), outputs: x.outputs.map((o) => `${o.name}${o.sensitive ? " [hassas]" : ""}`), resources: x.resources, dataSources: x.dataSources }]),
        ),
        resources: m.resources,
        dataSources: m.dataSources,
        blocked: tf.blocked,
        findings: [...blocking, ...other].slice(0, 20).map(findingOut),
        skipped: cur.fs.snapshot.manifest.skipped.length,
      },
      summary: `${engine}: ${m.files} dosya, ${Object.values(m.resources).reduce((x, y) => x + y, 0)} kaynak${tf.blocked ? ", ÖN-TARAMA ENGELİ var" : ""}`,
      subjects: [`Workspace/${cur.ws.id}`],
    };
  }

  private async collectAnsible(cur: ReturnType<IacAdapter["current"]>, files: readonly string[]): Promise<{ path: string; text: string }[]> {
    const out: { path: string; text: string }[] = [];
    for (const f of files) {
      if (/\.(ya?ml|ini)$/.test(f)) {
        try {
          out.push({ path: f, text: await cur.fs.readText(f) });
        } catch {
          out.push({ path: f, text: "" });
        }
      } else {
        // varlık işaretleri (ansible.cfg, eklenti dizinleri) için içerik gerekmez
        out.push({ path: f, text: "" });
      }
    }
    return out;
  }

  // ---- terraform çalıştırma yardımcıları -----------------------------------------------------

  private async tfEnv(cur: ReturnType<IacAdapter["current"]>): Promise<{ env: Record<string, string>; tfdata: string; roBinds: string[]; rwBinds: string[] }> {
    const tfdata = await ensureDir(join(cur.fs.snapshot.dir, "tfdata"));
    const rc = join(cur.fs.snapshot.dir, "tf.rc");
    await writeTfRc(rc, this.o.providerMirror);
    return {
      tfdata,
      env: { TF_IN_AUTOMATION: "1", TF_INPUT: "0", CHECKPOINT_DISABLE: "1", TF_DATA_DIR: tfdata, TF_CLI_CONFIG_FILE: rc, TF_CLI_ARGS: "", TF_LOG: "", TOFU_CLI_CONFIG_FILE: rc },
      roBinds: [rc, ...(this.o.providerMirror ? [this.o.providerMirror] : [])],
      rwBinds: [cur.fs.root, tfdata],
    };
  }

  private requireTfEngine(cur: ReturnType<IacAdapter["current"]>): "terraform" | "opentofu" {
    if (cur.ws.engine === "ansible") throw new OpsError("engine_mismatch", "bu araç Terraform/OpenTofu çalışma alanları içindir (çalışma alanı: ansible)");
    return cur.ws.engine;
  }

  // ---- fmt ----------------------------------------------------------------------------------

  private async fmt(cur: ReturnType<IacAdapter["current"]>, check: boolean): Promise<RawToolOutput> {
    const engine = this.requireTfEngine(cur);
    const sandbox = this.requireSandbox();
    const tool = await this.tool(ENGINE_BIN[engine]);
    const e = await this.tfEnv(cur);
    const res = await runInSandbox({ sandbox, tool, args: ["fmt", "-recursive", "-list=true", "-no-color", ...(check ? ["-check"] : [])], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env: e.env, timeoutMs: 60_000, maxOutputBytes: 400_000 });
    const removed = await cleanWorkDir(cur.fs.root);
    const out = res.stdout.toString("utf8");
    const err = res.stderr.toString("utf8");
    if (res.timedOut) throw new OpsError("tool_timeout", "fmt zaman aşımına uğradı");
    const files = out.split("\n").map((l) => l.trim()).filter((l) => /^[A-Za-z0-9._@+=/-]+$/.test(l));
    if (res.code !== 0 && res.code !== 3) {
      const diags = this.parseTfStderr(err);
      return { data: { ok: false, syntaxErrors: diags, note: "fmt sözdizimi hatası nedeniyle çalışmadı" }, summary: `fmt: ${diags.length} sözdizimi hatası`, subjects: [`Workspace/${cur.ws.id}`] };
    }
    return {
      data: { ok: true, mode: check ? "check" : "write", files: files.slice(0, 50), count: files.length, ...(removed.length ? { cleaned: removed } : {}) },
      summary: `fmt: ${files.length} dosya ${check ? "biçimlendirilmeli" : "biçimlendirildi"}`,
      subjects: files.slice(0, 20).map((f) => `File/${cur.ws.id}/${f}`),
    };
  }

  private parseTfStderr(err: string): { severity: string; message: string; file?: string; line?: number }[] {
    const out: { severity: string; message: string; file?: string; line?: number }[] = [];
    // OpenTofu/Terraform çerçeve karakterleri (╷ │ ╵) temizlenir
    const flat = err.replace(/^[╷╵]\s*$/gm, "").replace(/^│ ?/gm, "");
    const blocks = flat.split(/\n(?=Error:|Warning:)/);
    for (const b of blocks) {
      const head = /^(Error|Warning): (.+)$/m.exec(b);
      if (!head) continue;
      const loc = /on ([A-Za-z0-9._@+=/-]+) line (\d+)/.exec(b);
      out.push({ severity: (head[1] as string).toLowerCase(), message: (head[2] as string).slice(0, 200), ...(loc ? { file: loc[1] as string, line: Number(loc[2]) } : {}) });
      if (out.length >= 10) break;
    }
    if (out.length === 0 && flat.trim()) out.push({ severity: "error", message: line1(flat) });
    return out;
  }

  // ---- validate -----------------------------------------------------------------------------

  private async validate(cur: ReturnType<IacAdapter["current"]>): Promise<RawToolOutput> {
    const engine = this.requireTfEngine(cur);
    const sandbox = this.requireSandbox();
    const scan = await this.scanTf(cur);
    if (scan.blocked) {
      const { blocking, other } = summarizeFindings(scan.findings);
      return {
        data: { executed: false, blocked: true, reason: "ön-tarama kod çalıştıran/doğrulanamayan yapı buldu: init/validate ÇALIŞTIRILMADI", findings: [...blocking, ...other].slice(0, 20).map(findingOut) },
        summary: `validate ÇALIŞMADI: ${blocking.length} engelleyici bulgu`,
        subjects: [`Workspace/${cur.ws.id}`],
      };
    }
    const tool = await this.tool(ENGINE_BIN[engine]);
    const e = await this.tfEnv(cur);
    const before = await readIfExists(join(cur.fs.root, ".terraform.lock.hcl"));
    const init = await runInSandbox({ sandbox, tool, args: ["init", "-backend=false", "-input=false", "-no-color"], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env: e.env, timeoutMs: 120_000, maxOutputBytes: 400_000 });
    if (init.timedOut) throw new OpsError("tool_timeout", "init zaman aşımına uğradı");
    if (init.code !== 0) {
      await cleanWorkDir(cur.fs.root);
      const diags = this.parseTfStderr(init.stderr.toString("utf8") || init.stdout.toString("utf8"));
      const hint = /provider|plugin|registry|install/i.test(init.stderr.toString("utf8")) ? "sağlayıcı kurulamadı: sandbox ağsız; sağlayıcıları yerel aynaya koyun (providerMirror / OPS_IAC_PROVIDER_MIRROR)" : undefined;
      return { data: { executed: true, initOk: false, diagnostics: diags, ...(hint ? { hint } : {}), findings: scan.findings.slice(0, 10).map(findingOut) }, summary: `init başarısız: ${diags[0]?.message ?? "?"}`.slice(0, 200), subjects: [`Workspace/${cur.ws.id}`] };
    }
    const val = await runInSandbox({ sandbox, tool, args: ["validate", "-json", "-no-color"], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env: e.env, timeoutMs: 120_000, maxOutputBytes: 1_000_000 });
    const removed = await cleanWorkDir(cur.fs.root);
    if (val.timedOut) throw new OpsError("tool_timeout", "validate zaman aşımına uğradı");
    let j: Obj;
    try {
      j = obj(JSON.parse(val.stdout.toString("utf8")));
    } catch {
      throw new OpsError("tool_output_invalid", `validate çıktısı JSON değil (çıkış kodu ${val.code ?? "?"})`);
    }
    const diagnostics = arr(j["diagnostics"]).map(obj).slice(0, 20).map((d) => {
      const range = obj(d["range"]);
      return { severity: clip(d["severity"], 10), summary: clip(d["summary"], 160), detail: clip(d["detail"], 240), file: clip(range["filename"], 120), line: typeof obj(range["start"])["line"] === "number" ? obj(range["start"])["line"] : undefined };
    });
    const after = await readIfExists(join(cur.fs.root, ".terraform.lock.hcl"));
    const lock = after === null ? "yok" : before === null ? "oluşturuldu" : before === after ? "değişmedi" : "DEĞİŞTİ";
    return {
      data: {
        executed: true,
        valid: j["valid"] === true,
        errors: j["error_count"],
        warnings: j["warning_count"],
        diagnostics,
        lockFile: lock,
        findings: scan.findings.slice(0, 10).map(findingOut),
        ...(removed.length ? { cleaned: removed } : {}),
        ...(lock === "DEĞİŞTİ" ? { note: "sağlayıcı kilit dosyası değişti: hash farkını gözden geçirin" } : {}),
      },
      summary: j["valid"] === true ? `geçerli (${j["warning_count"] ?? 0} uyarı)` : `geçersiz: ${j["error_count"] ?? "?"} hata`,
      subjects: [`Workspace/${cur.ws.id}`],
    };
  }

  // ---- lint ---------------------------------------------------------------------------------

  private async lint(cur: ReturnType<IacAdapter["current"]>, playbook?: string): Promise<RawToolOutput> {
    const sandbox = this.requireSandbox();
    if (cur.ws.engine !== "ansible") {
      const tflint = await resolveTool("tflint", this.o.toolDirs ?? []);
      if (!tflint) return { data: { tool: "tflint", available: false, note: "tflint kurulu değil; iac.validate ve iac.fmt kullanın" }, summary: "tflint yok", subjects: [`Workspace/${cur.ws.id}`] };
      const cfg = join(cur.fs.snapshot.dir, "tflint.hcl");
      await ensureDir(cur.fs.snapshot.dir);
      await (await import("node:fs/promises")).writeFile(cfg, "config {\n  call_module_type = \"local\"\n}\n", { mode: 0o600 });
      const res = await runInSandbox({ sandbox, tool: tflint, args: ["--format=json", "--no-color", `--config=${cfg}`, `--chdir=${cur.fs.root}`], cwd: cur.fs.root, rwBinds: [cur.fs.root], roBinds: [cfg], timeoutMs: 120_000, maxOutputBytes: 1_000_000 });
      let issues: unknown[] = [];
      try {
        issues = arr(obj(JSON.parse(res.stdout.toString("utf8")))["issues"]);
      } catch {
        /* biçim dışı */
      }
      const items = issues.map(obj).slice(0, 30).map((i) => ({ rule: clip(obj(i["rule"])["name"], 60), severity: clip(obj(i["rule"])["severity"], 12), message: clip(i["message"], 200), file: clip(obj(i["range"])["filename"], 120), line: obj(obj(i["range"])["start"])["line"] }));
      return { data: { tool: "tflint", available: true, issues: items, total: issues.length }, summary: `tflint: ${issues.length} bulgu`, subjects: [`Workspace/${cur.ws.id}`] };
    }

    const an = scanAnsible(await this.collectAnsible(cur, await cur.fs.listFiles()));
    if (an.blocked) {
      const { blocking, other } = summarizeFindings(an.findings);
      return { data: { executed: false, blocked: true, reason: "ön-tarama yerel eklenti/modül dizini veya ayrıştırılamayan YAML buldu: ansible araçları ÇALIŞTIRILMADI", findings: [...blocking, ...other].slice(0, 20).map(findingOut) }, summary: `lint ÇALIŞMADI: ${blocking.length} engelleyici bulgu`, subjects: [`Workspace/${cur.ws.id}`] };
    }
    const home = join(cur.fs.snapshot.dir, "ansible-home");
    await ensureDir(home);
    const cfg = join(cur.fs.snapshot.dir, "ansible.cfg");
    const lintCfg = join(cur.fs.snapshot.dir, "ansible-lint.yml");
    const fsp = await import("node:fs/promises");
    await fsp.writeFile(cfg, "[defaults]\nhost_key_checking = True\nretry_files_enabled = False\nnocolor = True\n", { mode: 0o600 });
    await fsp.writeFile(lintCfg, "profile: basic\nexclude_paths: []\n", { mode: 0o600 });
    const env: Record<string, string> = {
      ANSIBLE_CONFIG: cfg, ANSIBLE_HOME: `${IAC_HOME}/.ansible`, ANSIBLE_LOCAL_TEMP: `${IAC_HOME}/tmp`, ANSIBLE_REMOTE_TEMP: `${IAC_HOME}/tmp`, ANSIBLE_NOCOLOR: "1",
      ANSIBLE_FORCE_COLOR: "0", ANSIBLE_HOST_KEY_CHECKING: "True", ANSIBLE_RETRY_FILES_ENABLED: "0", ANSIBLE_LOOKUP_PLUGINS: "", ANSIBLE_LIBRARY: "", ANSIBLE_ACTION_PLUGINS: "",
      ANSIBLE_CALLBACK_PLUGINS: "", ANSIBLE_FILTER_PLUGINS: "", ANSIBLE_CALLBACKS_ENABLED: "", ANSIBLE_STDOUT_CALLBACK: "default", NO_COLOR: "1", PYTHONDONTWRITEBYTECODE: "1",
    };
    const playbooks = (playbook ? [playbook] : an.model.playbooks).slice(0, 8);
    const syntax: { playbook: string; ok: boolean; message?: string }[] = [];
    const pb = await resolveTool("ansible-playbook", this.o.toolDirs ?? []);
    if (pb) {
      for (const p of playbooks) {
        if (!an.model.playbooks.includes(p)) {
          syntax.push({ playbook: p.slice(0, 120), ok: false, message: "dosya bir playbook olarak bulunamadı" });
          continue;
        }
        const r = await runInSandbox({ sandbox, tool: pb, args: ["--syntax-check", "-i", "localhost,", p], cwd: cur.fs.root, rwBinds: [], roBinds: [cur.fs.root, cfg], env, timeoutMs: 60_000, maxOutputBytes: 200_000 });
        syntax.push({ playbook: p, ok: r.code === 0, ...(r.code === 0 ? {} : { message: ansibleMessage(r.stderr.toString("utf8") || r.stdout.toString("utf8")) }) });
      }
    }
    let lintIssues: Obj[] = [];
    let lintNote: string | undefined;
    const al = await resolveTool("ansible-lint", this.o.toolDirs ?? []);
    if (al) {
      const r = await runInSandbox({ sandbox, tool: al, args: ["-f", "json", "--nocolor", "--offline", "-c", lintCfg, "--project-dir", cur.fs.root, ...(playbook ? [playbook] : [])], cwd: cur.fs.root, rwBinds: [], roBinds: [cur.fs.root, cfg, lintCfg], env, timeoutMs: 150_000, maxOutputBytes: 2_000_000 });
      try {
        lintIssues = arr(JSON.parse(r.stdout.toString("utf8"))).map(obj);
      } catch {
        lintNote = `ansible-lint çıktısı JSON değil (çıkış kodu ${r.code ?? "?"}): ${line1(r.stderr.toString("utf8"), 160)}`;
      }
    } else lintNote = "ansible-lint kurulu değil";
    await cleanWorkDir(cur.fs.root);
    const issues = lintIssues.slice(0, 30).map((i) => ({ rule: clip(i["check_name"], 60), severity: clip(i["severity"], 12), message: clip(i["description"], 200), file: clip(obj(i["location"])["path"], 120), line: obj(obj(obj(i["location"])["lines"]))["begin"] }));
    return {
      data: { tool: "ansible", syntaxCheck: pb ? syntax : "ansible-playbook kurulu değil", lint: { issues, total: lintIssues.length, ...(lintNote ? { note: lintNote } : {}) }, findings: an.findings.filter((f) => f.severity !== "info").slice(0, 10).map(findingOut) },
      summary: `ansible: sözdizimi ${syntax.filter((s) => s.ok).length}/${syntax.length} geçti, lint ${lintIssues.length} bulgu`,
      subjects: [`Workspace/${cur.ws.id}`],
    };
  }

  // ---- scan (SARIF) -------------------------------------------------------------------------

  private async scanSarif(cur: ReturnType<IacAdapter["current"]>, path: string, max: number): Promise<RawToolOutput> {
    if (!/\.(sarif|json)$/.test(path)) throw new OpsError("scan_path_invalid", "yol .sarif veya .json olmalı");
    const text = await cur.fs.readText(path);
    let j: Obj;
    try {
      j = obj(JSON.parse(text));
    } catch {
      throw new OpsError("scan_invalid", "dosya JSON değil");
    }
    if (typeof j["version"] !== "string" || !Array.isArray(j["runs"])) throw new OpsError("scan_invalid", "SARIF 2.1.0 biçimi değil (version/runs yok)");
    const results: Obj[] = [];
    let tool: string | undefined;
    for (const run of arr(j["runs"]).map(obj)) {
      tool ??= clip(obj(obj(run["tool"])["driver"])["name"], 60);
      for (const r of arr(run["results"]).map(obj)) results.push(r);
    }
    const byLevel: Record<string, number> = {};
    for (const r of results) {
      const l = clip(r["level"], 12) ?? "warning";
      byLevel[l] = (byLevel[l] ?? 0) + 1;
    }
    const rank = (l: string | undefined): number => (l === "error" ? 0 : l === "warning" ? 1 : 2);
    const items = results
      .map((r) => {
        const loc = obj(obj(arr(r["locations"])[0])["physicalLocation"]);
        return { rule: clip(r["ruleId"], 80), level: clip(r["level"], 12) ?? "warning", message: clip(obj(r["message"])["text"], 200), file: clip(obj(loc["artifactLocation"])["uri"], 140), line: obj(loc["region"])["startLine"] };
      })
      .sort((x, y) => rank(x.level) - rank(y.level))
      .slice(0, max);
    return { data: { tool, total: results.length, byLevel, results: items }, summary: `${tool ?? "tarayıcı"}: ${results.length} sonuç`, truncated: results.length > items.length, subjects: [`File/${cur.ws.id}/${path}`] };
  }

  // ---- docs.lookup --------------------------------------------------------------------------

  private async docs(cur: ReturnType<IacAdapter["current"]>, type: string, kind: "resource" | "data"): Promise<RawToolOutput> {
    const engine = this.requireTfEngine(cur);
    const sandbox = this.requireSandbox();
    const scan = await this.scanTf(cur);
    if (scan.blocked) throw new OpsError("prescan_blocked", "ön-tarama engelleyici bulgu buldu: önce iac.project.inspect ile bulguları giderin");
    const tool = await this.tool(ENGINE_BIN[engine]);
    const e = await this.tfEnv(cur);
    const init = await runInSandbox({ sandbox, tool, args: ["init", "-backend=false", "-input=false", "-no-color"], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env: e.env, timeoutMs: 120_000, maxOutputBytes: 400_000 });
    if (init.code !== 0) {
      await cleanWorkDir(cur.fs.root);
      throw new OpsError("init_failed", `init başarısız (sağlayıcılar yerel aynada olmalı): ${line1(init.stderr.toString("utf8"), 160)}`);
    }
    const sch = await runInSandbox({ sandbox, tool, args: ["providers", "schema", "-json"], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env: e.env, timeoutMs: 120_000, maxOutputBytes: 40_000_000 });
    await cleanWorkDir(cur.fs.root);
    if (sch.code !== 0) throw new OpsError("schema_failed", `providers schema başarısız: ${line1(sch.stderr.toString("utf8"), 160)}`);
    const all = obj(obj(JSON.parse(sch.stdout.toString("utf8")))["provider_schemas"]);
    const key = kind === "resource" ? "resource_schemas" : "data_source_schemas";
    for (const [provider, ps] of Object.entries(all)) {
      const schema = obj(obj(obj(ps)[key])[type]);
      if (Object.keys(schema).length === 0) continue;
      const block = obj(schema["block"]);
      const attrs = Object.entries(obj(block["attributes"])).map(([name, v]) => {
        const at = obj(v);
        return { name, type: typeof at["type"] === "string" ? at["type"] : JSON.stringify(at["type"] ?? "?").slice(0, 60), ...(at["required"] === true ? { required: true } : {}), ...(at["computed"] === true && at["optional"] !== true ? { computedOnly: true } : {}), ...(at["sensitive"] === true ? { sensitive: true } : {}), ...(at["deprecated"] === true ? { deprecated: true } : {}), description: clip(at["description"], 100) };
      });
      attrs.sort((x, y) => Number(y.required === true) - Number(x.required === true) || x.name.localeCompare(y.name));
      const blocks = Object.entries(obj(block["block_types"])).map(([name, v]) => ({ name, nesting: clip(obj(v)["nesting_mode"], 12), maxItems: obj(v)["max_items"], minItems: obj(v)["min_items"] }));
      return { data: { provider: provider.slice(0, 80), kind, type, attributes: attrs.slice(0, 60), blocks: blocks.slice(0, 20), truncated: attrs.length > 60 || undefined }, summary: `${kind} ${type}: ${attrs.length} öznitelik, ${blocks.length} blok`, subjects: [`Workspace/${cur.ws.id}`] };
    }
    throw new OpsError("schema_not_found", `${kind} '${type}' yüklü sağlayıcılarda bulunamadı (sağlayıcı required_providers ve yerel aynada olmalı)`);
  }

  // ---- plan ---------------------------------------------------------------------------------

  /**
   * `plan` — KİMLİKSİZ, ağsız, BOŞ state'e karşı (`init -backend=false`): yapılandırmanın tam olarak ne
   * yaratacağını ve risk etiketlerini gösterir. Plan JSON'unun hassas değerleri özete GİRMEZ (`plan.ts`);
   * plan dosyası işlemden sonra silinir. Gerçek altyapıya/uzak state'e karşı plan hedefin pipeline'ındadır.
   */
  private async plan(cur: ReturnType<IacAdapter["current"]>, vars: Record<string, string> | undefined): Promise<RawToolOutput> {
    const engine = this.requireTfEngine(cur);
    const sandbox = this.requireSandbox();
    const scan = await this.scanTf(cur);
    if (scan.blocked) {
      const { blocking, other } = summarizeFindings(scan.findings);
      return {
        data: { executed: false, blocked: true, reason: "ön-tarama kod çalıştıran/doğrulanamayan yapı buldu: init/plan ÇALIŞTIRILMADI", findings: [...blocking, ...other].slice(0, 20).map(findingOut) },
        summary: `plan ÇALIŞMADI: ${blocking.length} engelleyici bulgu`,
        subjects: [`Workspace/${cur.ws.id}`],
      };
    }
    const tool = await this.tool(ENGINE_BIN[engine]);
    const e = await this.tfEnv(cur);
    const env: Record<string, string> = { ...e.env, ...Object.fromEntries(Object.entries(vars ?? {}).map(([k, v]) => [`TF_VAR_${k}`, v])) };
    const init = await runInSandbox({ sandbox, tool, args: ["init", "-backend=false", "-input=false", "-no-color"], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env, timeoutMs: 90_000, maxOutputBytes: 400_000 });
    if (init.timedOut) throw new OpsError("tool_timeout", "init zaman aşımına uğradı");
    if (init.code !== 0) {
      await cleanWorkDir(cur.fs.root);
      const diags = this.parseTfStderr(init.stderr.toString("utf8") || init.stdout.toString("utf8"));
      const hint = /provider|plugin|registry|install/i.test(init.stderr.toString("utf8")) ? "sağlayıcı kurulamadı: sandbox ağsız; sağlayıcıları yerel aynaya koyun (providerMirror / OPS_IAC_PROVIDER_MIRROR)" : undefined;
      return { data: { executed: true, initOk: false, diagnostics: diags, ...(hint ? { hint } : {}) }, summary: `init başarısız: ${diags[0]?.message ?? "?"}`.slice(0, 200), subjects: [`Workspace/${cur.ws.id}`] };
    }
    const planFile = join(e.tfdata, "plan.tfplan");
    try {
      const pl = await runInSandbox({ sandbox, tool, args: ["plan", "-input=false", "-no-color", "-lock=false", "-refresh=false", "-detailed-exitcode", `-out=${planFile}`], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env, timeoutMs: 100_000, maxOutputBytes: 1_000_000 });
      if (pl.timedOut) throw new OpsError("tool_timeout", "plan zaman aşımına uğradı");
      if (pl.code !== 0 && pl.code !== 2) {
        const diags = this.parseTfStderr(pl.stderr.toString("utf8") || pl.stdout.toString("utf8"));
        return { data: { executed: true, planned: false, diagnostics: diags }, summary: `plan başarısız: ${diags[0]?.message ?? "?"}`.slice(0, 200), subjects: [`Workspace/${cur.ws.id}`] };
      }
      const show = await runInSandbox({ sandbox, tool, args: ["show", "-json", "-no-color", planFile], cwd: cur.fs.root, rwBinds: e.rwBinds, roBinds: e.roBinds, env, timeoutMs: 60_000, maxOutputBytes: 30_000_000 });
      if (show.timedOut) throw new OpsError("tool_timeout", "show zaman aşımına uğradı");
      let doc: unknown;
      try {
        doc = JSON.parse(show.stdout.toString("utf8"));
      } catch {
        throw new OpsError("tool_output_invalid", `plan çıktısı JSON değil (çıkış kodu ${show.code ?? "?"})`);
      }
      const sum = summarizePlan(doc, { maxChanges: 40 });
      const c = sum.counts;
      return {
        data: {
          executed: true,
          planned: true,
          noChanges: pl.code === 0,
          counts: { create: c.create, update: c.update, delete: c.delete, replace: c.replace },
          changes: sum.changes,
          ...(sum.omitted > 0 ? { omitted: sum.omitted } : {}),
          outputs: sum.outputs,
          risks: sum.risks,
          note: "BOŞ state'e karşı plan (yerel, kimliksiz, ağsız): yapılandırmanın sıfırdan ne yaratacağını gösterir; gerçek altyapıya karşı diff için hedefin pipeline'ındaki plan geçerlidir. Hassas değerler gösterilmez.",
        },
        summary: `plan: +${c.create} ~${c.update} -${c.delete} ±${c.replace}${sum.risks.length ? ` · risk: ${sum.risks.map((r) => r.label).join(",")}` : ""}`,
        truncated: sum.omitted > 0,
        subjects: [`Workspace/${cur.ws.id}`, ...sum.changes.slice(0, 20).map((x) => `Resource/${x.address}`)],
      };
    } finally {
      await rm(planFile, { force: true }).catch(() => undefined);
      await cleanWorkDir(cur.fs.root);
    }
  }

  // ---- ansible.check ------------------------------------------------------------------------

  /**
   * `ansible-playbook --check` — ağsız sandbox'ta YEREL bağlantıyla. Check modunun yan etkisiz olduğu GARANTİ
   * EDİLEMEZ (`check_mode: false`, `lookup('pipe')`, sınıflanamayan modül): ön-tarama bunlardan birini
   * bulursa ÇALIŞMAZ (fail-closed). Çıktı görev düzeyindedir: `--diff` içeriği (dosya gövdeleri) alınmaz.
   */
  private async ansibleCheck(cur: ReturnType<IacAdapter["current"]>, playbook: string, inventory: string | undefined, limit: string | undefined): Promise<RawToolOutput> {
    if (cur.ws.engine !== "ansible") throw new OpsError("engine_mismatch", "bu araç Ansible çalışma alanları içindir");
    const sandbox = this.requireSandbox();
    const an = scanAnsible(await this.collectAnsible(cur, await cur.fs.listFiles()));
    if (an.blocked) {
      const { blocking, other } = summarizeFindings(an.findings);
      return { data: { executed: false, blocked: true, reason: "ön-tarama yerel eklenti/modül dizini veya ayrıştırılamayan YAML buldu: check ÇALIŞTIRILMADI", findings: [...blocking, ...other].slice(0, 20).map(findingOut) }, summary: `check ÇALIŞMADI: ${blocking.length} engelleyici bulgu`, subjects: [`Workspace/${cur.ws.id}`] };
    }
    if (!an.model.playbooks.includes(playbook)) throw new OpsError("playbook_not_found", `'${playbook.slice(0, 120)}' bir playbook olarak bulunamadı (iac.project.inspect ile listeleyin)`);
    if (inventory !== undefined && !an.model.inventories.includes(inventory)) throw new OpsError("inventory_not_found", `'${inventory.slice(0, 120)}' statik bir envanter dosyası olarak bulunamadı (ansible.inventory.list ile listeleyin)`);
    const unsafe: { code: string; message: string; file?: string; line?: number }[] = [];
    for (const f of an.findings) if (["lookup_pipe", "module_unclassified", "dynamic_include"].includes(f.code)) unsafe.push({ code: f.code, message: f.message, file: f.file, ...(f.line !== undefined ? { line: f.line } : {}) });
    for (const t of an.tasks) if (t.flags.includes("check_mode_false")) unsafe.push({ code: "check_mode_false", message: `görev check modunda da GERÇEKTEN çalışır (${t.module})`, file: t.file, line: t.line });
    if (unsafe.length > 0) {
      return {
        data: { executed: false, unsafe: true, reason: "check modunun yan etkisiz olduğu garanti edilemiyor: ÇALIŞTIRILMADI (bulguları giderin ya da kullanıcı kendi ortamında çalıştırsın)", findings: unsafe.slice(0, 15) },
        summary: `check ÇALIŞMADI: ${unsafe.length} güvensiz yapı`,
        subjects: [`Workspace/${cur.ws.id}`, `File/${cur.ws.id}/${playbook}`],
      };
    }
    const pb = await resolveTool("ansible-playbook", this.o.toolDirs ?? []);
    if (!pb) throw new OpsError("tool_missing", "'ansible-playbook' bulunamadı: kurun veya OPS_TOOL_DIRS'e ekleyin");
    const fsp = await import("node:fs/promises");
    await ensureDir(cur.fs.snapshot.dir);
    const cfg = join(cur.fs.snapshot.dir, "ansible.cfg");
    await fsp.writeFile(cfg, "[defaults]\nhost_key_checking = True\nretry_files_enabled = False\nnocolor = True\nforks = 1\n", { mode: 0o600 });
    const env: Record<string, string> = {
      ANSIBLE_CONFIG: cfg, ANSIBLE_HOME: `${IAC_HOME}/.ansible`, ANSIBLE_LOCAL_TEMP: `${IAC_HOME}/tmp`, ANSIBLE_REMOTE_TEMP: `${IAC_HOME}/tmp`, ANSIBLE_NOCOLOR: "1",
      ANSIBLE_FORCE_COLOR: "0", ANSIBLE_HOST_KEY_CHECKING: "True", ANSIBLE_RETRY_FILES_ENABLED: "0", ANSIBLE_LOOKUP_PLUGINS: "", ANSIBLE_LIBRARY: "", ANSIBLE_ACTION_PLUGINS: "",
      ANSIBLE_CALLBACK_PLUGINS: "", ANSIBLE_FILTER_PLUGINS: "", ANSIBLE_STDOUT_CALLBACK: "default", NO_COLOR: "1", PYTHONDONTWRITEBYTECODE: "1",
    };
    const args = ["--check", "-i", inventory ?? "localhost,", "-e", "ansible_connection=local", ...(limit ? ["--limit", limit] : []), playbook];
    const r = await runInSandbox({ sandbox, tool: pb, args, cwd: cur.fs.root, rwBinds: [], roBinds: [cur.fs.root, cfg], env, timeoutMs: 180_000, maxOutputBytes: 1_000_000 });
    await cleanWorkDir(cur.fs.root);
    if (r.timedOut) throw new OpsError("tool_timeout", "ansible-playbook --check zaman aşımına uğradı");
    const parsed = parseAnsibleRun(r.stdout.toString("utf8"));
    const failed = parsed.recap.reduce((n, x) => n + x.failed + x.unreachable, 0);
    const changed = parsed.recap.reduce((n, x) => n + x.changed, 0);
    const fatalMsg = r.code !== 0 && parsed.recap.length === 0 ? ansibleMessage(r.stderr.toString("utf8") || r.stdout.toString("utf8")) : undefined;
    return {
      data: {
        executed: true,
        playbook,
        inventory: inventory ?? "localhost,",
        exitCode: r.code,
        recap: parsed.recap,
        tasks: parsed.tasks.slice(0, 40),
        ...(parsed.tasks.length > 40 ? { omitted: parsed.tasks.length - 40 } : {}),
        ...(fatalMsg ? { error: fatalMsg } : {}),
        note: "YEREL bağlantı (sandbox, ağsız): görevler sanal host olarak yerelde değerlendirildi; uzak host durumu GÖRÜLMEDİ. Diff içeriği alınmaz.",
      },
      summary: fatalMsg ? `check başarısız: ${fatalMsg}`.slice(0, 200) : `check: ${changed} değişecek görev, ${failed} başarısız/ulaşılamaz`,
      truncated: parsed.tasks.length > 40,
      subjects: [`Workspace/${cur.ws.id}`, `File/${cur.ws.id}/${playbook}`],
    };
  }

  // ---- ansible.inventory.list ---------------------------------------------------------------

  private async inventory(cur: ReturnType<IacAdapter["current"]>, path?: string): Promise<RawToolOutput> {
    if (cur.ws.engine !== "ansible") throw new OpsError("engine_mismatch", "bu araç Ansible çalışma alanları içindir");
    const files = await cur.fs.listFiles();
    const cands = path ? [path] : files.filter((f) => /(^|\/)(inventory|inventories|hosts)(\/|\.|$)/.test(f) || /\.ini$/.test(f)).filter((f) => /\.(ya?ml|ini)$|(^|\/)hosts$/.test(f)).slice(0, 8);
    if (cands.length === 0) return { data: { inventories: [], note: "statik envanter dosyası bulunamadı" }, summary: "envanter yok", subjects: [`Workspace/${cur.ws.id}`] };
    const out: { path: string; dynamic: boolean; groups: unknown[]; hosts: string[]; hostVarNames: string[] }[] = [];
    for (const f of cands) {
      const text = await cur.fs.readText(f);
      const inv = parseInventory(f, text);
      out.push({ path: f, dynamic: inv.dynamic, groups: inv.groups.slice(0, 40), hosts: inv.hosts, hostVarNames: inv.hostVarNames });
    }
    return { data: { inventories: out, note: "değişken DEĞERLERİ gösterilmez; dinamik envanter (plugin/betik) çalıştırılmaz" }, summary: `${out.length} envanter, ${out.reduce((n, i) => n + i.hosts.length, 0)} host`, subjects: out.map((i) => `File/${cur.ws.id}/${i.path}`) };
  }
}
