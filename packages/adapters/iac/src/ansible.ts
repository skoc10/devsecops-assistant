import { LineCounter, isAlias, isMap, isNode, isScalar, isSeq, parseDocument } from "yaml";
import type { Document, Node, YAMLMap } from "yaml";
import { riskRank } from "@ops/contracts";
import type { RiskClass } from "@ops/contracts";
import type { PrescanFinding } from "./terraform.ts";

/**
 * Ansible sınıf kataloğu (modül başına). Sınıflanamayan modül = `destroy` muamelesi (tasarım §7.5).
 * `state: absent` kaldıran/silen kullanım `destroy`; `command/shell/raw/script` en az `deploy`.
 */
const MODULE_CLASS: Readonly<Record<string, RiskClass>> = {
  // okuma / bağlam
  setup: "read", gather_facts: "read", stat: "read", find: "read", debug: "read", assert: "read", ping: "read", slurp: "read", fail: "read", meta: "read",
  set_fact: "read", include_vars: "read", getent: "read", service_facts: "read", package_facts: "read", pause: "read", add_host: "read", group_by: "read",
  set_stats: "read", validate_argument_spec: "read", wait_for_connection: "read", include_tasks: "read", import_tasks: "read", include: "read", include_role: "read",
  import_role: "read", import_playbook: "read", fetch: "read",
  // mutasyon
  copy: "mutate", template: "mutate", lineinfile: "mutate", blockinfile: "mutate", replace: "mutate", file: "mutate", user: "mutate", group: "mutate",
  package: "mutate", apt: "mutate", yum: "mutate", dnf: "mutate", pip: "mutate", service: "mutate", systemd: "mutate", systemd_service: "mutate", cron: "mutate",
  hostname: "mutate", sysctl: "mutate", mount: "mutate", git: "mutate", unarchive: "mutate", get_url: "mutate", uri: "mutate", known_hosts: "mutate",
  authorized_key: "mutate", apt_repository: "mutate", yum_repository: "mutate", rpm_key: "mutate", apt_key: "mutate", assemble: "mutate", synchronize: "mutate",
  wait_for: "mutate", timezone: "mutate", iptables: "mutate", firewalld: "mutate", ufw: "mutate", selinux: "mutate", expect: "deploy",
  // keyfî komut
  command: "deploy", shell: "deploy", raw: "deploy", script: "deploy",
  // yıkıcı
  reboot: "destroy", shutdown: "destroy",
};

const BUILTIN_NS = /^(ansible\.builtin|ansible\.legacy|ansible\.posix|ansible\.windows)\./;
const TASK_KEYWORDS = new Set([
  "name", "when", "loop", "loop_control", "register", "become", "become_user", "become_method", "become_flags", "become_exe", "vars", "tags", "block", "rescue", "always",
  "notify", "listen", "delegate_to", "delegate_facts", "local_action", "action", "environment", "args", "check_mode", "ignore_errors", "ignore_unreachable", "changed_when",
  "failed_when", "no_log", "until", "retries", "delay", "async", "poll", "connection", "remote_user", "port", "run_once", "throttle", "any_errors_fatal", "diff",
  "module_defaults", "collections", "timeout", "debugger", "first_found", "when_changed", "no_log_values", "max_fail_percentage",
]);
const PLAY_TASK_LISTS: readonly string[] = ["pre_tasks", "tasks", "post_tasks", "handlers"];
const PLUGIN_DIRS = /(^|\/)(library|action_plugins|callback_plugins|connection_plugins|filter_plugins|lookup_plugins|inventory_plugins|module_utils|vars_plugins|strategy_plugins|become_plugins|cache_plugins|test_plugins|doc_fragments|ansible_collections)\//;
const LOOKUP_PIPE = /\b(?:lookup|query|q)\s*\(\s*['"](?:ansible\.builtin\.)?pipe['"]/i;
const CONTROLLER_EXEC = /\blocal_action\b|delegate_to:\s*['"]?(localhost|127\.0\.0\.1)\b|connection:\s*['"]?local\b/;
const ROLE_TASK_FILE = /(^|\/)roles\/[^/]+\/(tasks|handlers)\//;

/** Görev listesi yükleyen modüller: hedef dosyanın görevleri AYNI ziyaretçiyle sınıflanır. */
const TASK_INCLUDES = new Set(["include_tasks", "import_tasks", "include"]);
/** Rol yükleyen modüller: `tasks_from`/`handlers_from` (yoksa `main`) ve rolün `meta` bağımlılıkları izlenir. */
const ROLE_INCLUDES = new Set(["include_role", "import_role"]);
/** Play düzeyinde playbook yükleyen anahtarlar (normalleştirilmiş; `include` eski biçim). */
const PLAYBOOK_IMPORTS = new Set(["import_playbook", "include"]);
/** Playbook tespiti: play (`hosts`) veya playbook içe aktarımı (FQCN dahil). */
const PLAYBOOK_KEYS = new Set(["hosts", "import_playbook", "ansible.builtin.import_playbook", "ansible.legacy.import_playbook"]);
/** Rol dosyası adayları (Ansible `_load_role_yaml`: uzantısız ad ve `.yml/.yaml/.json`). Sıra önemsiz: VAR OLAN her aday taranır. */
const ROLE_FILE_EXTS = ["", ".yml", ".yaml", ".json"] as const;
/** Jinja ifadesi/deyimi/yorumu: yol çalışma anında belirlenir → statik çözülemez. */
const TEMPLATED = /\{\{|\{%|\{#/;
/** include/rol zinciri derinlik sınırı: aşılırsa fail-closed (döngüler ziyaret kümeleriyle zaten sonlanır). */
const MAX_INCLUDE_DEPTH = 24;

export interface AnsibleTask {
  readonly file: string;
  readonly line: number;
  readonly module: string;
  readonly class: RiskClass;
  readonly flags: string[];
}

export interface AnsibleModel {
  readonly files: number;
  readonly playbooks: string[];
  readonly roles: string[];
  readonly inventories: string[];
  readonly taskCount: number;
  readonly modules: Record<string, number>;
  readonly maxClass: RiskClass;
  readonly requirements: boolean;
}

export interface AnsibleScan {
  readonly model: AnsibleModel;
  readonly tasks: AnsibleTask[];
  readonly findings: PrescanFinding[];
  readonly blocked: boolean;
}

/** Ön-taramaya verilen dosya. Ansible include/rol hedefini uzantısından bağımsız YAML olarak yükler: içerik her dosya için verilmelidir. */
export interface AnsibleFile {
  readonly path: string;
  /** `null`: içerik okunamadı (ikili/çok büyük). Include/rol hedefiyse "çözülemedi" sayılır (fail-closed). */
  readonly text: string | null;
}

type ArgResult<T> = { readonly kind: "ok"; readonly value: T } | { readonly kind: "dynamic" } | { readonly kind: "invalid"; readonly why: string };

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isTemplated = (v: unknown): boolean => typeof v === "string" && TEMPLATED.test(v);
const parentOf = (p: string): string => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const baseOf = (p: string): string => p.slice(p.lastIndexOf("/") + 1);
const deref = (n: unknown, doc: Document): unknown => (isAlias(n) ? n.resolve(doc) : n);

function normalizeModule(name: string): string {
  return BUILTIN_NS.test(name) ? name.replace(BUILTIN_NS, "") : name;
}

/** Kaba `k=v` ayrıştırma (`file: path=/x state=absent`); yalnız sınıflama içindir. */
function kvArgs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tok of s.trim().split(/\s+/)) {
    const i = tok.indexOf("=");
    if (i > 0) out[tok.slice(0, i)] = tok.slice(i + 1).replace(/^(['"])(.*)\1$/, "$2");
  }
  return out;
}

/** Katı `k=v`: her parça `anahtar=değer` ve anahtar `allowed` içinde olmalı; aksi halde undefined (çağıran fail-closed davranır). */
function strictKv(s: string, allowed: ReadonlySet<string>): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const tok of s.trim().split(/\s+/)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/.exec(tok);
    if (!m || !allowed.has(m[1] as string)) return undefined;
    out[m[1] as string] = (m[2] as string).replace(/^(['"])(.*)\1$/, "$2");
  }
  return out;
}

function classOf(module: string, args: unknown): RiskClass | "unclassified" {
  const base = MODULE_CLASS[module];
  if (base === undefined) return "unclassified";
  let cls: RiskClass = base;
  const state = isObj(args) ? args["state"] : typeof args === "string" ? kvArgs(args)["state"] : undefined;
  if (state === "absent" && (module === "file" || module === "user" || module === "group" || module === "package" || module === "apt" || module === "yum" || module === "dnf" || module === "pip")) cls = "destroy";
  return cls;
}

/** `action:`/`local_action:` değerinden modül ve argüman: `shell echo` (ilk sözcük + serbest biçim) veya `{ module: shell, ... }`. */
function actionForm(a: unknown): { module: string; args: unknown } {
  if (typeof a === "string") {
    const t = a.trim();
    const i = t.search(/\s/);
    return i < 0 ? { module: t || "action", args: undefined } : { module: t.slice(0, i), args: t.slice(i + 1).trim() };
  }
  if (isObj(a)) {
    const { module, ...rest } = a;
    return { module: typeof module === "string" && module !== "" ? module : "action", args: rest };
  }
  return { module: "action", args: undefined };
}

const TASK_INCLUDE_KEYS: ReadonlySet<string> = new Set(["file", "_raw_params"]);
const ROLE_INCLUDE_KEYS: ReadonlySet<string> = new Set(["name", "role", "tasks_from", "handlers_from", "vars_from", "defaults_from", "public", "allow_duplicates", "rolespec_validate"]);

/** `include_tasks`/`import_tasks`/`include` hedef(ler)i: `x.yml`, `file=x.yml` veya `{ file: x.yml }`. */
function taskIncludeTargets(args: unknown): ArgResult<string[]> {
  let o: Record<string, unknown>;
  if (typeof args === "string") {
    if (TEMPLATED.test(args)) return { kind: "dynamic" };
    if (!/[\s=]/.test(args)) return args === "" ? { kind: "invalid", why: "hedef yok" } : { kind: "ok", value: [args] };
    const kv = strictKv(args, TASK_INCLUDE_KEYS);
    if (!kv) return { kind: "invalid", why: "serbest biçimli argüman çözülemedi" };
    o = kv;
  } else if (isObj(args)) {
    o = args;
  } else {
    return { kind: "invalid", why: "hedef yok" };
  }
  const vals = [o["file"], o["_raw_params"]].filter((v) => v !== undefined && v !== null);
  if (vals.some(isTemplated)) return { kind: "dynamic" };
  if (vals.length === 0 || vals.some((v) => typeof v !== "string" || v === "")) return { kind: "invalid", why: "hedef yok veya dizge değil" };
  return { kind: "ok", value: vals as string[] };
}

/** `include_role`/`import_role`: `name` (veya `role`), `tasks_from`, `handlers_from`; sözlük ya da `name=x tasks_from=y`. */
function roleIncludeArgs(args: unknown): ArgResult<{ name: string; tasksFrom?: string; handlersFrom?: string }> {
  let o: Record<string, unknown>;
  if (typeof args === "string") {
    if (TEMPLATED.test(args)) return { kind: "dynamic" };
    const kv = strictKv(args, ROLE_INCLUDE_KEYS);
    if (!kv) return { kind: "invalid", why: "serbest biçimli argüman çözülemedi" };
    o = kv;
  } else if (isObj(args)) {
    o = args;
  } else {
    return { kind: "invalid", why: "rol adı yok" };
  }
  const name = o["name"] ?? o["role"];
  const tasksFrom = o["tasks_from"];
  const handlersFrom = o["handlers_from"];
  if ([name, tasksFrom, handlersFrom].some(isTemplated)) return { kind: "dynamic" };
  if (typeof name !== "string" || name === "") return { kind: "invalid", why: "rol adı yok" };
  for (const v of [tasksFrom, handlersFrom]) if (v !== undefined && v !== null && typeof v !== "string") return { kind: "invalid", why: "tasks_from/handlers_from dizge değil" };
  return {
    kind: "ok",
    value: { name, ...(typeof tasksFrom === "string" && tasksFrom !== "" ? { tasksFrom } : {}), ...(typeof handlersFrom === "string" && handlersFrom !== "" ? { handlersFrom } : {}) },
  };
}

/**
 * Göreli hedefin ağaç içi soneki: sözcüksel normalleştirme, BAŞTAKİ `..` bölümleri atılır. Ansible hedefi birden çok
 * tabana göre arar (playbook dizini, rol `tasks/`, üst include dizini, cwd...); ağaçtaki HER aday bu sonekle biter →
 * sonek eşleşmesi Ansible'ın ağaç içi arama kümesinin üst kümesidir. Mutlak, `~`, boş ya da NUL/ters eğik çizgili
 * yol → undefined (ağaçta çözülemez).
 */
function treeSuffix(target: string): string | undefined {
  if (target.startsWith("/") || target.startsWith("~") || /[\0\\]/.test(target)) return undefined;
  const segs: string[] = [];
  for (const s of target.split("/")) {
    if (s === "" || s === ".") continue;
    if (s === "..") segs.pop();
    else segs.push(s);
  }
  return segs.length > 0 ? segs.join("/") : undefined;
}

/**
 * Deterministik Ansible ön-taraması. Görevler playbook'lardan, `roles/<ad>/(tasks|handlers)/` dosyalarından ve bunların
 * YÜKLEDİĞİ her dosyadan (include_tasks/import_tasks/include, include_role/import_role + `tasks_from`, play `roles:`,
 * rol `meta` bağımlılıkları, import_playbook) aynı ziyaretçiyle sınıflanır. Hedef ağaç içinde sonek eşleşmesiyle çözülür
 * (büyük/küçük harfe duyarsız: macOS); şablonlu ya da çözülemeyen hedef → bulgu + destroy muamelesi (ansible.check ÇALIŞMAZ).
 */
export function scanAnsible(files: readonly AnsibleFile[]): AnsibleScan {
  const findings: PrescanFinding[] = [];
  const add = (severity: PrescanFinding["severity"], code: string, message: string, file: string, line?: number): void => {
    findings.push({ severity, code, message, file, ...(line !== undefined ? { line } : {}) });
  };
  const tasks: AnsibleTask[] = [];
  const playbooks: string[] = [];
  const roles = new Set<string>();
  const roleDirs = new Set<string>();
  const inventories: string[] = [];
  let requirements = false;
  let scanned = 0;
  let forceDestroy = false;
  const seenDirs = new Set<string>();

  // ---- dizin: metin ve include çözümü için harfe duyarsız tam yol / taban ad eşlemleri ----------------------------
  const textOf = new Map<string, string | null>();
  const byPath = new Map<string, string[]>();
  const fileByBase = new Map<string, string[]>();
  const dirByBase = new Map<string, string[]>();
  const allDirs = new Set<string>();
  const index = (m: Map<string, string[]>, k: string, v: string): void => {
    const l = m.get(k);
    if (l) l.push(v);
    else m.set(k, [v]);
  };
  for (const f of files) {
    textOf.set(f.path, f.text);
    index(byPath, f.path.toLowerCase(), f.path);
    index(fileByBase, baseOf(f.path).toLowerCase(), f.path);
    for (let d = parentOf(f.path); d !== "" && !allDirs.has(d); d = parentOf(d)) {
      allDirs.add(d);
      index(dirByBase, baseOf(d).toLowerCase(), d);
    }
  }
  const suffixMatch = (m: Map<string, string[]>, rel: string): string[] => {
    const l = rel.toLowerCase();
    return (m.get(baseOf(l)) ?? []).filter((p) => {
      const pl = p.toLowerCase();
      return pl === l || pl.endsWith(`/${l}`);
    });
  };

  interface Parsed {
    readonly doc: Document.Parsed;
    readonly lc: LineCounter;
  }
  const parsed = new Map<string, Parsed | null>();
  /** Dosyayı bir kez ayrıştırır; YAML hatası ENGELLER (fail-closed). Okunamayan içerik → null. */
  const parse = (path: string): Parsed | null => {
    const hit = parsed.get(path);
    if (hit !== undefined) return hit;
    let out: Parsed | null = null;
    const text = textOf.get(path);
    if (typeof text === "string") {
      const lc = new LineCounter();
      try {
        const doc = parseDocument(text, { lineCounter: lc, uniqueKeys: false });
        if (doc.errors.length > 0) {
          const e = doc.errors[0];
          add("block", "yaml_error", `YAML hatası: ${(e?.message ?? "").split("\n")[0]?.slice(0, 100)}`, path, e?.linePos?.[0]?.line);
        } else {
          out = { doc, lc };
        }
      } catch {
        add("block", "yaml_error", "YAML ayrıştırılamadı", path);
      }
    }
    parsed.set(path, out);
    return out;
  };

  const textChecked = new Set<string>();
  /** Metin düzeyi işaretler: her YAML dosyasında ve include/rol ile yüklenen (uzantısı ne olursa olsun) her dosyada. */
  const checkText = (path: string): void => {
    if (textChecked.has(path)) return;
    textChecked.add(path);
    const text = textOf.get(path) ?? "";
    if (LOOKUP_PIPE.test(text)) add("warn", "lookup_pipe", "lookup('pipe') denetleyicide komut çalıştırır (çalıştırma araçlarında engel)", path);
    if (CONTROLLER_EXEC.test(text)) add("warn", "controller_execution", "görev denetleyicide yerelde çalışıyor (local_action/delegate_to localhost/connection: local)", path);
  };

  for (const f of files) {
    const dir = PLUGIN_DIRS.exec(f.path);
    if (dir && !seenDirs.has(dir[0])) {
      seenDirs.add(dir[0]);
      add("block", "local_plugin_dir", `depoda Ansible eklenti/modül dizini (${dir[2]}): ansible-playbook/ansible-lint bunları YÜKLER (kod çalıştırır)`, f.path);
    }
    if (/(^|\/)ansible\.cfg$/.test(f.path)) add("warn", "ansible_cfg_ignored", "depodaki ansible.cfg GÜVENİLMEZ: yok sayılır (ürünün kendi yapılandırması kullanılır)", f.path);
    if (/(^|\/)\.ansible-lint(\.ya?ml)?$/.test(f.path)) add("warn", "ansible_lint_config_ignored", "depodaki .ansible-lint yok sayılır (rulesdir kod yükleyebilir)", f.path);
    const roleMatch = /(^|\/)roles\/([^/]+)\//.exec(f.path);
    if (roleMatch) {
      roles.add(roleMatch[2] as string);
      roleDirs.add(f.path.slice(0, roleMatch.index + roleMatch[0].length - 1));
    }
    if (/(^|\/)requirements\.ya?ml$/.test(f.path)) requirements = true;
    if (/(^|\/)(inventory|inventories|hosts)(\/|\.|$)/.test(f.path) || /\.ini$/.test(f.path)) inventories.push(f.path);
    if (!/\.ya?ml$/.test(f.path)) continue;
    scanned++;
    checkText(f.path);
    const p = parse(f.path);
    const root = p?.doc.contents;
    if (p && isSeq(root)) {
      const isPlaybook = root.items.some((x) => {
        const r = deref(x, p.doc);
        return isMap(r) && r.items.some((pr) => isScalar(pr.key) && PLAYBOOK_KEYS.has(String(pr.key.value)));
      });
      if (isPlaybook) playbooks.push(f.path);
    }
  }
  const playbookSet: ReadonlySet<string> = new Set(playbooks);

  // ---- ziyaret: playbook'lar, rol dosyaları ve YÜKLEDİKLERİ her dosya ------------------------------------------------
  interface Ctx {
    readonly file: string;
    readonly doc: Document.Parsed;
    readonly lc: LineCounter;
    readonly depth: number;
  }
  interface Site {
    readonly file: string;
    readonly line?: number;
  }
  const visitedTaskFiles = new Set<string>();
  const visitedPlaybooks = new Set<string>();
  const visitedRoles = new Map<string, { tasks: boolean; handlers: boolean; readable: boolean }>();

  const lineOf = (n: unknown, ctx: Ctx): number => (isNode(n) && n.range ? ctx.lc.linePos(n.range[0]).line : 0);
  const toJs = (v: unknown, ctx: Ctx): unknown => {
    if (isNode(v)) {
      try {
        return (v as Node & { toJS(d: unknown, o: { maxAliasCount: number }): unknown }).toJS(ctx.doc, { maxAliasCount: 50 });
      } catch {
        return undefined;
      }
    }
    return v;
  };
  const dynamic = (site: Site, what: string): void => {
    forceDestroy = true;
    add("warn", "dynamic_include", `${what} şablonlu yol içeriyor`, site.file, site.line);
  };
  const unresolved = (site: Site, what: string, why: string): void => {
    forceDestroy = true;
    add("warn", "include_unresolved", `${what} çözülemedi (${why}): içerik sınıflanamaz → destroy muamelesi`, site.file, site.line);
  };

  /** Hedefi ağaç içinde (sonek eşleşmesiyle) çözer ve VAR OLAN her adayı `visit` ile tarar; çözülemezse bulgu + false. */
  const follow = (label: string, target: string, site: Site, depth: number, visit: (path: string, depth: number) => boolean, skip?: ReadonlySet<string>): boolean => {
    const fail = (why: string): boolean => {
      unresolved(site, label, why);
      return false;
    };
    if (depth > MAX_INCLUDE_DEPTH) return fail(`include zinciri ${MAX_INCLUDE_DEPTH} düzeyden derin`);
    const rel = treeSuffix(target);
    if (rel === undefined) return fail("mutlak, ağaç dışı veya geçersiz yol");
    const cands = suffixMatch(fileByBase, rel).filter((c) => !skip?.has(c));
    if (cands.length === 0) return fail("çalışma alanında yok");
    const unreadable = cands.filter((c) => !visit(c, depth));
    return unreadable.length === 0 || fail(`içeriği okunamayan aday: ${(unreadable[0] as string).slice(0, 80)}`);
  };

  /** Dosyayı görev listesi olarak tarar (dosya başına bir kez: döngüler sonlanır). İçerik okunamadıysa false. */
  const visitTaskFile = (path: string, depth: number): boolean => {
    if (typeof textOf.get(path) !== "string") return false;
    if (visitedTaskFiles.has(path)) return true;
    visitedTaskFiles.add(path);
    checkText(path);
    const p = parse(path);
    if (p) visitTaskList(p.doc.contents, { file: path, doc: p.doc, lc: p.lc, depth });
    return true;
  };

  /** Playbook: play görev listeleri, `roles:` ve içe aktarılan playbook'lar (uzantısı ne olursa olsun). */
  const visitPlaybook = (path: string, depth: number): boolean => {
    if (typeof textOf.get(path) !== "string") return false;
    if (visitedPlaybooks.has(path)) return true;
    visitedPlaybooks.add(path);
    checkText(path);
    const p = parse(path);
    if (!p || !isSeq(p.doc.contents)) return true;
    const ctx: Ctx = { file: path, doc: p.doc, lc: p.lc, depth };
    for (const x of p.doc.contents.items) {
      const play = deref(x, p.doc);
      if (!isMap(play)) continue;
      const site: Site = { file: path, line: lineOf(play, ctx) };
      for (const pair of play.items) {
        const key = isScalar(pair.key) ? String(pair.key.value) : "";
        if (PLAY_TASK_LISTS.includes(key)) {
          visitTaskList(pair.value, ctx);
        } else if (key === "roles") {
          visitRoleRefs(pair.value, ctx);
        } else if (PLAYBOOK_IMPORTS.has(normalizeModule(key))) {
          const target = toJs(pair.value, ctx);
          if (isTemplated(target)) dynamic(site, "import_playbook");
          else if (typeof target !== "string" || target === "") unresolved(site, "import_playbook", "hedef yok");
          else follow(`import_playbook '${target.slice(0, 80)}'`, target, site, depth + 1, visitPlaybook);
        }
      }
    }
    return true;
  };

  /** Rol dizininde `<alt>/<ad>` dosya adayları; ad alt dizinden kaçarsa undefined (Ansible de rol dışını reddeder). */
  const roleFiles = (dir: string, sub: string, name: string): string[] | undefined => {
    if (name.startsWith("/") || name.startsWith("~") || /[\0\\]/.test(name)) return undefined;
    const segs: string[] = [];
    for (const s of name.split("/")) {
      if (s === "" || s === ".") continue;
      if (s !== "..") segs.push(s);
      else if (segs.pop() === undefined) return undefined;
    }
    if (segs.length === 0) return undefined;
    const base = `${dir}/${sub}/${segs.join("/")}`.toLowerCase();
    return ROLE_FILE_EXTS.flatMap((ext) => byPath.get(base + ext) ?? []);
  };

  /** Rol: görev/handler dosyaları (`*_from` yoksa `main`) aynı ziyaretçiyle; `meta/main` bağımlılıkları özyinelemeli. */
  const visitRole = (dir: string, tasksFrom: string | undefined, handlersFrom: string | undefined, depth: number): { tasks: boolean; handlers: boolean; readable: boolean } => {
    const key = `${dir}\0${tasksFrom ?? ""}\0${handlersFrom ?? ""}`;
    const seen = visitedRoles.get(key);
    if (seen) return seen;
    const r = { tasks: false, handlers: false, readable: true };
    visitedRoles.set(key, r);
    for (const [sub, from] of [["tasks", tasksFrom], ["handlers", handlersFrom]] as const) {
      const cands = roleFiles(dir, sub, from ?? "main") ?? [];
      if (cands.length > 0) r[sub] = true;
      for (const c of cands) if (!visitTaskFile(c, depth)) r.readable = false;
    }
    for (const mf of roleFiles(dir, "meta", "main") ?? []) {
      if (typeof textOf.get(mf) !== "string") {
        r.readable = false;
        continue;
      }
      checkText(mf);
      const p = parse(mf);
      if (!p || !isMap(p.doc.contents)) continue;
      const ctx: Ctx = { file: mf, doc: p.doc, lc: p.lc, depth };
      for (const pair of p.doc.contents.items) if (isScalar(pair.key) && pair.key.value === "dependencies") visitRoleRefs(pair.value, ctx);
    }
    return r;
  };

  /** Rol adını ağaç içindeki dizin(ler)e çözer (sonek: `<playbook>/roles/ad`, `<playbook>/ad`, rol tabanı/ad, cwd/ad...). */
  const followRole = (label: string, name: string, tasksFrom: string | undefined, handlersFrom: string | undefined, site: Site, depth: number): boolean => {
    const fail = (why: string): boolean => {
      unresolved(site, label, why);
      return false;
    };
    if (depth > MAX_INCLUDE_DEPTH) return fail(`include zinciri ${MAX_INCLUDE_DEPTH} düzeyden derin`);
    const rel = treeSuffix(name);
    if (rel === undefined) return fail("mutlak, ağaç dışı veya geçersiz rol yolu");
    const found = suffixMatch(dirByBase, rel);
    if (found.length === 0) return fail("rol dizini çalışma alanında yok");
    let hasTasks = tasksFrom === undefined;
    let hasHandlers = handlersFrom === undefined;
    let readable = true;
    for (const d of found) {
      const r = visitRole(d, tasksFrom, handlersFrom, depth);
      hasTasks ||= r.tasks;
      hasHandlers ||= r.handlers;
      readable &&= r.readable;
    }
    if (!hasTasks) return fail(`rolde tasks/${(tasksFrom ?? "").slice(0, 60)} yok`);
    if (!hasHandlers) return fail(`rolde handlers/${(handlersFrom ?? "").slice(0, 60)} yok`);
    return readable || fail("rol dosyası okunamadı");
  };

  /** Play `roles:` ve rol `meta` `dependencies:` listeleri: dize ya da `{ role|name: ad, ... }`. */
  const visitRoleRefs = (list: unknown, ctx: Ctx): void => {
    const seq = deref(list, ctx.doc);
    if (!isSeq(seq)) return;
    for (const raw of seq.items) {
      const item = deref(raw, ctx.doc);
      const js = toJs(item, ctx);
      const site: Site = { file: ctx.file, line: lineOf(item, ctx) };
      const name = isObj(js) ? (js["role"] ?? js["name"]) : js;
      if (isTemplated(name)) dynamic(site, "rol");
      else if (typeof name !== "string" || name === "") unresolved(site, "rol", "rol adı yok");
      else followRole(`rol '${name.slice(0, 80)}'`, name, undefined, undefined, site, ctx.depth + 1);
    }
  };

  const visitTaskList = (seq: unknown, ctx: Ctx): void => {
    if (!isSeq(seq)) return;
    for (const raw of seq.items) {
      const item = deref(raw, ctx.doc);
      if (isMap(item)) visitTask(item, ctx);
    }
  };
  const visitTask = (m: YAMLMap, ctx: Ctx): void => {
    const keys = m.items.map((p) => (isScalar(p.key) ? String(p.key.value) : ""));
    for (const nested of ["block", "rescue", "always"]) {
      const idx = keys.indexOf(nested);
      if (idx >= 0) visitTaskList(m.items[idx]?.value, ctx);
    }
    const flags: string[] = [];
    let module: string;
    let args: unknown;
    const get = (k: string): unknown => {
      const i = keys.indexOf(k);
      return i >= 0 ? m.items[i]?.value : undefined;
    };
    const local = keys.includes("local_action");
    if (local || keys.includes("action")) {
      ({ module, args } = actionForm(toJs(get(local ? "local_action" : "action"), ctx)));
      if (local) flags.push("local_action");
    } else {
      const k = keys.find((x) => x !== "" && !TASK_KEYWORDS.has(x) && !x.startsWith("with_"));
      if (k === undefined) return; // görev değil (block vb.)
      module = k;
      args = toJs(get(k), ctx);
    }
    // `args:` anahtar sözcüğü modül argümanlarına eklenir (Ansible gibi)
    const kw = toJs(get("args"), ctx);
    if (isObj(kw) && (args === undefined || args === null || isObj(args))) args = { ...(isObj(args) ? args : {}), ...kw };
    const norm = normalizeModule(module);
    let cls = classOf(norm, args);
    if (local && cls !== "unclassified" && riskRank(cls) < riskRank("deploy")) cls = "deploy"; // denetleyicide yürütme en az deploy
    const chk = toJs(get("check_mode"), ctx);
    if (chk === false || chk === "no" || chk === "false") flags.push("check_mode_false");
    const del = toJs(get("delegate_to"), ctx);
    if (typeof del === "string" && /^(localhost|127\.0\.0\.1)$/.test(del)) flags.push("delegate_localhost");
    if (toJs(get("become"), ctx) === true || toJs(get("become"), ctx) === "yes") flags.push("become");
    if (["command", "shell", "raw", "script"].includes(norm)) flags.push("arbitrary_command");
    const line = lineOf(m, ctx);
    const site: Site = { file: ctx.file, line };
    let resolved: RiskClass = cls === "unclassified" ? "destroy" : cls;
    if (cls === "unclassified") {
      add("warn", "module_unclassified", `modül '${norm.slice(0, 60)}' kataloğda yok: destroy muamelesi görür`, ctx.file, line);
      flags.push("unclassified");
    }
    // include/rol: hedefin görevleri AYNI ziyaretçiyle sınıflanır; şablonlu/çözülemeyen hedef → destroy muamelesi.
    // Görev, hedefin görevlerinden ÖNCE listelenir (sınıfı izleme sonucuna göre aşağıda güncellenir).
    const shown = (local ? "local_action" : norm).slice(0, 60);
    const slot = tasks.push({ file: ctx.file, line, module: shown, class: resolved, flags }) - 1;
    const failClosed = (flag: string): void => {
      if (!flags.includes(flag)) flags.push(flag);
      resolved = "destroy";
    };
    if (TASK_INCLUDES.has(norm)) {
      const t = taskIncludeTargets(args);
      if (t.kind === "dynamic") {
        dynamic(site, norm);
        failClosed("dynamic_include");
      } else if (t.kind === "invalid") {
        unresolved(site, norm, t.why);
        failClosed("include_unresolved");
      } else {
        for (const target of t.value) if (!follow(`${norm} '${target.slice(0, 80)}'`, target, site, ctx.depth + 1, visitTaskFile, playbookSet)) failClosed("include_unresolved");
      }
    } else if (ROLE_INCLUDES.has(norm)) {
      const r = roleIncludeArgs(args);
      if (r.kind === "dynamic") {
        dynamic(site, norm);
        failClosed("dynamic_include");
      } else if (r.kind === "invalid") {
        unresolved(site, norm, r.why);
        failClosed("include_unresolved");
      } else if (!followRole(`${norm} '${r.value.name.slice(0, 80)}'`, r.value.name, r.value.tasksFrom, r.value.handlersFrom, site, ctx.depth + 1)) {
        failClosed("include_unresolved");
      }
    }
    tasks[slot] = { file: ctx.file, line, module: shown, class: resolved, flags };
  };

  for (const pb of playbooks) visitPlaybook(pb, 0);
  for (const f of files) if (/\.ya?ml$/.test(f.path) && ROLE_TASK_FILE.test(f.path)) visitTaskFile(f.path, 0);
  for (const d of roleDirs) visitRole(d, undefined, undefined, 0);

  const modules: Record<string, number> = {};
  let maxClass: RiskClass = forceDestroy ? "destroy" : "read";
  for (const t of tasks) {
    modules[t.module] = (modules[t.module] ?? 0) + 1;
    if (riskRank(t.class) > riskRank(maxClass)) maxClass = t.class;
  }
  const blocked = findings.some((x) => x.severity === "block");
  return {
    model: { files: scanned, playbooks: playbooks.sort(), roles: [...roles].sort(), inventories: inventories.sort(), taskCount: tasks.length, modules, maxClass, requirements },
    tasks,
    findings,
    blocked,
  };
}

// ---- envanter ---------------------------------------------------------------------------------

export interface InventoryGroup {
  readonly name: string;
  readonly hosts: number;
  readonly children: string[];
  readonly varNames: string[];
}
export interface InventorySummary {
  readonly groups: InventoryGroup[];
  readonly hosts: string[];
  readonly hostVarNames: string[];
  readonly dynamic: boolean;
}

/** Bağlantı/yetki değişkenleri: DEĞERLERİ hiçbir zaman çıkmaz (yalnız adlar listelenir ve işaretlenir). */
export const SECRET_VAR = /(pass(word|phrase)?|secret|token|private_key|ssh_pass|become_pass|vault)/i;

const maskName = (n: string): string => (SECRET_VAR.test(n) ? `${n.slice(0, 40)} [maskeli]` : n.slice(0, 60));
const nameOk = (s: string): boolean => /^[A-Za-z0-9._:-]{1,100}$/.test(s);

/** Statik envanteri (YAML veya INI) çözer. `plugin:` anahtarı / betik benzeri içerik → `dynamic: true` (çalıştırılmaz). */
export function parseInventory(path: string, text: string): InventorySummary {
  const groups = new Map<string, { hosts: Set<string>; children: Set<string>; vars: Set<string> }>();
  const hostVars = new Set<string>();
  const allHosts = new Set<string>();
  const g = (n: string) => {
    let x = groups.get(n);
    if (!x) {
      x = { hosts: new Set(), children: new Set(), vars: new Set() };
      groups.set(n, x);
    }
    return x;
  };
  let dynamic = false;
  if (/\.ya?ml$/.test(path)) {
    const doc = parseDocument(text, { uniqueKeys: false });
    const js = doc.errors.length ? null : (doc.toJS({ maxAliasCount: 50 }) as unknown);
    if (js && typeof js === "object" && !Array.isArray(js)) {
      const o = js as Record<string, unknown>;
      if ("plugin" in o) dynamic = true;
      const walk = (name: string, node: unknown): void => {
        if (!node || typeof node !== "object") return;
        const n = node as Record<string, unknown>;
        const grp = g(name);
        for (const [h, hv] of Object.entries((n["hosts"] as Record<string, unknown> | undefined) ?? {})) {
          if (!nameOk(h)) continue;
          grp.hosts.add(h);
          allHosts.add(h);
          if (hv && typeof hv === "object") for (const k of Object.keys(hv)) hostVars.add(maskName(k));
        }
        for (const k of Object.keys((n["vars"] as Record<string, unknown> | undefined) ?? {})) grp.vars.add(maskName(k));
        for (const [c, cv] of Object.entries((n["children"] as Record<string, unknown> | undefined) ?? {})) {
          if (!nameOk(c)) continue;
          grp.children.add(c);
          walk(c, cv);
        }
      };
      if (!dynamic) for (const [name, node] of Object.entries(o)) if (nameOk(name)) walk(name, node);
    }
  } else {
    if (text.startsWith("#!")) dynamic = true;
    let cur = "ungrouped";
    let mode: "hosts" | "vars" | "children" = "hosts";
    for (const raw of text.split("\n").slice(0, 5_000)) {
      const line = raw.replace(/\s+#.*$/, "").trim();
      if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
      const hdr = /^\[([^\]:]+)(?::(vars|children))?\]$/.exec(line);
      if (hdr) {
        cur = hdr[1] as string;
        mode = (hdr[2] as "vars" | "children" | undefined) ?? "hosts";
        if (nameOk(cur)) g(cur);
        continue;
      }
      if (!nameOk(cur)) continue;
      if (mode === "vars") {
        const k = line.split("=")[0]?.trim();
        if (k) g(cur).vars.add(maskName(k));
      } else if (mode === "children") {
        if (nameOk(line)) g(cur).children.add(line);
      } else {
        const [h, ...rest] = line.split(/\s+/);
        if (h && nameOk(h)) {
          g(cur).hosts.add(h);
          allHosts.add(h);
          for (const kv of rest) {
            const k = kv.split("=")[0];
            if (k) hostVars.add(maskName(k));
          }
        }
      }
    }
  }
  return {
    groups: [...groups].map(([name, x]) => ({ name, hosts: x.hosts.size, children: [...x.children].sort().slice(0, 30), varNames: [...x.vars].sort().slice(0, 30) })).sort((a, b) => a.name.localeCompare(b.name)),
    hosts: [...allHosts].sort().slice(0, 100),
    hostVarNames: [...hostVars].sort().slice(0, 30),
    dynamic,
  };
}
