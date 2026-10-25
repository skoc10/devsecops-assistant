import { LineCounter, isAlias, isMap, isNode, isScalar, isSeq, parseDocument } from "yaml";
import type { Node, YAMLMap } from "yaml";
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
  set_stats: "read", validate_argument_spec: "read", wait_for_connection: "read", include_tasks: "read", import_tasks: "read", include_role: "read",
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
const PLAY_TASK_LISTS = ["pre_tasks", "tasks", "post_tasks", "handlers"] as const;
const PLUGIN_DIRS = /(^|\/)(library|action_plugins|callback_plugins|connection_plugins|filter_plugins|lookup_plugins|inventory_plugins|module_utils|vars_plugins|strategy_plugins|become_plugins|cache_plugins|test_plugins|doc_fragments|ansible_collections)\//;
const LOOKUP_PIPE = /\b(?:lookup|query|q)\s*\(\s*['"](?:ansible\.builtin\.)?pipe['"]/i;

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

function normalizeModule(name: string): string {
  return BUILTIN_NS.test(name) ? name.replace(BUILTIN_NS, "") : name;
}

function classOf(module: string, args: unknown): RiskClass | "unclassified" {
  const base = MODULE_CLASS[module];
  if (base === undefined) return "unclassified";
  let cls: RiskClass = base;
  const state = args !== null && typeof args === "object" && !Array.isArray(args) ? (args as Record<string, unknown>)["state"] : undefined;
  if (state === "absent" && (module === "file" || module === "user" || module === "group" || module === "package" || module === "apt" || module === "yum" || module === "dnf" || module === "pip")) cls = "destroy";
  return cls;
}

export function scanAnsible(files: readonly { path: string; text: string }[]): AnsibleScan {
  const findings: PrescanFinding[] = [];
  const add = (severity: PrescanFinding["severity"], code: string, message: string, file: string, line?: number): void => {
    findings.push({ severity, code, message, file, ...(line !== undefined ? { line } : {}) });
  };
  const tasks: AnsibleTask[] = [];
  const playbooks: string[] = [];
  const roles = new Set<string>();
  const inventories: string[] = [];
  let requirements = false;
  let scanned = 0;
  const seenDirs = new Set<string>();

  for (const f of files) {
    const dir = PLUGIN_DIRS.exec(f.path);
    if (dir && !seenDirs.has(dir[0])) {
      seenDirs.add(dir[0]);
      add("block", "local_plugin_dir", `depoda Ansible eklenti/modül dizini (${dir[2]}): ansible-playbook/ansible-lint bunları YÜKLER (kod çalıştırır)`, f.path);
    }
    if (/(^|\/)ansible\.cfg$/.test(f.path)) add("warn", "ansible_cfg_ignored", "depodaki ansible.cfg GÜVENİLMEZ: yok sayılır (ürünün kendi yapılandırması kullanılır)", f.path);
    if (/(^|\/)\.ansible-lint(\.ya?ml)?$/.test(f.path)) add("warn", "ansible_lint_config_ignored", "depodaki .ansible-lint yok sayılır (rulesdir kod yükleyebilir)", f.path);
    const roleMatch = /(^|\/)roles\/([^/]+)\//.exec(f.path);
    if (roleMatch) roles.add(roleMatch[2] as string);
    if (/(^|\/)requirements\.ya?ml$/.test(f.path)) requirements = true;
    if (/(^|\/)(inventory|inventories|hosts)(\/|\.|$)/.test(f.path) || /\.ini$/.test(f.path)) inventories.push(f.path);
    if (!/\.ya?ml$/.test(f.path)) continue;
    scanned++;

    if (LOOKUP_PIPE.test(f.text)) add("warn", "lookup_pipe", "lookup('pipe') denetleyicide komut çalıştırır (çalıştırma araçlarında engel)", f.path);
    if (/\blocal_action\b|delegate_to:\s*['"]?(localhost|127\.0\.0\.1)\b|connection:\s*['"]?local\b/.test(f.text)) add("warn", "controller_execution", "görev denetleyicide yerelde çalışıyor (local_action/delegate_to localhost/connection: local)", f.path);

    const lc = new LineCounter();
    let doc;
    try {
      doc = parseDocument(f.text, { lineCounter: lc, uniqueKeys: false });
    } catch {
      add("block", "yaml_error", "YAML ayrıştırılamadı", f.path);
      continue;
    }
    if (doc.errors.length > 0) {
      const e = doc.errors[0];
      add("block", "yaml_error", `YAML hatası: ${(e?.message ?? "").split("\n")[0]?.slice(0, 100)}`, f.path, e?.linePos?.[0]?.line);
      continue;
    }
    const lineOf = (n: Node | null | undefined): number => (n?.range ? lc.linePos(n.range[0]).line : 0);
    const root = doc.contents;
    const isRoleTaskFile = /(^|\/)roles\/[^/]+\/(tasks|handlers)\//.test(f.path);

    const visitTaskList = (seq: unknown): void => {
      if (!isSeq(seq)) return;
      for (const raw of seq.items) {
        const item = isAlias(raw) ? raw.resolve(doc) : raw;
        if (isMap(item)) visitTask(item);
      }
    };
    const visitTask = (m: YAMLMap): void => {
      const keys = m.items.map((p) => (isScalar(p.key) ? String(p.key.value) : ""));
      for (const nested of ["block", "rescue", "always"]) {
        const idx = keys.indexOf(nested);
        if (idx >= 0) visitTaskList(m.items[idx]?.value);
      }
      const flags: string[] = [];
      let module: string | undefined;
      let args: unknown;
      const get = (k: string): unknown => {
        const i = keys.indexOf(k);
        return i >= 0 ? m.items[i]?.value : undefined;
      };
      const toJs = (v: unknown): unknown => {
        if (isNode(v)) {
          try {
            return (v as Node & { toJS(d: unknown, o: { maxAliasCount: number }): unknown }).toJS(doc, { maxAliasCount: 50 });
          } catch {
            return undefined;
          }
        }
        return v;
      };
      if (keys.includes("local_action")) {
        module = "local_action";
        flags.push("local_action");
      } else if (keys.includes("action")) {
        const a = toJs(get("action"));
        module = typeof a === "string" ? (a.trim().split(/\s+/)[0] ?? "action") : a && typeof a === "object" ? String((a as Record<string, unknown>)["module"] ?? "action") : "action";
        args = typeof a === "object" ? a : undefined;
      } else {
        const k = keys.find((x) => x !== "" && !TASK_KEYWORDS.has(x) && !x.startsWith("with_"));
        if (k === undefined) return; // görev değil (block vb.)
        module = k;
        args = toJs(get(k));
      }
      const norm = normalizeModule(module);
      let cls = classOf(norm, args);
      if (module === "local_action") cls = "deploy";
      const chk = toJs(get("check_mode"));
      if (chk === false || chk === "no" || chk === "false") flags.push("check_mode_false");
      const del = toJs(get("delegate_to"));
      if (typeof del === "string" && /^(localhost|127\.0\.0\.1)$/.test(del)) flags.push("delegate_localhost");
      if (toJs(get("become")) === true || toJs(get("become")) === "yes") flags.push("become");
      if (["command", "shell", "raw", "script"].includes(norm)) flags.push("arbitrary_command");
      const line = lineOf(m);
      const resolved: RiskClass = cls === "unclassified" ? "destroy" : cls;
      if (cls === "unclassified") {
        add("warn", "module_unclassified", `modül '${norm.slice(0, 60)}' kataloğda yok: destroy muamelesi görür`, f.path, line);
        flags.push("unclassified");
      }
      if (/\{\{/.test(String(toJs(get(module)) ?? "")) && ["include_tasks", "import_tasks", "include_role", "import_role"].includes(norm)) {
        add("warn", "dynamic_include", `${norm} şablonlu yol içeriyor`, f.path, line);
        flags.push("dynamic_include");
      }
      tasks.push({ file: f.path, line, module: norm.slice(0, 60), class: resolved, flags });
    };

    if (isSeq(root)) {
      const maps: YAMLMap[] = [];
      for (const x of root.items) {
        const r = isAlias(x) ? x.resolve(doc) : x;
        if (isMap(r)) maps.push(r as unknown as YAMLMap);
      }
      const isPlaybook = maps.some((m) => m.items.some((p) => isScalar(p.key) && (p.key.value === "hosts" || p.key.value === "import_playbook")));
      if (isPlaybook) {
        playbooks.push(f.path);
        for (const play of maps) {
          for (const list of PLAY_TASK_LISTS) {
            const it = play.items.find((p) => isScalar(p.key) && p.key.value === list);
            if (it) visitTaskList(it.value);
          }
        }
      } else if (isRoleTaskFile) {
        visitTaskList(root);
      }
    }
  }

  const modules: Record<string, number> = {};
  let maxClass: RiskClass = "read";
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
