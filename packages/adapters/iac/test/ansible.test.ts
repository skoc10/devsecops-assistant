import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { OpsError } from "@ops/contracts";
import type { AdapterCall } from "@ops/contracts";
import type { Sandbox } from "@ops/sandbox";
import type { WorkspaceManager } from "@ops/workspace";
import { IacAdapter } from "../src/adapter.ts";
import { parseInventory, scanAnsible } from "../src/ansible.ts";

const pb = (tasks: string, extra = ""): { path: string; text: string }[] => [
  { path: "site.yml", text: `- hosts: web\n  ${extra}\n  tasks:\n${tasks}` },
];
const scan = (tasks: string, extra = "") => scanAnsible(pb(tasks, extra));
const codes = (tasks: string, extra = ""): string[] => scan(tasks, extra).findings.map((f) => f.code);
/** Çok dosyalı tarama: `null` içerik = okunamayan (ikili) dosya. */
const scanFiles = (files: Record<string, string | null>) => scanAnsible(Object.entries(files).map(([path, text]) => ({ path, text })));
const play = (task: string): string => `- hosts: all\n  tasks:\n    - ${task}\n`;
/** Bulgu PoC'si: include_tasks ile yüklenen, hiçbir playbook/rol kalıbına uymayan bağımsız görev dosyası. */
const EXTRA = "- shell: touch /tmp/pwned\n  check_mode: false\n- file: path=/etc/important state=absent\n";

describe("scanAnsible: modül sınıf kataloğu (S-18)", () => {
  it("okuma / mutasyon / keyfî komut / yıkıcı sınıfları", () => {
    const r = scan(
      [
        "    - ansible.builtin.stat: { path: /etc/hosts }",
        "    - ansible.builtin.copy: { src: a, dest: /tmp/a }",
        "    - ansible.builtin.shell: echo hi",
        "    - ansible.builtin.reboot:",
      ].join("\n"),
    );
    expect(r.tasks.map((t) => [t.module, t.class])).toEqual([
      ["stat", "read"],
      ["copy", "mutate"],
      ["shell", "deploy"],
      ["reboot", "destroy"],
    ]);
    expect(r.model.maxClass).toBe("destroy");
    expect(r.model.taskCount).toBe(4);
    expect(r.model.playbooks).toEqual(["site.yml"]);
    expect(r.tasks[2]?.flags).toContain("arbitrary_command");
  });

  it("state: absent → destroy (file/user/package)", () => {
    const r = scan(["    - file: { path: /tmp/x, state: absent }", "    - user: { name: bob, state: absent }", "    - package: { name: vim, state: absent }", "    - package: { name: vim, state: present }"].join("\n"));
    expect(r.tasks.map((t) => t.class)).toEqual(["destroy", "destroy", "destroy", "mutate"]);
  });

  it("sınıflanamayan modül = destroy muamelesi + uyarı", () => {
    const r = scan("    - community.general.some_unknown_module: { a: 1 }");
    expect(r.tasks[0]).toMatchObject({ class: "destroy", flags: ["unclassified"] });
    expect(r.findings.map((f) => f.code)).toContain("module_unclassified");
    expect(r.model.maxClass).toBe("destroy");
  });

  it("block/rescue/always içindeki görevler ve handlers taranır; görev anahtar sözcükleri modül sanılmaz", () => {
    const r = scan(
      [
        "    - name: grup",
        "      when: x",
        "      block:",
        "        - shell: a",
        "      rescue:",
        "        - command: b",
        "      always:",
        "        - debug: { msg: hi }",
      ].join("\n"),
      "handlers:\n    - name: h\n      service: { name: x, state: restarted }",
    );
    expect(r.tasks.map((t) => t.module).sort()).toEqual(["command", "debug", "service", "shell"]);
  });

  it("YAML takma adları (anchor/alias) çözülür", () => {
    const r = scan(["    - &t", "      shell: echo", "    - *t"].join("\n"));
    expect(r.tasks.map((t) => t.module)).toEqual(["shell", "shell"]);
  });
});

describe("scanAnsible: ön-tarama işaretleri", () => {
  it("check_mode: false, local_action, delegate_to localhost, become, lookup('pipe')", () => {
    const r = scan(
      [
        "    - stat: { path: /x }",
        "      check_mode: false",
        "      become: true",
        "    - local_action: { module: command, cmd: id }",
        "    - debug: { msg: \"{{ lookup('pipe', 'id') }}\" }",
        "      delegate_to: localhost",
      ].join("\n"),
    );
    expect(r.tasks[0]?.flags).toEqual(expect.arrayContaining(["check_mode_false", "become"]));
    expect(r.tasks[1]).toMatchObject({ module: "local_action", class: "deploy" });
    expect(r.tasks[2]?.flags).toContain("delegate_localhost");
    const c = r.findings.map((f) => f.code);
    expect(c).toEqual(expect.arrayContaining(["lookup_pipe", "controller_execution"]));
    expect(r.blocked).toBe(false); // uyarı, engel değil: çalıştırma araçlarında sınıf/onay belirler
  });

  it("şablonlu include_tasks/import_role yolu işaretlenir", () => {
    expect(codes("    - include_tasks: \"{{ item }}.yml\"")).toContain("dynamic_include");
  });

  it("yerel eklenti/modül dizinleri ENGELLER (ansible bunları yükler)", () => {
    for (const p of ["library/mymod.py", "roles/r/library/x.py", "action_plugins/a.py", "filter_plugins/f.py", "lookup_plugins/l.py", "callback_plugins/c.py", "plugins/../module_utils/u.py", "ansible_collections/x/y/plugins/m.py"]) {
      const r = scanAnsible([{ path: p, text: "" }]);
      expect(r.blocked, p).toBe(true);
      expect(r.findings[0]).toMatchObject({ severity: "block", code: "local_plugin_dir" });
    }
    expect(scanAnsible([{ path: "roles/r/tasks/main.yml", text: "- debug: { msg: hi }\n" }]).blocked).toBe(false);
  });

  it("repodaki ansible.cfg ve .ansible-lint güvenilmez (uyarı: yok sayılır)", () => {
    const r = scanAnsible([
      { path: "ansible.cfg", text: "" },
      { path: ".ansible-lint", text: "" },
      { path: "sub/ansible.cfg", text: "" },
    ]);
    expect(r.findings.map((f) => f.code).sort()).toEqual(["ansible_cfg_ignored", "ansible_cfg_ignored", "ansible_lint_config_ignored"]);
    expect(r.blocked).toBe(false);
  });

  it("ayrıştırılamayan YAML ENGELLER (fail-closed)", () => {
    const r = scanAnsible([{ path: "site.yml", text: "- hosts: web\n  tasks: [\n" }]);
    expect(r.blocked).toBe(true);
    expect(r.findings[0]).toMatchObject({ severity: "block", code: "yaml_error", file: "site.yml" });
  });

  it("rol görev dosyaları ve roller listelenir; playbook olmayan YAML görev sayılmaz", () => {
    const r = scanAnsible([
      { path: "roles/web/tasks/main.yml", text: "- name: a\n  apt: { name: nginx }\n" },
      { path: "roles/web/defaults/main.yml", text: "port: 80\n" },
      { path: "vars.yml", text: "- just\n- a\n- list\n" },
      { path: "requirements.yml", text: "roles: []\n" },
    ]);
    expect(r.model.roles).toEqual(["web"]);
    expect(r.model.requirements).toBe(true);
    expect(r.tasks.map((t) => [t.file, t.module, t.class])).toEqual([["roles/web/tasks/main.yml", "apt", "mutate"]]);
  });

  it("özyinelemeli alias (billion laughs) çökertmez", () => {
    const bomb = ["a: &a [x, x, x, x, x, x, x, x, x]", ...Array.from({ length: 9 }, (_, i) => `${String.fromCharCode(98 + i)}: &${String.fromCharCode(98 + i)} [${Array(9).fill(`*${String.fromCharCode(97 + i)}`).join(",")}]`)].join("\n");
    expect(() => scanAnsible([{ path: "site.yml", text: `- hosts: all\n  vars: {}\n  tasks:\n    - debug: { msg: x }\n` }, { path: "bomb.yml", text: bomb }])).not.toThrow();
  });
});

describe("scanAnsible: include/import ve rollerle yüklenen dosyalar aynı ziyaretçiyle sınıflanır", () => {
  it("PoC: include_tasks ile yüklenen bağımsız görev dosyası (shell + check_mode: false + state=absent) görünür", () => {
    const r = scanFiles({ "site.yml": play("include_tasks: extra.yml"), "extra.yml": EXTRA });
    expect(r.tasks.map((t) => [t.file, t.module, t.class])).toEqual([
      ["site.yml", "include_tasks", "read"],
      ["extra.yml", "shell", "deploy"],
      ["extra.yml", "file", "destroy"], // serbest biçimli k=v `state=absent` de yakalanır
    ]);
    expect(r.tasks[1]?.flags).toEqual(expect.arrayContaining(["check_mode_false", "arbitrary_command"]));
    expect(r.model.maxClass).toBe("destroy");
    expect(r.findings.map((f) => f.code)).not.toContain("include_unresolved");
  });

  it("tüm yazım biçimleri: FQCN, import_tasks, eski include, file=, sözlük, args:, action:, ./ öneki, harf farkı", () => {
    const forms = [
      "ansible.builtin.include_tasks: extra.yml",
      "ansible.builtin.import_tasks: extra.yml",
      "ansible.legacy.include_tasks: extra.yml",
      "include: extra.yml",
      "include_tasks: file=extra.yml",
      "include_tasks: { file: ./extra.yml, apply: { tags: [x] } }",
      "include_tasks:\n      args:\n        file: extra.yml",
      "action: include_tasks extra.yml",
      "action: { module: ansible.builtin.import_tasks, file: extra.yml }",
      "include_tasks: EXTRA.yml", // macOS dosya sistemi harfe duyarsız: aday sayılır
    ];
    for (const form of forms) {
      const r = scanFiles({ "site.yml": play(form), "extra.yml": EXTRA });
      expect(r.tasks.filter((t) => t.file === "extra.yml").map((t) => t.module), form).toEqual(["shell", "file"]);
      expect(r.findings.map((f) => f.code), form).not.toContain("include_unresolved");
    }
  });

  it("iç içe include: alt dizindeki playbook, '../' hedefi, üst dosyaya göreli hedef, JSON görev dosyası (metin işaretleri dahil)", () => {
    const r = scanFiles({
      "playbooks/site.yml": "- hosts: all\n  tasks:\n    - import_tasks: ../tasks/a.yml\n",
      "tasks/a.yml": "- include_tasks: b.yml\n",
      "tasks/b.yml": "- include_tasks: c.json\n",
      "tasks/c.json": '[{"shell": "id", "check_mode": false}, {"debug": {"msg": "{{ lookup(\'pipe\', \'id\') }}"}}]',
    });
    expect(r.tasks.map((t) => [t.file, t.module])).toEqual([
      ["playbooks/site.yml", "import_tasks"],
      ["tasks/a.yml", "include_tasks"],
      ["tasks/b.yml", "include_tasks"],
      ["tasks/c.json", "shell"],
      ["tasks/c.json", "debug"],
    ]);
    expect(r.tasks[3]?.flags).toContain("check_mode_false");
    expect(r.findings).toContainEqual(expect.objectContaining({ code: "lookup_pipe", file: "tasks/c.json" }));
  });

  it("aynı sonekli her görev dosyası taranır (Ansible arama yollarının üst kümesi); playbook dosyası görev hedefi sayılmaz", () => {
    const r = scanFiles({
      "site.yml": play("include_tasks: setup.yml"),
      "other/setup.yml": "- hosts: db\n  tasks: []\n",
      "lib/setup.yml": "- command: id\n",
    });
    expect(r.tasks.map((t) => [t.file, t.module])).toEqual([["site.yml", "include_tasks"], ["lib/setup.yml", "command"]]);
    expect(r.model.playbooks).toEqual(["other/setup.yml", "site.yml"]);
  });

  it("roller: roles/ dışındaki rol dizini (play roles:, include_role, import_role + tasks_from/handlers_from), JSON main, meta bağımlılığı", () => {
    const evil = "- shell: touch /tmp/pwned\n  check_mode: false\n";
    const cases: Record<string, string>[] = [
      { "site.yml": "- hosts: all\n  roles: [evil]\n", "evil/tasks/main.yml": evil },
      { "site.yml": "- hosts: all\n  roles:\n    - { role: evil, tags: x }\n", "evil/tasks/main.yml": evil },
      { "site.yml": play("include_role: { name: evil }"), "evil/tasks/main.yml": evil },
      { "site.yml": play("ansible.builtin.import_role:\n        name: evil\n        tasks_from: setup"), "evil/tasks/setup.yml": evil },
      { "site.yml": play("include_role: name=evil tasks_from=setup.yml"), "evil/tasks/setup.yml": evil },
      { "site.yml": play("include_role: { name: evil, handlers_from: h }"), "evil/handlers/h.yml": evil },
      { "site.yml": "- hosts: all\n  roles: [web]\n", "roles/web/tasks/main.json": '[{"shell": "id", "check_mode": false}]' },
      { "site.yml": "- hosts: all\n  roles: [web]\n", "roles/web/tasks/main.yml": "- debug: { msg: x }\n", "roles/web/meta/main.yml": "dependencies:\n  - role: evil\n", "evil/tasks/main.yml": evil },
    ];
    for (const files of cases) {
      const r = scanFiles(files);
      const label = JSON.stringify(files);
      expect(r.tasks.some((t) => t.module === "shell" && t.flags.includes("check_mode_false")), label).toBe(true);
      expect(r.findings.map((f) => f.code), label).not.toContain("include_unresolved");
    }
  });

  it("import_playbook: uzantısı ne olursa olsun içe aktarılan playbook'un görevleri taranır; FQCN içe aktarma playbook sayılır", () => {
    const r = scanFiles({ "site.yml": "- ansible.builtin.import_playbook: other.json\n", "other.json": '[{"hosts": "all", "tasks": [{"shell": "id", "check_mode": false}]}]' });
    expect(r.model.playbooks).toEqual(["site.yml"]);
    expect(r.tasks.map((t) => [t.file, t.module, t.flags.includes("check_mode_false")])).toEqual([["other.json", "shell", true]]);
  });

  it("döngüler sonlanır: kendini ve birbirini yükleyen dosyalar, döngüsel rol bağımlılığı; her görev bir kez sayılır", () => {
    const r = scanFiles({
      "site.yml": "- hosts: all\n  tasks:\n    - include_tasks: a.yml\n  roles: [r1]\n",
      "a.yml": "- include_tasks: b.yml\n- include_tasks: a.yml\n- debug: { msg: a }\n",
      "b.yml": "- import_tasks: a.yml\n",
      "roles/r1/meta/main.yml": "dependencies: [r2]\n",
      "roles/r2/meta/main.yml": "dependencies:\n  - role: r1\n",
    });
    expect(r.tasks.filter((t) => t.module === "debug")).toHaveLength(1);
    expect(r.findings.map((f) => f.code)).not.toContain("include_unresolved");
    expect(r.model.maxClass).toBe("read");
  });

  it("derinlik sınırı: çok uzun include zinciri fail-closed", () => {
    const files: Record<string, string> = { "site.yml": play("include_tasks: t0.yml") };
    for (let i = 0; i < 40; i++) files[`t${i}.yml`] = `- include_tasks: t${i + 1}.yml\n`;
    files["t40.yml"] = "- debug: { msg: son }\n";
    const r = scanFiles(files);
    expect(r.findings.find((f) => f.code === "include_unresolved")?.message).toMatch(/derin/);
    expect(r.model.maxClass).toBe("destroy");
  });
});

describe("scanAnsible: çözülemeyen veya şablonlu include/rol hedefi fail-closed", () => {
  it("eksik dosya, mutlak/ev/ağaç dışı yol, okunamayan içerik, eksik rol/tasks_from, rolden kaçan tasks_from, hedefsiz/çözülemeyen argüman", () => {
    const cases: [string, Record<string, string | null>][] = [
      ["eksik dosya", { "site.yml": play("include_tasks: missing.yml") }],
      ["mutlak yol", { "site.yml": play("include_tasks: /etc/ansible/x.yml") }],
      ["ev dizini", { "site.yml": play("import_tasks: ~/x.yml") }],
      ["ağaç dışı", { "site.yml": play("include_tasks: ../../outside.yml") }],
      ["okunamayan içerik", { "site.yml": play("include_tasks: blob.yml"), "blob.yml": null }],
      ["rol dizini yok", { "site.yml": play("include_role: { name: nope }") }],
      ["tasks_from yok", { "site.yml": play("include_role: { name: web, tasks_from: nope }"), "roles/web/tasks/main.yml": "- debug: {}\n" }],
      ["rolden kaçan tasks_from", { "site.yml": play("import_role: { name: web, tasks_from: ../../../x }"), "roles/web/tasks/main.yml": "- debug: {}\n", "x.yml": "- debug: {}\n" }],
      ["hedefsiz include", { "site.yml": play("include_tasks: { apply: { tags: [x] } }") }],
      ["çözülemeyen serbest biçim", { "site.yml": play("include_tasks: extra.yml tags=x"), "extra.yml": "- debug: {}\n" }],
      ["play rolü yok (vendor edilmemiş Galaxy rolü)", { "site.yml": "- hosts: all\n  roles: [geerlingguy.docker]\n" }],
      ["import_playbook hedefi yok", { "site.yml": "- import_playbook: other.yml\n" }],
    ];
    for (const [label, files] of cases) {
      const r = scanFiles(files);
      expect(r.findings.map((f) => f.code), label).toContain("include_unresolved");
      expect(r.model.maxClass, label).toBe("destroy");
      expect(r.blocked, label).toBe(false); // uyarı: lint yine çalışır; ansible.check ÇALIŞMAZ
    }
    expect(scanFiles({ "site.yml": play("include_tasks: missing.yml") }).tasks[0]).toMatchObject({ module: "include_tasks", class: "destroy", flags: ["include_unresolved"] });
  });

  it("şablonlu hedef: sözlük biçimi, action:, rol adı, tasks_from, play rolü, import_playbook → dynamic_include + destroy", () => {
    for (const task of ['include_tasks: { file: "{{ x }}.yml" }', "action: include_tasks {{ x }}.yml", 'import_role: { name: "{{ r }}" }', 'include_role: { name: web, tasks_from: "{% if a %}x{% endif %}" }']) {
      const r = scanFiles({ "site.yml": play(task), "roles/web/tasks/main.yml": "- debug: {}\n" });
      expect(r.findings.map((f) => f.code), task).toContain("dynamic_include");
      expect(r.tasks[0], task).toMatchObject({ class: "destroy", flags: ["dynamic_include"] });
    }
    expect(scanFiles({ "site.yml": '- hosts: all\n  roles: ["{{ r }}"]\n' }).findings.map((f) => f.code)).toContain("dynamic_include");
    expect(scanFiles({ "site.yml": '- import_playbook: "{{ pb }}.yml"\n' }).model.maxClass).toBe("destroy");
  });

  it("rol dosyası yüklenmeyen dizinde tasks/main olmaması sorun değildir (yalnız handlers/vars içeren rol)", () => {
    const r = scanFiles({ "site.yml": "- hosts: all\n  roles: [web]\n", "roles/web/handlers/main.yml": "- name: h\n  service: { name: x, state: restarted }\n" });
    expect(r.findings).toEqual([]);
    expect(r.tasks.map((t) => t.module)).toEqual(["service"]);
  });
});

describe("scanAnsible: check_mode kapsamı ve ayrıştırıcı farkları (Ansible/PyYAML ne görürse o)", () => {
  it("check_mode değeri: açıkça doğru olmayan her yazım (off, NO, n, 0, f, şablon, null) güvensiz; doğru yazımlar zararsız", () => {
    for (const v of ["false", "no", "NO", "off", "Off", "n", "N", "0", "f", "False", "'{{ ansible_check_mode and false }}'", "~", "''"]) {
      expect(scan(`    - stat: { path: /x }\n      check_mode: ${v}`).tasks[0]?.flags, v).toContain("check_mode_false");
    }
    for (const v of ["true", "yes", "on", "1", "True", "'y'", "' YES '"]) {
      expect(scan(`    - stat: { path: /x }\n      check_mode: ${v}`).tasks[0]?.flags, v).not.toContain("check_mode_false");
    }
  });

  it("play, blok (iç içe dahil), rol girdisi ve meta bağımlılığı düzeyinde check_mode kapatma bulgu üretir; include apply görevi işaretler", () => {
    const cases: [string, Record<string, string>][] = [
      ["play", { "site.yml": "- hosts: all\n  check_mode: false\n  tasks:\n    - shell: id\n" }],
      ["blok", { "site.yml": play("block:\n        - shell: id\n      check_mode: no") }],
      ["iç içe blok", { "site.yml": play("block:\n        - block:\n            - shell: id\n          check_mode: off") }],
      ["play rolü", { "site.yml": "- hosts: all\n  roles:\n    - { role: web, check_mode: false }\n", "roles/web/tasks/main.yml": "- shell: id\n" }],
      ["meta bağımlılığı", { "roles/web/meta/main.yml": "dependencies:\n  - { role: db, check_mode: false }\n", "roles/db/tasks/main.yml": "- shell: id\n" }],
    ];
    for (const [label, files] of cases) {
      expect(scanFiles(files).findings, label).toContainEqual(expect.objectContaining({ code: "check_mode_false", severity: "warn" }));
    }
    for (const task of ["include_tasks: { file: x.yml, apply: { check_mode: false } }", "include_role: { name: web, apply: { check_mode: no } }", 'include_tasks: { file: x.yml, apply: "{{ a }}" }']) {
      const r = scanFiles({ "site.yml": play(task), "x.yml": "- debug: {}\n", "roles/web/tasks/main.yml": "- debug: {}\n" });
      expect(r.tasks[0]?.flags, task).toContain("check_mode_false");
    }
    expect(scanFiles({ "site.yml": play("include_tasks: { file: x.yml, apply: { tags: [a] } }"), "x.yml": "- debug: {}\n" }).tasks[0]?.flags).toEqual([]);
  });

  it("yinelenen anahtar (PyYAML: son kazanır), birleştirme anahtarı (<<) ve takma ad anahtarı check_mode'u gizleyemez", () => {
    expect(scan("    - shell: id\n      check_mode: true\n      check_mode: false").tasks[0]?.flags).toContain("check_mode_false");
    const merge = scanFiles({ "site.yml": "- hosts: all\n  vars:\n    base: &base { check_mode: false, become: true }\n  tasks:\n    - shell: id\n      <<: *base\n" });
    expect(merge.tasks[0]?.flags).toEqual(expect.arrayContaining(["check_mode_false", "become"]));
    const mergedModule = scanFiles({ "site.yml": "- hosts: all\n  vars:\n    t: &t { shell: id, check_mode: false }\n  tasks:\n    - name: birleştirilmiş görev\n      <<: *t\n" });
    expect(mergedModule.tasks[0]).toMatchObject({ module: "shell", class: "deploy" });
    expect(mergedModule.tasks[0]?.flags).toContain("check_mode_false");
    expect(mergedModule.findings.map((f) => f.code)).not.toContain("module_unclassified");
    const aliasKey = scanFiles({ "site.yml": "- hosts: all\n  vars:\n    k: &k check_mode\n  tasks:\n    - shell: id\n      *k : false\n" });
    expect(aliasKey.tasks[0]?.flags).toContain("check_mode_false");
    const dupTasks = scanFiles({ "site.yml": "- hosts: all\n  tasks:\n    - debug: {}\n  tasks:\n    - shell: id\n      check_mode: false\n" });
    expect(dupTasks.tasks.map((t) => [t.module, t.flags.includes("check_mode_false")])).toEqual([["debug", false], ["shell", true]]);
  });

  it("takma adlı görev listesi (tasks: *x, block: *x) taranır", () => {
    const r = scanFiles({ "site.yml": "- hosts: all\n  vars:\n    evil: &evil\n      - shell: touch /tmp/pwned\n        check_mode: false\n  tasks: *evil\n  post_tasks:\n    - block: *evil\n" });
    expect(r.tasks.map((t) => [t.module, t.flags.includes("check_mode_false")])).toEqual([["shell", true], ["shell", true]]);
  });

  it("görev listesinde takma ad bombası ve kendine başvuran blok taramayı kilitlemez: sınır aşılınca ENGEL (fail-closed)", () => {
    const chr = (i: number): string => String.fromCharCode(97 + i);
    const levels = ["a: &a {block: [{debug: {msg: x}}]}", ...Array.from({ length: 8 }, (_, i) => `${chr(i + 1)}: &${chr(i + 1)} {block: [${Array(9).fill(`*${chr(i)}`).join(", ")}]}`)];
    const t0 = Date.now();
    const bomb = scanFiles({ "site.yml": `- hosts: all\n  vars:\n${levels.map((l) => `    ${l}`).join("\n")}\n  tasks:\n    - *i\n` });
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(bomb.blocked).toBe(true);
    expect(bomb.findings.map((f) => f.code)).toContain("task_limit");
    const self = scanFiles({ "site.yml": "- hosts: all\n  tasks:\n    - &x\n      block:\n        - *x\n" });
    expect(self.blocked).toBe(true);
    expect(self.findings.map((f) => f.code)).toContain("task_limit");
  });

  it("lookup('lines'), query('ansible.legacy.pipe'), with_pipe ve with_lines da denetleyicide komut çalıştırır", () => {
    for (const t of ["    - debug: { msg: \"{{ lookup('lines', 'id') }}\" }", "    - debug: { msg: \"{{ query('ansible.legacy.pipe', 'id') }}\" }", '    - debug: { msg: "{{ item }}" }\n      with_pipe: [id]', '    - debug: { msg: "{{ item }}" }\n      with_lines: cat /etc/passwd']) {
      expect(codes(t), t).toContain("lookup_pipe");
    }
  });
});

describe("ansible.check güvenlik kapısı (adapter): yüklenen dosyalardaki yapı da çalıştırmayı engeller", () => {
  async function gate(files: Record<string, string>) {
    const dir = await mkdtemp(join(tmpdir(), "ops-iac-gate-"));
    const manager = {
      current: () => ({
        ws: { id: "infra", engine: "ansible" },
        fs: {
          listFiles: async () => Object.keys(files).sort(),
          readText: async (p: string) => {
            const t = files[p];
            if (t === undefined) throw new OpsError("fs_not_found", p);
            return t;
          },
          snapshot: { dir, manifest: { skipped: [] } },
          root: join(dir, "work"),
        },
      }),
    } as unknown as WorkspaceManager;
    // Kapı sandbox'a ULAŞMADAN karar verir; ulaşılırsa ayırt edilebilir hata
    const reached = async (): Promise<never> => {
      throw new OpsError("sandbox_reached", "kapı geçildi");
    };
    const sandbox: Sandbox = { kind: "bwrap", run: reached, spawn: reached };
    const adapter = new IacAdapter({ manager, sandbox, toolDirs: [] });
    return {
      check: (playbook: string) => adapter.invoke({ tool: "ansible.check", args: { playbook } } as unknown as AdapterCall),
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  }

  it("PoC: include_tasks ile gelen check_mode: false → ÇALIŞMAZ; çözülemeyen include ve roles/ dışı rol → ÇALIŞMAZ; temiz playbook kapıdan geçer", async () => {
    const g = await gate({
      "site.yml": play("include_tasks: extra.yml"),
      "extra.yml": EXTRA,
      "missing.yml": play("include_tasks: nope.yml"),
      "role.yml": "- hosts: all\n  roles: [evil]\n",
      "evil/tasks/main.yml": "- command: id\n  check_mode: false\n",
      "clean.yml": play("debug: { msg: ok }"),
    });
    try {
      // depo genelinde güvensiz yapı varsa hiçbir playbook çalışmaz (bütün depo taranır)
      for (const pbName of ["site.yml", "missing.yml", "role.yml", "clean.yml"]) {
        const out = await g.check(pbName);
        expect(out.data, pbName).toMatchObject({ executed: false, unsafe: true });
        const found = (out.data as { findings: { code: string; file?: string }[] }).findings;
        expect(found).toContainEqual(expect.objectContaining({ code: "check_mode_false", file: "extra.yml" }));
        expect(found).toContainEqual(expect.objectContaining({ code: "check_mode_false", file: "evil/tasks/main.yml" }));
        expect(found).toContainEqual(expect.objectContaining({ code: "include_unresolved", file: "missing.yml" }));
      }
    } finally {
      await g.cleanup();
    }
    const ok = await gate({ "clean.yml": play("debug: { msg: ok }"), "tasks/x.yml": "- debug: { msg: x }\n", "inc.yml": play("include_tasks: tasks/x.yml") });
    try {
      for (const pbName of ["clean.yml", "inc.yml"]) await expect(ok.check(pbName), pbName).rejects.toMatchObject({ code: expect.stringMatching(/^(tool_missing|sandbox_reached)$/) });
    } finally {
      await ok.cleanup();
    }
  });

  it("blok/play düzeyinde check_mode kapatma ve yinelenen anahtarla gizlenen check_mode: false da ÇALIŞTIRMAYI ENGELLER", async () => {
    const cases: Record<string, string>[] = [
      { "site.yml": play("block:\n        - shell: id\n      check_mode: false") },
      { "site.yml": "- hosts: all\n  check_mode: off\n  tasks:\n    - shell: id\n" },
      { "site.yml": play("shell: id\n      check_mode: true\n      check_mode: false") },
    ];
    for (const files of cases) {
      const g = await gate(files);
      try {
        const out = await g.check("site.yml");
        expect(out.data, JSON.stringify(files)).toMatchObject({ executed: false, unsafe: true });
        expect((out.data as { findings: { code: string }[] }).findings.map((f) => f.code)).toContain("check_mode_false");
      } finally {
        await g.cleanup();
      }
    }
  });
});

describe("parseInventory: değerler asla çıkmaz", () => {
  const SECRET = "canary-" + Math.random().toString(36).slice(2);
  it("INI: gruplar, çocuklar, host değişkenleri; gizli adlar maskeli, değerler yok", () => {
    const ini = ["[web]", `h1 ansible_host=10.0.0.1 ansible_password=${SECRET}`, "h2", "", "[web:vars]", `ansible_become_pass=${SECRET}`, "http_port=80", "", "[all_servers:children]", "web", ""].join("\n");
    const inv = parseInventory("inventory/hosts.ini", ini);
    expect(inv.hosts).toEqual(["h1", "h2"]);
    expect(inv.groups.find((g) => g.name === "web")).toMatchObject({ hosts: 2, varNames: ["ansible_become_pass [maskeli]", "http_port"] });
    expect(inv.groups.find((g) => g.name === "all_servers")?.children).toEqual(["web"]);
    expect(inv.hostVarNames).toEqual(["ansible_host", "ansible_password [maskeli]"]);
    expect(JSON.stringify(inv)).not.toContain(SECRET);
    expect(inv.dynamic).toBe(false);
  });

  it("YAML: iç içe çocuk grupları; değerler yok", () => {
    const y = ["all:", "  children:", "    web:", "      hosts:", "        w1: { ansible_ssh_private_key_file: /k }", "      vars:", `        db_password: ${SECRET}`, "    db:", "      hosts: { d1: {} }", ""].join("\n");
    const inv = parseInventory("inventory.yml", y);
    expect(inv.hosts).toEqual(["d1", "w1"]);
    expect(inv.groups.map((g) => g.name)).toEqual(["all", "db", "web"]);
    expect(inv.groups.find((g) => g.name === "web")?.varNames).toEqual(["db_password [maskeli]"]);
    expect(inv.hostVarNames).toEqual(["ansible_ssh_private_key_file [maskeli]"]);
    expect(JSON.stringify(inv)).not.toContain(SECRET);
  });

  it("dinamik envanter (plugin: / #! betik) işaretlenir, içeriği yorumlanmaz", () => {
    expect(parseInventory("aws_ec2.yml", "plugin: amazon.aws.aws_ec2\nregions: [eu-west-1]\n").dynamic).toBe(true);
    expect(parseInventory("hosts", "#!/bin/sh\necho '{}'\n").dynamic).toBe(true);
  });

  it("geçersiz host/grup adları atlanır (enjeksiyon güvenli)", () => {
    const inv = parseInventory("hosts.ini", ["[web]", "ok-host", "evil;rm -rf", "$(id)"].join("\n"));
    expect(inv.hosts).toEqual(["ok-host"]);
  });
});
