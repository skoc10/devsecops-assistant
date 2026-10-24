import { describe, expect, it } from "vitest";
import { parseInventory, scanAnsible } from "../src/ansible.ts";

const pb = (tasks: string, extra = ""): { path: string; text: string }[] => [
  { path: "site.yml", text: `- hosts: web\n  ${extra}\n  tasks:\n${tasks}` },
];
const scan = (tasks: string, extra = "") => scanAnsible(pb(tasks, extra));
const codes = (tasks: string, extra = ""): string[] => scan(tasks, extra).findings.map((f) => f.code);

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
