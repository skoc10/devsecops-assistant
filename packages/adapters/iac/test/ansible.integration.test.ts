import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { makeIacHarness, sandbox } from "./harness.ts";
import { findTool } from "./tools.ts";

const playbook = await findTool("ansible-playbook", sandbox);
const lint = await findTool("ansible-lint", sandbox);
const ok = !!sandbox && !!playbook;

const SITE = [
  "---",
  "- name: Web",
  "  hosts: web",
  "  gather_facts: false",
  "  tasks:",
  "    - name: Show message",
  "      ansible.builtin.debug:",
  "        msg: hello",
  "    - name: Create dir",
  "      ansible.builtin.file:",
  "        path: /tmp/demo",
  "        state: directory",
  "        mode: '0755'",
  "",
].join("\n");

const BASE = {
  "site.yml": SITE,
  "inventory/hosts.ini": "[web]\nh1 ansible_host=10.0.0.1\n",
};

describe.skipIf(!ok)("Ansible araçları (gerçek ansible + gerçek bubblewrap, ağsız)", () => {
  it("iac.project.inspect: playbook/rol/görev sayısı ve en yüksek sınıf", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: { ...BASE, "roles/web/tasks/main.yml": "- name: Install\n  ansible.builtin.apt:\n    name: nginx\n" } });
    try {
      const r = await h.call("iac.project.inspect", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ engine: "ansible", tool: { name: "ansible-playbook", available: true }, playbooks: ["site.yml"], roles: ["web"], taskCount: 3, maxClass: "mutate", blocked: false });
      expect(j.modules).toEqual({ debug: 1, file: 1, apt: 1 });
    } finally {
      await h.cleanup();
    }
  });

  const LOCAL = [
    "---",
    "- name: Local",
    "  hosts: all",
    "  gather_facts: false",
    "  tasks:",
    "    - name: Say hi",
    "      ansible.builtin.debug:",
    "        msg: hello",
    "    - name: Make file",
    "      ansible.builtin.file:",
    "        path: /tmp/ops-check-target",
    "        state: touch",
    "    - name: Always fails",
    "      ansible.builtin.fail:",
    "        msg: expected-failure-marker",
    "      ignore_errors: true",
    "",
  ].join("\n");

  it("ansible.check: yerel bağlantı, görev düzeyi sonuç (changed/ok/failed), PLAY RECAP; sandbox'ta GERÇEK değişiklik olmaz; diff içeriği çıkmaz", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: { "local.yml": LOCAL, "inventory/hosts.ini": "[web]\nh1 ansible_host=10.0.0.1\n" } });
    try {
      const r = await h.call("ansible.check", { playbook: "local.yml" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j, JSON.stringify(j)).toMatchObject({ executed: true, playbook: "local.yml", inventory: "localhost,", exitCode: 0 });
      expect(j.recap).toEqual([expect.objectContaining({ host: "localhost", failed: 0, unreachable: 0 })]);
      const byTask = Object.fromEntries(j.tasks.map((t: { task: string; status: string }) => [t.task, t.status]));
      expect(byTask["Say hi"]).toBe("ok");
      expect(byTask["Make file"]).toBe("changed"); // check modunda "değişecek"
      expect(j.tasks.find((t: { task: string }) => t.task === "Always fails")).toMatchObject({ status: "failed" });
      expect(j.note).toMatch(/YEREL bağlantı/);
      expect(r.summary).toMatch(/1 değişecek görev/);
      expect(existsSync("/tmp/ops-check-target")).toBe(false); // check gerçekten dokunmadı
      expect(existsSync(join(h.fs.root, ".ansible"))).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("ansible.check: statik envanter + --limit; envanter/playbook doğrulanır (kayıtlı olmayan yol ret)", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: { "local.yml": LOCAL.replace("hosts: all", "hosts: web"), "inventory/hosts.ini": "[web]\nh1 ansible_host=10.0.0.1\nh2 ansible_host=10.0.0.2\n" } });
    try {
      const r = await h.call("ansible.check", { playbook: "local.yml", inventory: "inventory/hosts.ini", limit: "h2" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j.recap.map((x: { host: string }) => x.host)).toEqual(["h2"]); // limit uygulandı; h1 dokunulmadı
      const bad1 = await h.call("ansible.check", { playbook: "nope.yml" });
      expect(bad1.status).toBe("error");
      expect(bad1.summary).toMatch(/playbook olarak bulunamadı/);
      const bad2 = await h.call("ansible.check", { playbook: "local.yml", inventory: "../etc/hosts" });
      expect(bad2.summary).toMatch(/envanter dosyası olarak bulunamadı/);
      expect((await h.call("ansible.check", { playbook: "local.yml", limit: "h1; id" })).reasonCode).toBe("schema_invalid");
    } finally {
      await h.cleanup();
    }
  });

  it("ansible.check: check modunda yan etkisiz olduğu garanti edilemeyen yapılar ÇALIŞTIRMAYI ENGELLER (check_mode: false, lookup pipe, sınıflanamayan modül, şablonlu include)", async () => {
    const mk = (task: string) => ["---", "- hosts: all", "  gather_facts: false", "  tasks:", ...task.split("\n").map((l) => `    ${l}`), ""].join("\n");
    const cases: [string, string, string][] = [
      ["check_mode_false", "- name: real\n  ansible.builtin.file:\n    path: /tmp/ops-should-not-exist\n    state: touch\n  check_mode: false", "check_mode_false"],
      ["lookup_pipe", "- name: pipe\n  ansible.builtin.debug:\n    msg: \"{{ lookup('pipe', 'id') }}\"", "lookup_pipe"],
      ["unclassified", "- name: weird\n  community.unknown.thing:\n    a: 1", "module_unclassified"],
      ["dynamic_include", "- name: inc\n  ansible.builtin.include_tasks: \"{{ which }}.yml\"", "dynamic_include"],
      ["block_check_mode", "- block:\n    - name: real\n      ansible.builtin.file:\n        path: /tmp/ops-should-not-exist\n        state: touch\n  check_mode: off", "check_mode_false"],
      ["dup_check_mode", "- name: real\n  ansible.builtin.file:\n    path: /tmp/ops-should-not-exist\n    state: touch\n  check_mode: true\n  check_mode: false", "check_mode_false"],
    ];
    for (const [name, task, code] of cases) {
      const h = await makeIacHarness({ engine: "ansible", files: { "p.yml": mk(task) } });
      try {
        const r = await h.call("ansible.check", { playbook: "p.yml" });
        expect(r.status, name).toBe("ok");
        const j = h.json(r);
        expect(j, name).toMatchObject({ executed: false, unsafe: true });
        expect(j.findings.map((f: { code: string }) => f.code), name).toContain(code);
        expect(r.summary).toMatch(/check ÇALIŞMADI/);
        expect(existsSync("/tmp/ops-should-not-exist")).toBe(false);
      } finally {
        await h.cleanup();
      }
    }
  });

  it("ansible.check: include_tasks / roles/ dışı rol ile YÜKLENEN dosyadaki check_mode: false ve çözülemeyen include da ÇALIŞTIRMAYI ENGELLER (bulgu PoC'si)", async () => {
    const MARK = "/tmp/ops-include-" + Math.random().toString(36).slice(2);
    const head = "---\n- hosts: all\n  gather_facts: false\n";
    const evil = `- ansible.builtin.shell: touch ${MARK}\n  check_mode: false\n- ansible.builtin.file:\n    path: /tmp/ops-should-not-exist\n    state: absent\n`;
    const cases: [string, Record<string, string>, string][] = [
      ["include_tasks", { "site.yml": `${head}  tasks:\n    - ansible.builtin.include_tasks: extra.yml\n`, "extra.yml": evil }, "check_mode_false"],
      ["roles/ dışı rol", { "site.yml": `${head}  roles: [evil]\n`, "evil/tasks/main.yml": evil }, "check_mode_false"],
      ["çözülemeyen include", { "site.yml": `${head}  tasks:\n    - ansible.builtin.include_tasks: missing.yml\n` }, "include_unresolved"],
    ];
    for (const [name, files, code] of cases) {
      const h = await makeIacHarness({ engine: "ansible", files });
      try {
        const r = await h.call("ansible.check", { playbook: "site.yml" });
        expect(r.status, name).toBe("ok");
        const j = h.json(r);
        expect(j, name).toMatchObject({ executed: false, unsafe: true });
        expect(j.findings.map((f: { code: string }) => f.code), name).toContain(code);
        expect(existsSync(MARK), name).toBe(false);
      } finally {
        await h.cleanup();
      }
    }
  });

  it("ansible.check: yerel eklenti dizini (library/) engelleyici bulgu — ÇALIŞMAZ", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: { "p.yml": "---\n- hosts: all\n  gather_facts: false\n  tasks: []\n", "library/evil.py": "print('x')\n" } });
    try {
      const r = await h.call("ansible.check", { playbook: "p.yml" });
      expect(h.json(r)).toMatchObject({ executed: false, blocked: true });
    } finally {
      await h.cleanup();
    }
  });

  it("iac.lint: --syntax-check geçer; çalışma kopyasında artık dosya kalmaz; kullanıcının deposu değişmez", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: BASE });
    try {
      const r = await h.call("iac.lint", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(j.syntaxCheck).toEqual([{ playbook: "site.yml", ok: true }]);
      expect(existsSync(join(h.fs.root, ".ansible"))).toBe(false);
      expect(existsSync(join(h.repo.dir, ".ansible"))).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("iac.lint: sözdizimi hatası kompakt iletiyle döner; yaz → doğrula → düzelt döngüsü", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: BASE });
    try {
      await h.call("fs.write", { path: "broken.yml", content: "---\n- hosts: web\n  tasks:\n    - name: x\n      ansible.builtin.no_such_module_xyz:\n        a: 1\n" });
      const bad = h.json(await h.call("iac.lint", { playbook: "broken.yml" }));
      expect(bad.syntaxCheck[0]).toMatchObject({ playbook: "broken.yml", ok: false });
      expect(bad.syntaxCheck[0].message).toMatch(/no_such_module_xyz|couldn't resolve module/i);
      await h.call("fs.write", { path: "broken.yml", content: "---\n- hosts: web\n  gather_facts: false\n  tasks:\n    - name: x\n      ansible.builtin.debug:\n        msg: ok\n" });
      expect(h.json(await h.call("iac.lint", { playbook: "broken.yml" })).syntaxCheck[0]).toMatchObject({ ok: true });
    } finally {
      await h.cleanup();
    }
  });

  it("iac.lint: playbook olmayan yol / dizin kaçışı reddedilir (kataloğdaki playbook'lar dışında çalışmaz)", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: { ...BASE, "vars/x.yml": "a: 1\n" } });
    try {
      for (const p of ["vars/x.yml", "../etc/passwd", "/etc/passwd", "nope.yml"]) {
        const r = await h.call("iac.lint", { playbook: p });
        if (r.status !== "ok") continue; // şema/yol politikası reddetmiş olabilir
        expect(h.json(r).syntaxCheck[0], p).toMatchObject({ ok: false, message: expect.stringMatching(/playbook olarak bulunamadı/) });
      }
    } finally {
      await h.cleanup();
    }
  });

  it.skipIf(!lint)("iac.lint: ansible-lint (çevrimdışı, ürünün kendi yapılandırması) bulguları kompakt döner", async () => {
    const h = await makeIacHarness({
      engine: "ansible",
      files: { "site.yml": "---\n- name: Web\n  hosts: web\n  gather_facts: false\n  tasks:\n    - name: bad\n      shell: echo hi\n      changed_when: true\n    - ansible.builtin.debug:\n        msg: x\n" },
    });
    try {
      const j = h.json(await h.call("iac.lint", {}));
      expect(j.lint.total, JSON.stringify(j.lint)).toBeGreaterThan(0);
      expect(j.lint.issues.length).toBeLessThanOrEqual(30);
      expect(j.lint.issues[0]).toEqual(expect.objectContaining({ rule: expect.any(String), file: "site.yml" }));
      expect(j.lint.issues.map((i: any) => i.rule).join(" ")).toMatch(/fqcn|name|command-instead-of-shell|no-changed-when/);
    } finally {
      await h.cleanup();
    }
  });

  it("S-18: yerel eklenti/modül dizini ENGELLER — ansible ÇALIŞTIRILMAZ (library/ içindeki betik hiç yürümez)", async () => {
    const MARK = "/tmp/ops-pwned-" + Math.random().toString(36).slice(2);
    const h = await makeIacHarness({
      engine: "ansible",
      files: {
        ...BASE,
        "library/evil.py": `import os\nos.system("touch ${MARK}")\n`,
        "lookup_plugins/evil.py": `import os\nos.system("touch ${MARK}")\n`,
      },
    });
    try {
      const r = await h.call("iac.lint", {});
      expect(r.status).toBe("ok");
      const j = h.json(r);
      expect(j).toMatchObject({ executed: false, blocked: true });
      expect(j.findings.map((f: any) => f.code)).toContain("local_plugin_dir");
      expect(existsSync(MARK)).toBe(false);
      const insp = h.json(await h.call("iac.project.inspect", {}));
      expect(insp.blocked).toBe(true);
    } finally {
      await h.cleanup();
    }
  });

  it("S-18: depodaki ansible.cfg yok sayılır (callback/lookup yolu, host_key_checking=False etkisiz)", async () => {
    const MARK = "/tmp/ops-cfg-" + Math.random().toString(36).slice(2);
    const h = await makeIacHarness({
      engine: "ansible",
      files: {
        ...BASE,
        "ansible.cfg": `[defaults]\nhost_key_checking = False\ncallbacks_enabled = evil\ninventory_plugins = ./plugins\nremote_tmp = ${MARK}\n`,
      },
    });
    try {
      const insp = h.json(await h.call("iac.project.inspect", {}));
      expect(insp.findings.map((f: any) => f.code)).toContain("ansible_cfg_ignored");
      const j = h.json(await h.call("iac.lint", {}));
      expect(j.syntaxCheck).toEqual([{ playbook: "site.yml", ok: true }]);
      expect(existsSync(MARK)).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("ansible.inventory.list: gruplar/host adları; parola/anahtar değişken DEĞERLERİ çıkmaz (S-19)", async () => {
    const SECRET = "canary-" + Math.random().toString(36).slice(2);
    const h = await makeIacHarness({
      engine: "ansible",
      files: {
        ...BASE,
        "inventory/hosts.ini": `[web]\nh1 ansible_host=10.0.0.1 ansible_password=${SECRET}\n\n[web:vars]\nansible_become_pass=${SECRET}\n`,
        "inventory/prod.yml": `all:\n  children:\n    db:\n      hosts:\n        d1: {}\n      vars:\n        db_password: ${SECRET}\n`,
      },
    });
    try {
      const r = await h.call("ansible.inventory.list", {});
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.json(r);
      expect(JSON.stringify(j)).not.toContain(SECRET);
      expect(JSON.stringify(r)).not.toContain(SECRET);
      expect(JSON.stringify(h.storage)).not.toContain(SECRET);
      const hosts = j.inventories.flatMap((i: any) => i.hosts);
      expect(hosts.sort()).toEqual(["d1", "h1"]);
      expect(JSON.stringify(j)).toContain("ansible_password [maskeli]");
    } finally {
      await h.cleanup();
    }
  });

  it("ansible.inventory.list: dinamik envanter betiği ÇALIŞTIRILMAZ (yalnız işaretlenir)", async () => {
    const MARK = "/tmp/ops-inv-" + Math.random().toString(36).slice(2);
    const h = await makeIacHarness({ engine: "ansible", files: { ...BASE, "inventory/dyn.py": `#!/bin/sh\ntouch ${MARK}\necho '{}'\n`, "inventory/dyn.yml": "plugin: amazon.aws.aws_ec2\n" } });
    try {
      const j = h.json(await h.call("ansible.inventory.list", { path: "inventory/dyn.yml" }));
      expect(j.inventories[0]).toMatchObject({ path: "inventory/dyn.yml", dynamic: true, hosts: [] });
      expect(existsSync(MARK)).toBe(false);
    } finally {
      await h.cleanup();
    }
  });

  it("lookup('pipe') ve local_action uyarı olarak görünür; araç yalnız sözdizimi denetler (görev ÇALIŞMAZ)", async () => {
    const MARK = "/tmp/ops-pipe-" + Math.random().toString(36).slice(2);
    const h = await makeIacHarness({
      engine: "ansible",
      files: {
        "site.yml": `---\n- hosts: web\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: "{{ lookup('pipe', 'touch ${MARK}') }}"\n    - local_action: command touch ${MARK}\n`,
      },
    });
    try {
      const insp = h.json(await h.call("iac.project.inspect", {}));
      expect(insp.findings.map((f: any) => f.code)).toEqual(expect.arrayContaining(["lookup_pipe", "controller_execution"]));
      expect(insp.maxClass).toBe("deploy");
      const j = h.json(await h.call("iac.lint", {}));
      expect(j.syntaxCheck[0].ok).toBe(true);
      expect(existsSync(MARK)).toBe(false); // --syntax-check hiçbir görevi çalıştırmaz
    } finally {
      await h.cleanup();
    }
  });

  it("motor uyuşmazlığı: Terraform araçları ansible çalışma alanında reddedilir", async () => {
    const h = await makeIacHarness({ engine: "ansible", files: BASE });
    try {
      const r = await h.call("iac.validate", {});
      expect(r.status).not.toBe("ok");
      expect(JSON.stringify(r)).toMatch(/engine_mismatch|Terraform/);
    } finally {
      await h.cleanup();
    }
  });
});
