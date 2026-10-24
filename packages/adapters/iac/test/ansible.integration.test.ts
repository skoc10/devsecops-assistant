import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { makeIacHarness, sandbox } from "./harness.ts";
import { findTool } from "./tools.ts";

const playbook = findTool("ansible-playbook");
const lint = findTool("ansible-lint");
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
