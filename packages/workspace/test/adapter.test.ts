import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import { estimateTokens } from "@ops/contracts";
import type { ApprovalGate, ApprovalRequest } from "@ops/contracts";
import { EvidenceStore, Session, ToolGateway, ToolRegistry, createLocalAdapter } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { detectSandbox } from "@ops/sandbox";
import { FakeBroker, checkAdapterStructure } from "@ops/testkit";
import { WorkspaceAdapter, WorkspaceManager, WorkspaceRegistry } from "../src/index.ts";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";

const sandbox = await detectSandbox();

class Gate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  approve = true;
  async request(req: ApprovalRequest) {
    this.requests.push(req);
    return this.approve ? ({ approved: true, approvalId: `a${this.requests.length}`, actionHash: req.actionHash } as const) : ({ approved: false, reason: "reddedildi" } as const);
  }
}

describe("WorkspaceAdapter yapısı", () => {
  it("4 araç; yalnız fs.write localWrite; hepsi kimliksiz ve ağsız", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ops-wsa-"));
    try {
      const mgr = new WorkspaceManager({ registry: await WorkspaceRegistry.open(join(dir, "w.json")), worktreesDir: join(dir, "wt"), sandbox: null });
      const a = new WorkspaceAdapter(mgr);
      expect(checkAdapterStructure(a)).toEqual([]);
      expect(a.manifest.tools.map((t) => t.name).sort()).toEqual(["fs.diff", "fs.list", "fs.read", "fs.write"]);
      expect(a.manifest.tools.filter((t) => t.localWrite).map((t) => t.name)).toEqual(["fs.write"]);
      expect(a.manifest.tools.every((t) => t.scope === "local" && t.profileKind === null && t.network === "none" && t.toolset === "workspace")).toBe(true);
      const specs = JSON.stringify(a.manifest.tools.map((t) => ({ n: t.name, d: t.description, s: t.inputSchema })));
      expect(estimateTokens(specs)).toBeLessThanOrEqual(900);
      // etkin çalışma alanı yokken açık hata
      await expect(mgr.activate("yok", "s1")).rejects.toThrow(/kayıtlı değil/);
      await expect(new WorkspaceManager({ registry: await WorkspaceRegistry.open(join(dir, "w.json")), worktreesDir: join(dir, "wt"), sandbox: null }).activate("x", "s1")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!sandbox)("fs.* araçları PEP üzerinden: ilk yazma onayı → oturum yazma izni", () => {
  let repo: TestRepo;
  let home = "";
  beforeAll(async () => {
    repo = await makeRepo();
    home = await mkdtemp(join(tmpdir(), "ops-wsh-"));
  });
  afterAll(async () => {
    await repo.cleanup();
    await rm(home, { recursive: true, force: true });
  });

  async function make(opts: { gate?: Gate | null } = {}) {
    const storage = new MemoryAuditStorage();
    const known = new KnownSecrets();
    const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
    const evidence = new EvidenceStore();
    const session = new Session(`s${randomBytes(4).toString("hex")}`);
    const reg = await WorkspaceRegistry.open(join(home, `w-${session.id}.json`));
    await reg.add({ id: "infra", path: repo.dir, engine: "opentofu" });
    const mgr = new WorkspaceManager({ registry: reg, worktreesDir: join(home, "wt"), sandbox, known });
    const registry = new ToolRegistry();
    const local = createLocalAdapter(evidence);
    registry.register(local.adapter, local.definitions);
    const adapter = new WorkspaceAdapter(mgr);
    registry.register(adapter, adapter.definitions);
    const gate = opts.gate === undefined ? new Gate() : opts.gate;
    const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker: new FakeBroker({ secretFor: () => "x" }), evidence, known, ...(gate ? { approval: gate } : {}) });
    // fs.* araçları çekirdek olmayan toolset'te; test için etkinleştir
    session.activeToolsets.add("workspace");
    const call = (tool: string, args: unknown) => gateway.invoke({ tool, args, providerZone: "local" });
    return { mgr, session, gate, call, storage, evidence, activate: () => mgr.activate("infra", session.id) };
  }

  it("etkin çalışma alanı yokken açık hata", async () => {
    const h = await make();
    const r = await h.call("fs.read", { path: "main.tf" });
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/etkin çalışma alanı yok/);
  });

  it("fs.read/list/diff onaysız; fs.read bağlamı kirletmez", async () => {
    const h = await make();
    await h.activate();
    expect((await h.call("fs.list", {})).status).toBe("ok");
    const r = await h.call("fs.read", { path: "main.tf", maxLines: 3 });
    expect(r.status).toBe("ok");
    expect((await h.call("fs.diff", {})).status).toBe("ok");
    expect(h.gate?.requests.length).toBe(0);
    expect(h.session.context.tainted).toBe(false);
  });

  it("ilk fs.write sorar (kapsam notuyla); onaydan sonra aynı oturumda diğer yazımlar sorulmaz ama denetime yazılır", async () => {
    const h = await make();
    const { fs } = await h.activate();
    const first = await h.call("fs.write", { path: "a.tf", content: "# a\n" });
    expect(first.status, JSON.stringify(first)).toBe("ok");
    expect(h.gate?.requests.length).toBe(1);
    expect(h.gate?.requests[0]?.summary).toMatchObject({ tool: "fs.write", why: "approval_required", taintedContext: false });
    expect(h.gate?.requests[0]?.summary.note).toMatch(/oturumda AYNI aracın çalışma alanı/);
    const second = await h.call("fs.write", { path: "b.tf", content: "# b\n" });
    expect(second.status).toBe("ok");
    expect(h.gate?.requests.length).toBe(1); // yeniden sorulmadı
    expect((await fs.read("b.tf")).content).toBe("# b");
    const audit = (await h.storage.readLines()).join("\n");
    expect(audit).toContain("oturum yazma izni");
    // fs.read hâlâ onay istemez
    await h.call("fs.read", { path: "a.tf" });
    expect(h.gate?.requests.length).toBe(1);
  });

  it("bağlam taint'li olunca yeniden sorar; reddedilirse yazım yapılmaz ve izin verilmez", async () => {
    const h = await make();
    const { fs } = await h.activate();
    await h.call("fs.write", { path: "a.tf", content: "# a\n" });
    h.session.noteResult({ sensitivity: "none", tainted: true }); // untrusted içerik bağlama girdi
    h.gate!.approve = false;
    const denied = await h.call("fs.write", { path: "c.tf", content: "# c\n" });
    expect(denied).toMatchObject({ status: "denied", reasonCode: "approval_denied" });
    expect(h.gate?.requests.length).toBe(2);
    expect(existsSync(join(fs.root, "c.tf"))).toBe(false);
    // onaylanırsa yazılır ama taint'liyken izin VERİLMEZ (her yazım sorar)
    h.gate!.approve = true;
    expect((await h.call("fs.write", { path: "c.tf", content: "# c\n" })).status).toBe("ok");
    expect(h.gate?.requests.length).toBe(3);
    expect((await h.call("fs.write", { path: "d.tf", content: "# d\n" })).status).toBe("ok");
    expect(h.gate?.requests.length).toBe(4);
  });

  it("onay kapısı yoksa fs.write reddedilir (fail-closed) ve hiçbir şey yazılmaz", async () => {
    const h = await make({ gate: null });
    const { fs } = await h.activate();
    const r = await h.call("fs.write", { path: "a.tf", content: "# a\n" });
    expect(r).toMatchObject({ status: "denied", reasonCode: "approval_unavailable" });
    expect(existsSync(join(fs.root, "a.tf"))).toBe(false);
  });

  it("ilk onay reddedilirse izin oluşmaz; yasak yol/secret yazımı onaydan sonra bile reddedilir ve denetimde değer yok", async () => {
    const h = await make();
    const { fs } = await h.activate();
    h.gate!.approve = false;
    expect((await h.call("fs.write", { path: "a.tf", content: "# a\n" })).reasonCode).toBe("approval_denied");
    h.gate!.approve = true;
    const ci = await h.call("fs.write", { path: ".github/workflows/ci.yml", content: "name: x\n" });
    expect(ci.status).toBe("error");
    expect(ci.summary).toMatch(/yazma yasak: CI\/pipeline tanımı/);
    const aws = `AKIA${"Q1W2E3R4T5Y6U7I8"}`;
    const sec = await h.call("fs.write", { path: "p.tf", content: `access_key = "${aws}"\n` });
    expect(sec.status).toBe("error");
    expect(sec.summary).toMatch(/gömülü secret/);
    expect(existsSync(join(fs.root, "p.tf"))).toBe(false);
    expect((await h.storage.readLines()).join("\n")).not.toContain(aws);
    expect(JSON.stringify(h.evidence.all().map((e) => e.text))).not.toContain(aws);
  });

  it("fs.diff: yazılanları gösterir; kanıt/subject; kullanıcı deposu değişmez", async () => {
    const h = await make();
    await h.activate();
    await h.call("fs.write", { path: "extra.tf", content: 'output "o" {\n  value = 1\n}\n' });
    const d = await h.call("fs.diff", {});
    expect(d.status).toBe("ok");
    const ev = h.evidence.get(d.evidenceId!);
    expect(JSON.parse(ev!.text).changes).toEqual([{ path: "extra.tf", status: "added", additions: 3, deletions: 0 }]);
    expect(ev?.subjects).toContain("File/infra/extra.tf");
    expect(existsSync(join(repo.dir, "extra.tf"))).toBe(false);
  });
});
