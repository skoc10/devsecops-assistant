import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import type { ApprovalGate, ApprovalRequest, ToolResult } from "@ops/contracts";
import { EvidenceStore, Session, ToolGateway, ToolRegistry, createLocalAdapter } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { detectSandbox } from "@ops/sandbox";
import { FakeBroker } from "@ops/testkit";
import { makeRepo } from "@ops/testkit/git-repo";
import type { TestRepo } from "@ops/testkit/git-repo";
import { WorkspaceAdapter, WorkspaceManager, WorkspaceRegistry } from "@ops/workspace";
import type { WorkspaceEngine } from "@ops/workspace";
import { IacAdapter } from "../src/index.ts";
import { TOOL_DIRS } from "./tools.ts";

export const sandbox = await detectSandbox();

class Gate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  async request(req: ApprovalRequest) {
    this.requests.push(req);
    return { approved: true, approvalId: `a${this.requests.length}`, actionHash: req.actionHash } as const;
  }
}

export interface IacHarnessOpts {
  readonly engine: WorkspaceEngine;
  readonly files: Record<string, string>;
  readonly providerMirror?: string;
}

/** Gerçek git deposu + gerçek bubblewrap + PEP; fs.* ve iac.* araçları bir arada. */
export async function makeIacHarness(opts: IacHarnessOpts) {
  const repo: TestRepo = await makeRepo(opts.files);
  const home = await mkdtemp(join(tmpdir(), "ops-iac-"));
  const storage = new MemoryAuditStorage();
  const known = new KnownSecrets();
  const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session(`s${randomBytes(4).toString("hex")}`);
  const reg = await WorkspaceRegistry.open(join(home, "workspaces.json"));
  await reg.add({ id: "infra", path: repo.dir, engine: opts.engine });
  const manager = new WorkspaceManager({ registry: reg, worktreesDir: join(home, "worktrees"), sandbox, known });
  const registry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  registry.register(local.adapter, local.definitions);
  const ws = new WorkspaceAdapter(manager);
  registry.register(ws, ws.definitions);
  const iac = new IacAdapter({ manager, sandbox, toolDirs: TOOL_DIRS, ...(opts.providerMirror ? { providerMirror: opts.providerMirror } : {}) });
  registry.register(iac, iac.definitions);
  const gate = new Gate();
  const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker: new FakeBroker({ secretFor: () => "x" }), evidence, known, approval: gate });
  session.activeToolsets.add("workspace");
  session.activeToolsets.add("iac");
  const active = await manager.activate("infra", session.id);
  const call = (tool: string, args: unknown): Promise<ToolResult> => gateway.invoke({ tool, args, providerZone: "local" });
  const json = (r: ToolResult): any => {
    const e = r.evidenceId ? evidence.get(r.evidenceId) : undefined;
    if (!e) throw new Error(`kanıt yok: ${JSON.stringify(r)}`);
    return JSON.parse(e.text);
  };
  return { repo, home, session, manager, fs: active.fs, call, json, gate, evidence, storage, async cleanup() { await repo.cleanup(); await rm(home, { recursive: true, force: true }); } };
}
export type IacHarness = Awaited<ReturnType<typeof makeIacHarness>>;
