import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AuditLog, MemoryAuditStorage, MemoryHeadAnchor } from "@ops/audit";
import type { ApprovalGate, ApprovalRequest, ToolResult } from "@ops/contracts";
import { EvidenceStore, Session, ToolGateway, ToolRegistry } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { detectSandbox } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { FakeBroker } from "@ops/testkit";
import { McpBridgeAdapter, McpManifestSchema } from "../src/index.ts";
import type { McpManifest } from "../src/index.ts";

export const sandbox = await detectSandbox();
export const MOCK_SERVER = fileURLToPath(new URL("./mock-server.mjs", import.meta.url));
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
export const NODE_SHA = sha(readFileSync(process.execPath));
export const MOCK_SHA = sha(readFileSync(MOCK_SERVER));

class Gate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  async request(req: ApprovalRequest) {
    this.requests.push(req);
    return { approved: true, approvalId: `a${this.requests.length}`, actionHash: req.actionHash } as const;
  }
}

const ALL_TOOLS = ["echo", "search", "probe", "docs", "big", "leak"] as const;
const DESC: Record<string, string> = {
  echo: "Metni geri yansıtır.",
  search: "Arama yapar.",
  probe: "Ortam yoklaması.",
  docs: "Doküman getirir.",
  big: "Büyük çıktı.",
  leak: "Anahtar döndürür.",
};

export interface McpHarnessOpts {
  readonly mode?: string;
  readonly network?: "none" | "host";
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly env?: Record<string, string>;
  readonly sha256?: string;
  readonly fileSha256?: string;
  readonly tools?: readonly string[];
}

export function manifestFor(o: McpHarnessOpts = {}): McpManifest {
  const tools = (o.tools ?? ALL_TOOLS).map((name) => ({
    name,
    description: DESC[name] ?? name,
    sensitivity: "internal" as const,
    args:
      name === "echo"
        ? { text: { type: "string" as const, required: true, maxLength: 200 } }
        : name === "search"
          ? { query: { type: "string" as const, required: true, maxLength: 100 }, limit: { type: "integer" as const, min: 1, max: 20 } }
          : {},
  }));
  return McpManifestSchema.parse({
    servers: [
      {
        id: "mock",
        command: process.execPath,
        sha256: o.sha256 ?? NODE_SHA,
        args: [MOCK_SERVER],
        files: [{ path: MOCK_SERVER, sha256: o.fileSha256 ?? MOCK_SHA }],
        env: { MOCK_MODE: o.mode ?? "normal", ...(o.env ?? {}) },
        network: o.network ?? "none",
        ...(o.network === "host" ? { acknowledgeUnrestrictedNetwork: true } : {}),
        timeoutMs: o.timeoutMs ?? 10_000,
        ...(o.maxOutputBytes ? { maxOutputBytes: o.maxOutputBytes } : {}),
        tools,
      },
    ],
  });
}

/** Sandbox'a verilen `spawn` çağrılarını sayan sarmalayıcı (pin reddinde sunucunun HİÇ başlamadığını göstermek için). */
function spied(sb: Sandbox): { sandbox: Sandbox; spawns: () => number } {
  let n = 0;
  return {
    sandbox: { kind: sb.kind, run: (s) => sb.run(s), spawn: (s) => (n++, sb.spawn(s)) },
    spawns: () => n,
  };
}

export async function makeMcpHarness(o: McpHarnessOpts = {}) {
  const known = new KnownSecrets();
  const storage = new MemoryAuditStorage();
  const audit = await AuditLog.open({ storage, key: randomBytes(32), anchor: new MemoryHeadAnchor(), scrub: (s) => scrubText(s, known) });
  const evidence = new EvidenceStore();
  const session = new Session(`s${randomBytes(4).toString("hex")}`);
  const spy = spied(sandbox!);
  const manifest = manifestFor(o);
  const adapter = new McpBridgeAdapter({ manifest, sandbox: spy.sandbox, known });
  const registry = new ToolRegistry();
  registry.register(adapter, adapter.definitions);
  const gate = new Gate();
  const gateway = new ToolGateway({ registry, session, policy: new PolicyEngine(DEFAULT_POLICY), audit, broker: new FakeBroker({ secretFor: () => "x" }), evidence, known, approval: gate });
  session.activeToolsets.add("mcp-mock");
  const call = (tool: string, args: unknown): Promise<ToolResult> => gateway.invoke({ tool, args, providerZone: "local" });
  const json = (r: ToolResult): any => {
    const e = r.evidenceId ? evidence.get(r.evidenceId) : undefined;
    if (!e) throw new Error(`kanıt yok: ${JSON.stringify(r)}`);
    return JSON.parse(e.text);
  };
  return { adapter, manifest, session, call, json, gate, evidence, storage, known, spawns: spy.spawns };
}
export type McpHarness = Awaited<ReturnType<typeof makeMcpHarness>>;
