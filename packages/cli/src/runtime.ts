import { access, readFile } from "node:fs/promises";
import { mergeCatalogs, parseCatalog, shellCommandClassifier } from "@ops/classifiers";
import type { CommandCatalog } from "@ops/classifiers";
import { TerminalAdapter, assertSafeWorkdir } from "@ops/terminal";
import { KubernetesAdapter } from "@ops/adapter-kubernetes";
import { AuditLog, FileAuditStorage, FileHeadAnchor } from "@ops/audit";
import {
  EncryptedFileStore,
  ExecCredentialRunner,
  LocalBroker,
  ProfileRegistry,
  ProfileService,
  ensureAuditKey,
} from "@ops/broker";
import type { ProfileRegistryOptions } from "@ops/broker";
import type { AgentRuntime, ApprovalGate, DoctorReport, ModelProvider, Profile, SecretStore } from "@ops/contracts";
import { EvidenceStore, Orchestrator, RuntimeOrchestrator, Session, ToolGateway, ToolRegistry, createLocalAdapter } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine, loadPolicyFile } from "@ops/policy";
import type { PolicyDocument } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { detectSandbox } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { SkillRegistry, createSkillAdapter } from "@ops/skills";
import { BUILTIN_CATALOG_FILE, BUILTIN_POLICY_FILE, BUILTIN_SKILLS_DIR, ensureHome } from "./paths.ts";
import type { OpsPaths } from "./paths.ts";

export interface RuntimeOptions {
  readonly paths: OpsPaths;
  /** Şifreli dosya kasası için parola; `store` verilmediyse zorunlu. */
  readonly passphrase?: () => Promise<Uint8Array>;
  readonly scryptParams?: { N: number; r: number; p: number };
  /** Hazır kasa (test / OS anahtar zinciri). */
  readonly store?: SecretStore;
  /** `"detect"` (varsayılan): bubblewrap/seatbelt yoklanır. `null`: sandbox yok. */
  readonly sandbox?: Sandbox | null | "detect";
  readonly policy?: PolicyDocument;
  readonly builtinSkillsDir?: string;
  /** `shell.run` iş alanı (salt-okunur bağlanır). Verilmezse ve/veya sandbox yoksa terminal aracı KAYITLI DEĞİLDİR. */
  readonly workdir?: string;
  readonly approval?: ApprovalGate;
  readonly registryOptions?: Partial<ProfileRegistryOptions>;
  readonly now?: () => Date;
}

export interface Runtime {
  readonly paths: OpsPaths;
  readonly store: SecretStore;
  readonly known: KnownSecrets;
  readonly audit: AuditLog;
  readonly profiles: ProfileService;
  readonly registry: ProfileRegistry;
  readonly broker: LocalBroker;
  readonly session: Session;
  readonly evidence: EvidenceStore;
  readonly toolRegistry: ToolRegistry;
  readonly gateway: ToolGateway;
  readonly policy: PolicyEngine;
  readonly skills: SkillRegistry;
  readonly adapter: KubernetesAdapter;
  readonly sandbox: Sandbox | null;
  /** Profili doktordan geçirir (bağlamaz). */
  diagnose(id: string): Promise<DoctorReport>;
  /** Profili doktordan geçirip oturuma bağlar; `bindable=false` ise BAĞLAMAZ. */
  bindProfile(id: string): Promise<DoctorReport>;
  createOrchestrator(provider: ModelProvider, options?: ConstructorParameters<typeof Orchestrator>[0]["options"]): Orchestrator;
  /** Sağlayıcı-döngülü çalışma zamanı (Cursor): araçlar yalnız PEP köprüsünden. */
  createRuntimeOrchestrator(runtime: AgentRuntime): RuntimeOrchestrator;
  close(): Promise<void>;
}

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Bileşim kökü (composition root): kasa → denetim anahtarı → denetim günlüğü → broker (+sandbox'lı
 * exec) → araç kaydı (yerel, skill, kubernetes) → politika → PEP. Tek kullanıcı, tek süreç.
 */
export async function createRuntime(o: RuntimeOptions): Promise<Runtime> {
  await ensureHome(o.paths);

  let store: SecretStore;
  if (o.store) store = o.store;
  else {
    if (!o.passphrase) throw new Error("kasa parolası sağlanmadı");
    store = await EncryptedFileStore.open(o.paths.vaultFile, o.passphrase, o.scryptParams ? { kdf: o.scryptParams } : {});
  }

  const known = new KnownSecrets();
  const auditKey = await ensureAuditKey(store);
  const audit = await AuditLog.open({
    storage: new FileAuditStorage(o.paths.auditLog),
    key: auditKey,
    anchor: new FileHeadAnchor(o.paths.auditAnchor),
    scrub: (s) => scrubText(s, known),
  });

  const sandbox = o.sandbox === "detect" || o.sandbox === undefined ? await detectSandbox() : o.sandbox;
  const broker = new LocalBroker({ store, exec: new ExecCredentialRunner({ sandbox, ...(o.now ? { now: o.now } : {}) }), ...(o.now ? { now: o.now } : {}) });
  const registry = await ProfileRegistry.open({ path: o.paths.profilesFile, testMode: false, ...(o.registryOptions ?? {}) });
  const profiles = new ProfileService({ store, registry });

  let policyDoc: PolicyDocument;
  if (o.policy) policyDoc = o.policy;
  else if (await exists(o.paths.policyFile)) policyDoc = await loadPolicyFile(o.paths.policyFile);
  else if (await exists(BUILTIN_POLICY_FILE)) policyDoc = await loadPolicyFile(BUILTIN_POLICY_FILE);
  else policyDoc = DEFAULT_POLICY;
  const policy = new PolicyEngine(policyDoc);

  const session = new Session();
  const evidence = new EvidenceStore();
  const toolRegistry = new ToolRegistry();
  const local = createLocalAdapter(evidence);
  toolRegistry.register(local.adapter, local.definitions);

  const adapter = new KubernetesAdapter(broker.resolver);
  toolRegistry.register(adapter, adapter.definitions);

  // Terminal servisi: yalnız iş alanı verildiyse VE OS sandbox varsa (aksi halde kabuk yok).
  const availableAdapters = ["kubernetes"];
  const classifiers: ((tool: string, args: unknown) => ReturnType<ReturnType<typeof shellCommandClassifier>>)[] = [];
  let terminalNote = "kapalı";
  if (o.workdir) {
    if (!sandbox || sandbox.kind === "none") {
      terminalNote = "devre dışı (OS sandbox yok)";
    } else {
      const workdir = await assertSafeWorkdir(o.workdir);
      let catalog: CommandCatalog = parseCatalog(await readFile(BUILTIN_CATALOG_FILE, "utf8"));
      if (await exists(o.paths.userCatalogFile)) catalog = mergeCatalogs(catalog, parseCatalog(await readFile(o.paths.userCatalogFile, "utf8")));
      const terminal = new TerminalAdapter({ sandbox, catalog, workdir });
      toolRegistry.register(terminal, terminal.definitions);
      classifiers.push(shellCommandClassifier(catalog, workdir));
      availableAdapters.push("terminal");
      terminalNote = `açık (${workdir})`;
    }
  }

  const skills = await SkillRegistry.load({ builtinDir: o.builtinSkillsDir ?? BUILTIN_SKILLS_DIR, userDir: o.paths.userSkillsDir });
  skills.setAvailableAdapters(availableAdapters);
  const skillAdapter = createSkillAdapter(skills, session, () => toolRegistry);
  toolRegistry.register(skillAdapter.adapter, skillAdapter.definitions);

  const gateway = new ToolGateway({
    registry: toolRegistry,
    session,
    policy,
    audit,
    broker,
    evidence,
    known,
    ...(classifiers.length ? { classifiers } : {}),
    ...(o.approval ? { approval: o.approval } : {}),
    ...(o.now ? { now: o.now } : {}),
  });

  await audit.append({
    event: "session_start",
    sessionId: session.id,
    policyVersionHash: policy.versionHash,
    message: `sandbox=${sandbox?.kind ?? "yok"} terminal=${terminalNote} skills=${skills.all().map((s) => s.name).join(",")}`,
  });

  const diagnoseProfile = async (id: string): Promise<{ report: DoctorReport; profile: Profile }> => {
    const profile: Profile | undefined = registry.get(id);
    if (!profile) throw new Error(`profil bulunamadı: ${id}`);
    if (profile.kind !== "k8s") throw new Error(`bu sürümde yalnız 'k8s' profilleri bağlanabilir: ${profile.kind}`);
    await broker.prime?.(profile, known);
    const lease = await broker.acquire({ profile, purpose: "doctor", callId: `doctor-${profile.id}`, ttlSec: 60 }, known);
    let report: DoctorReport;
    try {
      report = await adapter.doctor!(lease.handle, profile);
    } finally {
      await lease.release();
    }
    await audit.append({
      event: "lease",
      sessionId: session.id,
      profile: profile.id,
      environment: profile.environment,
      message: `doctor bindable=${report.bindable} effective=${report.effectiveClass ?? "?"} findings=${report.findings.map((f) => `${f.severity}:${f.code}`).join(",")}`,
    });
    return { report, profile };
  };

  let closed = false;
  const rt: Runtime = {
    paths: o.paths,
    store,
    known,
    audit,
    profiles,
    registry,
    broker,
    session,
    evidence,
    toolRegistry,
    gateway,
    policy,
    skills,
    adapter,
    sandbox,
    async diagnose(id: string): Promise<DoctorReport> {
      return (await diagnoseProfile(id)).report;
    },
    async bindProfile(id: string): Promise<DoctorReport> {
      const { report, profile } = await diagnoseProfile(id);
      if (report.bindable) session.bind(profile, { replace: true });
      return report;
    },
    createOrchestrator(provider, options) {
      return new Orchestrator({
        provider,
        gateway,
        registry: toolRegistry,
        session,
        evidence,
        policy,
        audit,
        known,
        skills,
        ...(options ? { options } : {}),
      });
    },
    createRuntimeOrchestrator(runtime) {
      // araç listesi görev başında sabitlendiğinden kullanılabilir skill'ler (en çok 2) önceden etkinleşir
      const preload = skills.all().slice(0, 2).map((sk) => ({ name: sk.name, tier: sk.tier, body: sk.body, tokens: sk.tokens, toolsets: sk.sidecar.requests.toolsets }));
      return new RuntimeOrchestrator({ runtime, gateway, registry: toolRegistry, session, evidence, policy, audit, known, skills, preloadSkills: preload });
    },
    async close() {
      if (closed) return;
      closed = true;
      await audit.append({ event: "session_end", sessionId: session.id, message: `toolCalls=${session.usage.toolCalls}` }).catch(() => undefined);
      broker.clearExecCache();
      if ("close" in store && typeof (store as { close?: unknown }).close === "function") (store as { close(): void }).close();
    },
  };
  return rt;
}
