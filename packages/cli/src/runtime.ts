import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { initSqlClassifier, mergeCatalogs, parseCatalog, shellCommandClassifier } from "@ops/classifiers";
import type { CommandCatalog } from "@ops/classifiers";
import { TerminalAdapter, assertSafeWorkdir } from "@ops/terminal";
import { KubernetesAdapter } from "@ops/adapter-kubernetes";
import { GithubActionsAdapter, GithubScmAdapter } from "@ops/adapter-github";
import { IacAdapter } from "@ops/adapter-iac";
import { McpBridgeAdapter, parseMcpManifest } from "@ops/mcp-bridge";
import { WorkspaceAdapter, WorkspaceManager, WorkspaceRegistry } from "@ops/workspace";
import { EMPTY_MASKING_CONFIG, PostgresAdapter, loadMaskingConfig, maskingRulesFor } from "@ops/adapter-postgres";
import type { MaskingConfig } from "@ops/adapter-postgres";
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
import { BreakGlassController, ChangeStore, EvidenceStore, Orchestrator, Quarantine, RuntimeOrchestrator, Session, ToolGateway, ToolRegistry, createChangeAdapter, createLocalAdapter, renderBreakGlassReview } from "@ops/core";
import type { QuarantineMode } from "@ops/core";
import { DEFAULT_POLICY, PolicyEngine, loadPolicyFile } from "@ops/policy";
import type { PolicyDocument } from "@ops/policy";
import { KnownSecrets, scrubText } from "@ops/redaction";
import { detectSandbox } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { SkillRegistry, createSkillAdapter } from "@ops/skills";
import { readAuditRecords } from "./backend.ts";
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
  /** Oturumun etkin IaC çalışma alanı (kayıtlı kimlik). Verilmezse `fs.*`/`iac.*` araçları çalışmaz ve terraform/ansible skill'leri gizli kalır. */
  readonly workspace?: string;
  /** IaC ikililerinin aranacağı dizinler (`OPS_TOOL_DIRS`); `PATH`'e güvenilmez. */
  readonly toolDirs?: readonly string[];
  /** Terraform/OpenTofu sağlayıcıları için yerel dosya aynası (`OPS_IAC_PROVIDER_MIRROR`). */
  readonly providerMirror?: string;
  readonly registryOptions?: Partial<ProfileRegistryOptions>;
  readonly now?: () => Date;
  /** `egress: local-only`: yalnız yerel sağlayıcı, yalnız okuma sınıfı, MCP köprüsü ve break-glass kapalı. */
  readonly localOnly?: boolean;
  /**
   * Karantina (§4.2): log/olay gibi ham serbest metin ana bağlama girmez. `digest`: yalnız deterministik tipli özet;
   * `model`: ek olarak araçsız, katı şemalı bir modelin sınıflandırması (`attachQuarantineProvider` ile bağlanır;
   * bağlanmazsa tipli özet).
   */
  readonly quarantine?: { readonly mode: Exclude<QuarantineMode, "off"> };
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
  readonly postgres: PostgresAdapter;
  readonly githubActions: GithubActionsAdapter;
  readonly githubScm: GithubScmAdapter;
  readonly workspaces: WorkspaceManager;
  readonly iac: IacAdapter;
  /** `mcp-servers.yaml` varsa MCP istemci köprüsü; yoksa `null`. */
  readonly mcp: McpBridgeAdapter | null;
  readonly sandbox: Sandbox | null;
  /** Geçici tavan yükseltme (break-glass); başlatma çağıranın yeniden kimlik doğrulama kanıtını ister. */
  readonly breakGlass: BreakGlassController;
  /** `model` karantina kipinde özetleyici sağlayıcıyı bağlar (host döngülü `generate` gerekir). */
  attachQuarantineProvider(provider: ModelProvider): void;
  /** Kanıtın redakte içeriği — YALNIZ kullanıcı ekranı için (karantinadaki ham log dahil); modele gitmez. */
  showEvidence(id: string): string;
  /** Karantinadaki kanıtı modele açar (denetim kaydı yazılır; yazılamazsa açılmaz). */
  releaseEvidence(id: string): Promise<string>;
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

  // ChangeSet: önerilen değişikliği kanıtlara bağlı yerel dosya olarak kaydeder (toolset 'change'; uygulamaz)
  const change = createChangeAdapter({ store: new ChangeStore(o.paths.changesDir), evidence, sessionId: () => session.id, ...(o.now ? { now: o.now } : {}) });
  toolRegistry.register(change.adapter, change.definitions);

  const adapter = new KubernetesAdapter(broker.resolver);
  toolRegistry.register(adapter, adapter.definitions);

  // PostgreSQL reader: SQL, PEP öncesi gerçek PostgreSQL ayrıştırıcısıyla AST allowlist'ten geçer.
  await initSqlClassifier();
  const masking: MaskingConfig = (await exists(o.paths.maskingFile)) ? await loadMaskingConfig(o.paths.maskingFile) : EMPTY_MASKING_CONFIG;
  const postgres = new PostgresAdapter(broker.resolver, { masking, ...(o.now ? { now: o.now } : {}) });
  toolRegistry.register(postgres, postgres.definitions);

  // CI/CD ve kaynak deposu (GitHub REST, yalnız GET)
  const githubActions = new GithubActionsAdapter(broker.resolver, { ...(o.now ? { now: o.now } : {}) });
  toolRegistry.register(githubActions, githubActions.definitions);
  const githubScm = new GithubScmAdapter(broker.resolver, { ...(o.now ? { now: o.now } : {}) });
  toolRegistry.register(githubScm, githubScm.definitions);

  // IaC (Terraform/OpenTofu, Ansible): çalışma alanı anlık kopyası + sandbox'lı araçlar. Araçlar her zaman
  // kayıtlıdır (toolset etkinleşene dek bağlama girmez); skill'ler yalnız etkin çalışma alanı varsa görünür.
  const workspaceRegistry = await WorkspaceRegistry.open(o.paths.workspacesFile);
  const workspaces = new WorkspaceManager({ registry: workspaceRegistry, worktreesDir: o.paths.worktreesDir, sandbox, known });
  const workspaceAdapter = new WorkspaceAdapter(workspaces);
  toolRegistry.register(workspaceAdapter, workspaceAdapter.definitions);
  const iac = new IacAdapter({ manager: workspaces, sandbox, ...(o.toolDirs ? { toolDirs: o.toolDirs } : {}), ...(o.providerMirror ? { providerMirror: o.providerMirror } : {}) });
  toolRegistry.register(iac, iac.definitions);

  // MCP istemci köprüsü v0: yalnız kullanıcı manifesti varsa. Geçersiz manifest = başlangıç hatası (fail-closed).
  let mcp: McpBridgeAdapter | null = null;
  if (!o.localOnly && (await exists(o.paths.mcpManifestFile))) {
    mcp = new McpBridgeAdapter({ manifest: parseMcpManifest(await readFile(o.paths.mcpManifestFile, "utf8")), sandbox, known });
    toolRegistry.register(mcp, mcp.definitions);
  }

  // Terminal servisi: yalnız iş alanı verildiyse VE OS sandbox varsa (aksi halde kabuk yok).
  const availableAdapters = ["kubernetes", "postgres", "github-actions", "github-scm"];
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
  const skillAdapter = createSkillAdapter(skills, session, () => toolRegistry);
  toolRegistry.register(skillAdapter.adapter, skillAdapter.definitions);

  // Etkin çalışma alanı: oturum kimliğiyle anlık kopya çıkarılır (yoksa/başarısızsa oturum BAŞLAMAZ).
  let workspaceNote = "yok";
  if (o.workspace) {
    const active = await workspaces.activate(o.workspace, session.id);
    availableAdapters.push("workspace", "iac", active.ws.engine === "ansible" ? "iac-ansible" : "iac-terraform");
    workspaceNote = `${active.ws.id} (${active.ws.engine})`;
  }
  if (mcp) availableAdapters.push("mcp-bridge");
  // Skill ilanı, YAPILANDIRILMIŞ profillere göre dinamiktir: profili olmayan adapter'ın skill'i ilan edilmez
  // (gereksiz meta token yok); çalışma alanı/terminal/MCP gibi profilsiz yetenekler sabit listeden gelir.
  const KIND_ADAPTER: Readonly<Record<string, string>> = { k8s: "kubernetes", db: "postgres", pipeline: "github-actions", scm: "github-scm" };
  const PROFILELESS = availableAdapters.filter((a) => !["kubernetes", "postgres", "github-actions", "github-scm"].includes(a));
  skills.setAvailabilityProvider(() => [...PROFILELESS, ...registry.list().flatMap((p) => (KIND_ADAPTER[p.kind] ? [KIND_ADAPTER[p.kind] as string] : []))]);

  const quarantine = o.quarantine ? new Quarantine({ mode: o.quarantine.mode }) : undefined;

  const gateway = new ToolGateway({
    registry: toolRegistry,
    session,
    policy,
    audit,
    broker,
    evidence,
    known,
    maskingFor: (tool, p) => (tool.profileKind === "db" && p ? maskingRulesFor(masking, p.id) : null),
    ...(classifiers.length ? { classifiers } : {}),
    ...(o.approval ? { approval: o.approval } : {}),
    ...(o.now ? { now: o.now } : {}),
    ...(o.localOnly ? { localOnly: true } : {}),
    ...(quarantine ? { quarantine } : {}),
  });

  await audit.append({
    event: "session_start",
    sessionId: session.id,
    policyVersionHash: policy.versionHash,
    message: `egress=${o.localOnly ? "local-only" : "normal"} quarantine=${o.quarantine?.mode ?? "off"} sandbox=${sandbox?.kind ?? "yok"} terminal=${terminalNote} workspace=${workspaceNote} mcp=${mcp ? mcp.definitions.length + " araç" : "kapalı"} skills=${skills.all().map((s) => s.name).join(",")}`,
  });

  const diagnoseWith = async (profile: Profile): Promise<{ report: DoctorReport; profile: Profile }> => {
    const doctorAdapter =
      profile.kind === "k8s" ? adapter : profile.kind === "db" ? postgres : profile.kind === "pipeline" ? githubActions : profile.kind === "scm" ? githubScm : null;
    if (!doctorAdapter) throw new Error(`bu sürümde yalnız 'k8s', 'db', 'pipeline' ve 'scm' profilleri bağlanabilir: ${profile.kind}`);
    await broker.prime?.(profile, known);
    const lease = await broker.acquire({ profile, purpose: "doctor", callId: `doctor-${profile.id}`, ttlSec: 60 }, known);
    let report: DoctorReport;
    try {
      report = await doctorAdapter.doctor!(lease.handle, profile);
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
  const diagnoseProfile = async (id: string): Promise<{ report: DoctorReport; profile: Profile }> => {
    const profile: Profile | undefined = registry.get(id);
    if (!profile) throw new Error(`profil bulunamadı: ${id}`);
    return diagnoseWith(profile);
  };

  // Break-glass: yükseltilmiş kopya, FİİLİ yetkiye karşı (doktor) sınanır; denetim yazılamazsa başlamaz.
  const breakGlass = new BreakGlassController({ session, audit, doctor: async (raised) => (await diagnoseWith(raised)).report, ...(o.now ? { now: o.now } : {}), ...(o.localOnly ? { disabledReason: "egress: local-only kipi yalnız okuma sınıfına izin verir" } : {}) });
  const sweeper = setInterval(() => void breakGlass.sweep(), 15_000);
  sweeper.unref();

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
    postgres,
    githubActions,
    githubScm,
    workspaces,
    iac,
    mcp,
    sandbox,
    breakGlass,
    attachQuarantineProvider(provider: ModelProvider): void {
      quarantine?.attachModel({ provider, audit, known, sessionId: () => session.id, onUsage: (u) => session.addModelUsage({ ...u, cacheReadTokens: 0 }) });
    },
    showEvidence(id: string): string {
      const e = evidence.get(id);
      if (!e) throw new Error(`kanıt bulunamadı: ${id}`);
      let body: string;
      try {
        const v: unknown = JSON.parse(e.text);
        body = typeof v === "string" ? v : JSON.stringify(v, null, 2);
      } catch {
        body = e.text;
      }
      const MAX_CHARS = 20_000;
      const shown = body.length > MAX_CHARS ? `${body.slice(0, MAX_CHARS)}\n…(${body.length - MAX_CHARS} karakter daha; kırpıldı)` : body;
      const flags = [e.quarantined ? (e.released ? "karantina: modele AÇIK" : "karantina: modele KAPALI") : null, e.taint === "untrusted" ? "güvenilmez içerik" : null].filter(Boolean).join(", ");
      return `── ${e.id} ${e.tool}${flags ? ` (${flags})` : ""} — yalnız sizin ekranınız, modele gitmedi ──\n${shown}`;
    },
    async releaseEvidence(id: string): Promise<string> {
      const e = evidence.get(id);
      if (!e) throw new Error(`kanıt bulunamadı: ${id}`);
      if (!e.quarantined) return `${id} karantinada değil (zaten modele açık veya tipli özetsiz)`;
      if (e.released) return `${id} zaten modele açık`;
      // Önce denetim (write-ahead): yazılamıyorsa içerik modele AÇILMAZ.
      await audit.append({ event: "evidence_release", sessionId: session.id, tool: e.tool, message: `${id} ham içeriği modele açıldı (${e.tokens} token tahmini)` });
      evidence.release(id);
      return `${id} (${e.tool}) ham içeriği modele AÇILDI; model evidence.get ile dilimleyebilir. Bağlam güvenilmez içerik aldığında tainted olur (mutasyon/başka profil okuması onay ister).`;
    },
    async diagnose(id: string): Promise<DoctorReport> {
      return (await diagnoseProfile(id)).report;
    },
    async bindProfile(id: string): Promise<DoctorReport> {
      const { report, profile } = await diagnoseProfile(id);
      if (report.bindable) {
        // Yeniden bağlama / başka profile geçiş: aynı türdeki etkin break-glass biter (yükseltme taşınmaz).
        const cur = session.boundByKind(profile.kind);
        if (cur && session.breakGlass.has(cur.id)) await breakGlass.end(cur.id, "rebind");
        session.bind(profile, { replace: true });
      }
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
      // Öncelik: bağlı profil türlerinin adapter'ını gerektiren skill'ler; sonra genel teşhis; en çok 2.
      // Her görevin başında hesaplanır (profiller sohbet sırasında bağlanır).
      const adapterOfKind: Record<string, string> = { k8s: "kubernetes", db: "postgres", pipeline: "github-actions", scm: "github-scm" };
      const preload = (): { name: string; tier: Parameters<Session["activateSkill"]>[0]["tier"]; body: string; tokens: number; toolsets: string[] }[] => {
        const bound = new Set(session.boundProfiles().map((p) => adapterOfKind[p.kind]).filter((x): x is string => x !== undefined));
      // etkin çalışma alanı varsa IaC skill'i (motoruna uyan) önceliklidir
      const ws = workspaces.current();
      if (ws) for (const t of ["workspace", "iac", ws.ws.engine === "ansible" ? "iac-ansible" : "iac-terraform"]) bound.add(t);
        const rank = (sk: ReturnType<typeof skills.all>[number]): number =>
          sk.sidecar.requires.adapters.some((a) => bound.has(a)) ? 0 : sk.name === "generic-diagnosis" ? 1 : 2;
        return [...skills.all()]
          .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name))
          .slice(0, 2)
          .map((sk) => ({ name: sk.name, tier: sk.tier, body: sk.body, tokens: sk.tokens, toolsets: sk.sidecar.requests.toolsets }));
      };
      return new RuntimeOrchestrator({ runtime, gateway, registry: toolRegistry, session, evidence, policy, audit, known, skills, preloadSkills: preload });
    },
    async close() {
      if (closed) return;
      closed = true;
      clearInterval(sweeper);
      await breakGlass.endAll("session_end");
      // İnceleme dosyası denetim kayıtlarından üretilir (hash zinciriyle korunan kaynak).
      try {
        const md = renderBreakGlassReview(await readAuditRecords(o.paths.auditLog), session.id);
        if (md) {
          await mkdir(o.paths.breakGlassDir, { recursive: true, mode: 0o700 });
          await writeFile(join(o.paths.breakGlassDir, `${session.id}.md`), md, { mode: 0o600 });
        }
      } catch {
        /* inceleme dosyası yazılamadıysa kayıtlar denetimde zaten durur */
      }
      await audit.append({ event: "session_end", sessionId: session.id, message: `toolCalls=${session.usage.toolCalls}` }).catch(() => undefined);
      broker.clearExecCache();
      if ("close" in store && typeof (store as { close?: unknown }).close === "function") (store as { close(): void }).close();
    },
  };
  return rt;
}
