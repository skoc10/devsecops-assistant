import { readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import type { Readable, Writable } from "node:stream";
import { generateReadOnlyRbac } from "@ops/adapter-kubernetes";
import { FileAuditStorage, FileHeadAnchor, verifyAudit } from "@ops/audit";
import { ensureAuditKey, scanAmbientCredentials, scanAmbientEnv, writeFileAtomic } from "@ops/broker";
import { ENVIRONMENTS, OpsError, RISK_CLASSES } from "@ops/contracts";
import type { Environment, ModelProvider, RiskClass, SecretStore } from "@ops/contracts";
import { ChangeStore, breakGlassBanner, buildReplay, formatUsage, lastSessionId, renderBreakGlassReview, renderReplay, usageFromAudit } from "@ops/core";
import type { WhatIfDeps } from "@ops/core";
import { McpBridgeAdapter, parseMcpManifest } from "@ops/mcp-bridge";
import { stripControlChars } from "@ops/redaction";
import { WORKSPACE_ENGINES, WorkspaceManager, WorkspaceRegistry } from "@ops/workspace";
import type { WorkspaceEngine } from "@ops/workspace";
import { PolicyEngine, explainReason, loadPolicyFile, parsePolicy } from "@ops/policy";
import { detectSandbox, detectSandboxDetailed, VmSandbox, loadVmState } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { RunbookRegistry, lintSkillRoot, renderLint } from "@ops/skills";
import { readAuditRecords, LocalBackend } from "./backend.ts";
import type { Sender } from "./backend.ts";
import { OpsdClient } from "./client.ts";
import { renderDoctor, runChat } from "./chat.ts";
import { TtyApprovalGate, openDevTty, openDevTtyRaw } from "./approval.ts";
import type { TtyIo } from "./approval.ts";
import { parseDurationSec, reauthVaultPassphrase } from "./reauth.ts";
import { DEFAULT_ALLOW_TTL_SEC, addRuleToText, buildAllowRule, parseTtlSec, policyHash, removeRuleFromText, renderPolicyDiff, renderRuleList } from "./policy-edit.ts";
import { Opsd } from "./opsd.ts";
import { BUILTIN_POLICY_FILE, BUILTIN_SKILLS_DIR, ensureHome } from "./paths.ts";
import type { OpsPaths } from "./paths.ts";
import { readPassphrase } from "./prompt.ts";
import { registerBuiltinProviders } from "./builtin-providers.ts";
import { createProvider, isAgentRuntime, providerKeyName, providerNames } from "./providers.ts";
import type { ProviderFactory } from "./providers.ts";
import { createRuntime } from "./runtime.ts";
import type { Runtime } from "./runtime.ts";
import { guestToolVersions, vmCommand } from "./vm.ts";

export interface CliEnv {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly io: { readonly input: Readable & { isTTY?: boolean; setRawMode?: (m: boolean) => void }; readonly output: Writable; readonly error: Writable };
  readonly paths: OpsPaths;
  readonly scryptParams?: { N: number; r: number; p: number };
  /** Hazır kasa (test / OS anahtar zinciri). */
  readonly store?: SecretStore;
  readonly sandbox?: Sandbox | null | "detect";
  /** Test: sağlayıcıyı doğrudan ver. */
  readonly provider?: ModelProvider;
  readonly providerFactory?: ProviderFactory;
  /** `shell.run` iş alanı (varsayılan: OPS_WORKDIR). */
  readonly workdir?: string;
  /** Etkin IaC çalışma alanı (varsayılan: `--workspace` / OPS_WORKSPACE). */
  readonly workspace?: string;
  /** Onay kapısı (test: sahte TTY). Varsayılan: `/dev/tty`; açılamazsa onay REDDEDİLİR. */
  readonly approval?: TtyApprovalGate;
  /** `daemon` komutunun beklemesini durduran sinyal (test). */
  readonly stop?: AbortSignal;
  /** `egress: local-only` (varsayılan: OPS_EGRESS=local-only): yalnız yerel sağlayıcı + yalnız okuma. */
  readonly localOnly?: boolean;
  /** Karantina kipi (varsayılan: OPS_QUARANTINE): ham log/olay modele girmez, tipli özet gider. */
  readonly quarantine?: "off" | "digest" | "model";
  /** Kontrol terminali (yeniden kimlik doğrulama, politika düzenleme onayı). Varsayılan `/dev/tty`; açılamazsa işlem REDDEDİLİR. */
  readonly openTty?: () => Promise<TtyIo | null>;
  /** Test: kasa parolası doğrulayıcı (varsayılan: kasa dosyasına karşı). */
  readonly reauthVerify?: (passphrase: Uint8Array) => Promise<boolean>;
}

const USAGE = [
  "kullanım: ops <komut>",
  "  init                               OPS_HOME ve kasayı oluştur",
  "  profile add k8s --id ID --kubeconfig YOL --env dev|stage|prod|sandbox [--context C] [--scope a,b] [--ceiling read]",
  "              [--name AD] [--ambient-env ADLAR] [--ambient-path DİZİN] [--allow-external-token-file]  (kubeconfig dizini dışındaki tokenFile yalnız bu açık izinle)",
  "  profile add db --id ID --env E --host H [--port 5432] --database D --user U --scope public,sales [--ca-file PEM] [--ceiling read|mutate|deploy|destroy]  (read olmayan tavan = writer profili)",
  "              [--default-schema S] [--datasource AD] [--name AD] [--tls verify-full|disable] [--replace]",
  "              (parola: OPS_DB_PASSWORD_FILE ile 0600 dosya veya yankısız TTY istemi; bağlantı DİZESİ kabul edilmez)",
  "  profile add pipeline|scm --id ID --env E --scope sahip/depo,sahip/* [--api-url https://api.github.com] [--ca-file PEM] [--ceiling read|mutate|deploy]",
  "              [--log-hosts h1,h2] [--name AD] [--replace]   (belirteç: OPS_GITHUB_TOKEN_FILE ile 0600 dosya veya yankısız TTY; salt okunur fine-grained belirteç önerilir)",
  "  profile list | rm ID | doctor ID",
  "  profile rbac --sa-namespace NS --namespace a,b [--cluster-read] [--name AD]   (manifest üretir, UYGULAMAZ)",
  "  doctor                             ortam kimlikleri ve sandbox durumu (VM kipinde konuk araç sürümleri)",
  "  vm up|status|halt|destroy|reload   macOS sandbox VM'i (Vagrant + Linux + bubblewrap; ADR-0011) — VM yalnız bu komutlarla başlar",
  "  audit verify                       denetim zincirini doğrula",
  "  usage                              token kullanım raporu (denetimden)",
  "  replay [--session ID] [--policy DOSYA|current] [--verbose] [--json]   denetimden oturum incelemesi: eylem zaman çizelgesi + tutarlılık denetimi; --policy ile kayıtlı kararlar aday politikayla yeniden değerlendirilir (araç/model ÇAĞRILMAZ)",
  "  explain-policy [--last N | --code KOD]   reddedilen/sorulan çağrıları açıkla",
  "  provider list | set-key AD         sağlayıcıları listele / API anahtarını kasaya yaz (OPS_PROVIDER_KEY_FILE veya TTY)",
  "  workspace add --id ID --path DİZİN --engine terraform|opentofu|ansible [--write-paths g1,g2] [--deny-paths g1,g2] [--replace]",
  "  workspace list | rm ID | snapshots [ID]",
  "  workspace diff ID [--session S] [--path P]      ajanın değişiklikleri (anlık kopya ↔ özgün HEAD)",
  "  workspace export ID --out DOSYA [--session S]   değişiklikleri `git apply` ile uygulanabilir yama olarak yaz (depoya YAZMAZ)",
  "  change list | show ID | export ID --out DOSYA   ajanın önerdiği değişiklikler (ChangeSet); uygulamak size aittir",
  "  skill lint [DİZİN...] [--builtin] [--strict] [--json]   skill denetimi (B-02): ad/boyut/ön bilgi, görünmez Unicode, enjeksiyon/curl|sh/dış URL sezgileri, scripts/ hash'leri, pin için skill hash'i (varsayılan: OPS_HOME/skills)",
  "  runbook list | lint               OPS_HOME/runbooks/<ad>.md runbook'ları (numaralı adımlar, `araç {json}` çağrıları) ve geçersiz olanların sebebi",
  "  mcp check [SUNUCU]                 OPS_HOME/mcp-servers.yaml sunucularını sandbox'ta başlatıp manifestle karşılaştır (araç çağırmaz)",
  "  break-glass --profile ID --ceiling mutate|deploy|destroy --ttl 30m --reason \"…\"   çalışan opsd oturumunda GEÇİCİ tavan yükseltme (yeniden kimlik doğrulama; sohbette /breakglass da olur)",
  "  break-glass end --profile ID | status | review [--session S]",
  "  policy list | allow --tool T --profile P [--scope a,b] [--ttl 8h] | add --effect ask|deny --id ID [--tool T --profile P --environment e,.. --class c,..] | rm ID   politika düzenleme (diff + TTY onayı + denetim)",
  "  daemon [--workspace ID] [--local-only] [--quarantine digest|model]   opsd'yi başlat (UDS)",
  "  chat [--embedded] [--workspace ID] [--local-only] [--quarantine digest|model]   sohbet (opsd'ye bağlanır; --embedded süreç içi). --local-only / OPS_EGRESS=local-only: yalnız yerel model + yalnız okuma",
  "  (ortam) OPS_PROVIDER_SMALL_MODEL=MODEL  küçük kademe: tüm etkin skill'ler `model_hint: small` diyorsa tur bu modelle yürür (aksi halde ana model)",
  "  (ortam) OPS_QUARANTINE=digest|model  ham log/olay modele GİRMEZ, tipli özet gider (ham: sohbette /show, /raw); model: ek olarak araçsız şemalı model sınıflaması (OPS_QUARANTINE_MODEL=küçük model)",
  "  (ortam) OPS_WORKDIR=DİZİN          shell.run iş alanı (salt-okunur; OS sandbox gerekir; ev dizini olamaz)",
  "  (ortam) OPS_WORKSPACE=ID           etkin IaC çalışma alanı; OPS_TOOL_DIRS=d1:d2 terraform/tofu/ansible dizinleri; OPS_IAC_PROVIDER_MIRROR=DİZİN yerel sağlayıcı aynası",
  "  (ortam) OPS_SANDBOX=vm|bwrap|none  sandbox seçimi (varsayılan: Linux bwrap, macOS VM varsa VM); OPS_VM_DIR=DİZİN VM durum dizini (varsayılan OPS_HOME/vm)",
].join("\n");

const out = (c: CliEnv, s: string): void => void c.io.output.write(`${s}\n`);
const err = (c: CliEnv, s: string): void => void c.io.error.write(`${s}\n`);

const QUARANTINE_MODES = ["off", "digest", "model"] as const;
/** `--quarantine MOD` > `CliEnv.quarantine` > OPS_QUARANTINE; geçersiz değer = hata (sessizce kapatma YOK). */
function quarantineMode(c: CliEnv, flag?: string): "digest" | "model" | undefined {
  const v = flag ?? c.quarantine ?? c.env["OPS_QUARANTINE"];
  if (v === undefined || v === "" || v === "off") return undefined;
  if (!(QUARANTINE_MODES as readonly string[]).includes(v)) throw new OpsError("usage", `--quarantine / OPS_QUARANTINE şunlardan biri olmalı: ${QUARANTINE_MODES.join(", ")}`);
  return v as "digest" | "model";
}

/** `OPS_EGRESS`: yalnız `normal` | `local-only`. Yazım hatası (ör. `local_only`) sessizce NORMAL kipe düşmez: açık hata. */
function isLocalOnly(c: CliEnv, flag?: boolean): boolean {
  const e = c.env["OPS_EGRESS"];
  if (e !== undefined && e !== "" && e !== "normal" && e !== "local-only") throw new OpsError("usage", `OPS_EGRESS 'normal' veya 'local-only' olmalı (verilen: '${stripControlChars(e).slice(0, 20)}')`);
  return flag === true || c.localOnly === true || e === "local-only";
}

async function withRuntime<T>(c: CliEnv, fn: (rt: Runtime) => Promise<T>, approval?: TtyApprovalGate, workspace?: string, localOnly?: boolean, quarantine?: "digest" | "model"): Promise<T> {
  const ws = workspace ?? c.workspace ?? c.env["OPS_WORKSPACE"];
  const toolDirs = c.env["OPS_TOOL_DIRS"]?.split(":").filter(Boolean);
  const rt = await createRuntime({
    paths: c.paths,
    ...(ws ? { workspace: ws } : {}),
    ...(toolDirs?.length ? { toolDirs } : {}),
    ...(c.env["OPS_IAC_PROVIDER_MIRROR"] ? { providerMirror: c.env["OPS_IAC_PROVIDER_MIRROR"] } : {}),
    ...(approval ? { approval } : {}),
    ...(isLocalOnly(c, localOnly) ? { localOnly: true } : {}),
    ...(quarantine ? { quarantine: { mode: quarantine } } : {}),
    ...(c.store ? { store: c.store } : { passphrase: () => readPassphrase(c.env, c.io) }),
    ...(c.scryptParams ? { scryptParams: c.scryptParams } : {}),
    ...(c.sandbox !== undefined ? { sandbox: c.sandbox } : {}),
    ...(c.workdir ?? c.env["OPS_WORKDIR"] ? { workdir: (c.workdir ?? c.env["OPS_WORKDIR"]) as string } : {}),
  });
  try {
    return await fn(rt);
  } finally {
    await rt.close();
  }
}

registerBuiltinProviders();

/** Yapılandırılan sağlayıcıya göre host döngülü veya sağlayıcı döngülü orkestratör. */
async function engineFor(c: CliEnv, rt: Runtime, localOnly?: boolean, quarantine?: "digest" | "model"): Promise<Sender> {
  const lo = isLocalOnly(c, localOnly);
  const ctx = { env: c.env, store: rt.store, known: rt.known, sandbox: rt.sandbox };
  const sel = c.provider ?? (await (c.providerFactory ?? createProvider)(ctx));
  if (lo) {
    // Sağlayıcı seçimi sırasında erken ret (PEP ayrıca her çağrıda zorlar): bağlam bulut modele HİÇ gitmez.
    if (isAgentRuntime(sel)) throw new OpsError("local_only", "egress: local-only kipinde sağlayıcı-döngülü çalışma zamanı (Cursor) kullanılamaz: model barındırması dış");
    if (sel.capabilities.trustZone !== "local") throw new OpsError("local_only", `egress: local-only kipinde yalnız yerel (local) sağlayıcı kullanılır; '${sel.id}' bölgesi '${sel.capabilities.trustZone}'. Yerel uç için OPS_PROVIDER_BASE_URL=http://127.0.0.1:… ayarlayın`);
  }
  if (quarantine === "model" && !isAgentRuntime(sel)) {
    // Karantina özetleyicisi: AYRI bir sağlayıcı örneği (ana örneğin konuşma durumu — ör. Anthropic'in düşünme bloğu
    // izleyicisi — özetleyici çağrılarıyla bozulmasın); OPS_QUARANTINE_MODEL ile aynı sağlayıcının küçük kademesi.
    let qp: ModelProvider = sel;
    const qm = c.env["OPS_QUARANTINE_MODEL"];
    if (!c.provider) {
      const made = await (c.providerFactory ?? createProvider)({ ...ctx, env: { ...c.env, ...(qm ? { OPS_PROVIDER_MODEL: qm, OPS_PROVIDER_TIER: "small" } : {}) } });
      if (isAgentRuntime(made)) throw new OpsError("usage", "karantina özetleyicisi ana model döngülü bir sağlayıcıyla kullanılamaz");
      qp = made;
    }
    if (lo && qp.capabilities.trustZone !== "local") throw new OpsError("local_only", "egress: local-only kipinde karantina özetleyicisi de yerel olmalı");
    rt.attachQuarantineProvider(qp);
  }
  if (isAgentRuntime(sel)) return rt.createRuntimeOrchestrator(sel);
  // Küçük kademe (opt-in): OPS_PROVIDER_SMALL_MODEL ile aynı sağlayıcının ucuz modeli; yalnız tüm etkin skill'ler
  // `model_hint: small` diyorsa kullanılır (yerleşik skill'lerin hepsi `large`).
  let small: ModelProvider | undefined;
  const sm = c.env["OPS_PROVIDER_SMALL_MODEL"];
  if (sm && !c.provider) {
    const made = await (c.providerFactory ?? createProvider)({ ...ctx, env: { ...c.env, OPS_PROVIDER_MODEL: sm, OPS_PROVIDER_TIER: "small" } });
    if (isAgentRuntime(made)) throw new OpsError("usage", "OPS_PROVIDER_SMALL_MODEL ana model döngülü bir sağlayıcıyla kullanılamaz");
    if (lo && made.capabilities.trustZone !== "local") throw new OpsError("local_only", "egress: local-only kipinde küçük kademe sağlayıcı da yerel olmalı");
    small = made;
  }
  return rt.createOrchestrator(sel, undefined, small);
}

const list = (v: string | undefined): string[] => (v ? v.split(",").map((x) => x.trim()).filter(Boolean) : []);

async function addDatabaseProfile(c: CliEnv, args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" }, env: { type: "string" }, host: { type: "string" }, port: { type: "string" }, database: { type: "string" }, user: { type: "string" },
      scope: { type: "string" }, "ca-file": { type: "string" }, "default-schema": { type: "string" }, datasource: { type: "string" }, name: { type: "string" },
      tls: { type: "string" }, ceiling: { type: "string" }, replace: { type: "boolean" },
    },
    strict: true,
  });
  if (!values.id || !values.env || !values.host || !values.database || !values.user || !values.scope) {
    throw new OpsError("usage", "--id, --env, --host, --database, --user ve --scope gerekli (bağlantı dizesi kabul edilmez)");
  }
  if (!ENVIRONMENTS.includes(values.env as Environment)) throw new OpsError("usage", `--env şunlardan biri olmalı: ${ENVIRONMENTS.join(", ")}`);
  if (values.tls !== undefined && values.tls !== "verify-full" && values.tls !== "disable") throw new OpsError("usage", "--tls verify-full veya disable olmalı");
  const port = values.port === undefined ? undefined : Number(values.port);
  if (port !== undefined && !Number.isInteger(port)) throw new OpsError("usage", "--port tam sayı olmalı");
  const caPem = values["ca-file"] ? await readFile(values["ca-file"], "utf8") : undefined;
  const pwBytes = await readPassphrase(c.env, c.io, "Veritabanı parolası: ", "OPS_DB_PASSWORD_FILE");
  const password = Buffer.from(pwBytes).toString("utf8");
  pwBytes.fill(0);
  const res = await withRuntime(c, (rt) =>
    rt.profiles.addDatabase({
      id: values.id as string,
      environment: values.env as Environment,
      host: values.host as string,
      database: values.database as string,
      user: values.user as string,
      password,
      allowedScopes: list(values.scope),
      ...(port !== undefined ? { port } : {}),
      ...(caPem !== undefined ? { caPem } : {}),
      ...(values.tls ? { tlsMode: values.tls as "verify-full" | "disable" } : {}),
      ...(values["default-schema"] ? { defaultSchema: values["default-schema"] } : {}),
      ...(values.datasource ? { datasource: values.datasource } : {}),
      ...(values.name ? { displayName: values.name } : {}),
      ...(values.ceiling ? { classCeiling: values.ceiling as RiskClass } : {}),
      ...(values.replace ? { replace: true } : {}),
    }),
  );
  out(c, `Profil eklendi: ${res.profile.id} (${res.profile.environment}, ${res.profile.attributes["role"] ?? "reader"}, şemalar ${res.profile.allowedScopes.join("|")}, çıktı bölgesi ${res.profile.egressClass})`);
  for (const w of res.warnings) out(c, `⚠ ${w}`);
  out(c, "Parola yalnız kasada. `ops profile doctor` rolün fiili yetkilerini sınar (yazma/CREATE/süper yetki varsa profil bağlanmaz). Maskeli sütunlar için OPS_HOME/masking.yaml.");
  return 0;
}

async function addTokenProfile(c: CliEnv, kind: "pipeline" | "scm", args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" }, env: { type: "string" }, scope: { type: "string" }, "api-url": { type: "string" }, "ca-file": { type: "string" },
      "log-hosts": { type: "string" }, name: { type: "string" }, ceiling: { type: "string" }, replace: { type: "boolean" },
    },
    strict: true,
  });
  if (!values.id || !values.env || !values.scope) throw new OpsError("usage", "--id, --env ve --scope gerekli");
  if (!ENVIRONMENTS.includes(values.env as Environment)) throw new OpsError("usage", `--env şunlardan biri olmalı: ${ENVIRONMENTS.join(", ")}`);
  const caPem = values["ca-file"] ? await readFile(values["ca-file"], "utf8") : undefined;
  const tokBytes = await readPassphrase(c.env, c.io, "GitHub belirteci: ", "OPS_GITHUB_TOKEN_FILE");
  const token = Buffer.from(tokBytes).toString("utf8");
  tokBytes.fill(0);
  const res = await withRuntime(c, (rt) =>
    rt.profiles.addToken({
      id: values.id as string,
      kind,
      environment: values.env as Environment,
      apiBase: values["api-url"] ?? "https://api.github.com",
      token,
      allowedScopes: list(values.scope),
      ...(caPem !== undefined ? { caPem } : {}),
      ...(values["log-hosts"] ? { attributes: { logHosts: list(values["log-hosts"]).join(",") } } : {}),
      ...(values.name ? { displayName: values.name } : {}),
      ...(values.ceiling ? { classCeiling: values.ceiling as RiskClass } : {}),
      ...(values.replace ? { replace: true } : {}),
    }),
  );
  out(c, `Profil eklendi: ${res.profile.id} (${kind}, ${res.profile.environment}, depolar ${res.profile.allowedScopes.join("|")}, çıktı bölgesi ${res.profile.egressClass})`);
  for (const w of res.warnings) out(c, `⚠ ${w}`);
  out(c, "Belirteç yalnız kasada. `ops profile doctor` belirtecin çalıştığını ve klasik belirteçlerde yazma kapsamı olmadığını sınar; fine-grained belirteç izinleri API'den doğrulanamaz.");
  return 0;
}

async function workspaceCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  const registry = await WorkspaceRegistry.open(c.paths.workspacesFile);
  const manager = new WorkspaceManager({ registry, worktreesDir: c.paths.worktreesDir, sandbox: null });
  switch (sub) {
    case "add": {
      const { values } = parseArgs({ args: rest, options: { id: { type: "string" }, path: { type: "string" }, engine: { type: "string" }, "write-paths": { type: "string" }, "deny-paths": { type: "string" }, replace: { type: "boolean" } }, strict: true });
      if (!values.id || !values.path || !values.engine) throw new OpsError("usage", "--id, --path ve --engine gerekli");
      if (!WORKSPACE_ENGINES.includes(values.engine as WorkspaceEngine)) throw new OpsError("usage", `--engine şunlardan biri olmalı: ${WORKSPACE_ENGINES.join(", ")}`);
      const ws = await registry.add(
        { id: values.id, path: resolve(values.path), engine: values.engine as WorkspaceEngine, ...(values["write-paths"] ? { writePaths: list(values["write-paths"]) } : {}), ...(values["deny-paths"] ? { denyPaths: list(values["deny-paths"]) } : {}) },
        { ...(values.replace ? { replace: true } : {}), ...(c.env["HOME"] ? { home: c.env["HOME"] } : {}) },
      );
      out(c, `Çalışma alanı kaydedildi: ${ws.id} (${ws.engine}, ${ws.path})`);
      if (await loadVmState(c.paths.vmDir).catch(() => null)) out(c, "Sandbox VM'i kurulu: deponun konukta salt-okunur görünmesi için `ops vm reload` çalıştırın (paylaşımlar açılışta bağlanır).");
      out(c, "Ajan deponuza YAZMAZ: her oturumda HEAD'in anlık kopyasında çalışır. Değişiklikleri `ops workspace diff/export` ile alırsınız. State, tfvars, .env, anahtar ve CI tanımı dosyaları kopyalanmaz/yazılamaz.");
      return 0;
    }
    case "list": {
      const rows = registry.list();
      out(c, rows.length === 0 ? "(çalışma alanı yok)" : rows.map((w) => `${w.id}\t${w.engine}\t${w.path}\tyazılabilir ${w.writePaths.join("|")}\tek yasak ${w.denyPaths.join("|") || "-"}`).join("\n"));
      return 0;
    }
    case "rm": {
      const id = rest[0];
      if (!id) throw new OpsError("usage", "kullanım: ops workspace rm ID");
      const removed = await registry.remove(id);
      out(c, removed ? `Kayıt silindi: ${id} (anlık kopyalar ${c.paths.worktreesDir} altında kalır; elle silebilirsiniz)` : `Bulunamadı: ${id}`);
      return removed ? 0 : 1;
    }
    case "snapshots": {
      const snaps = await manager.snapshots(rest[0]);
      out(c, snaps.length === 0 ? "(anlık kopya yok)" : snaps.map((x) => `${x.workspaceId}\toturum ${x.sessionId}\t${x.createdAt}\tHEAD ${x.head.slice(0, 12)}`).join("\n"));
      return 0;
    }
    case "diff":
    case "export": {
      const { values, positionals } = parseArgs({ args: rest, options: { session: { type: "string" }, path: { type: "string" }, out: { type: "string" } }, allowPositionals: true, strict: true });
      const id = positionals[0];
      if (!id) throw new OpsError("usage", `kullanım: ops workspace ${sub} ID${sub === "export" ? " --out DOSYA" : ""} [--session S]`);
      const { info, fs } = await manager.openSnapshot(id, values.session);
      const { changes, patch } = await fs.changes(sub === "diff" ? values.path : undefined);
      if (sub === "diff") {
        out(c, `# ${info.workspaceId} oturum ${info.sessionId} (HEAD ${info.head.slice(0, 12)}): ${changes.length} dosya değişti`);
        for (const ch of changes) out(c, `#   ${ch.status === "added" ? "+" : "~"} ${ch.path}  (+${ch.additions} -${ch.deletions})`);
        if (patch !== "") out(c, stripControlChars(patch).trimEnd());
        return 0;
      }
      if (!values.out) throw new OpsError("usage", "--out DOSYA gerekli");
      if (changes.length === 0) {
        out(c, "Değişiklik yok; yama yazılmadı.");
        return 0;
      }
      await writeFile(values.out, patch, { flag: "wx", mode: 0o600 }).catch((e: NodeJS.ErrnoException) => {
        throw new OpsError("export_failed", e.code === "EEXIST" ? "hedef dosya zaten var (üzerine yazılmaz)" : `yazılamadı: ${e.code ?? "?"}`);
      });
      out(c, `${changes.length} dosyalık yama yazıldı: ${values.out}`);
      out(c, `Depoda HEAD ${info.head.slice(0, 12)} üzerinde: git apply --check ${values.out} && git checkout -b ops/${info.workspaceId} && git apply ${values.out}`);
      out(c, "Yamayı UYGULAMADAN önce gözden geçirin (ops workspace diff). Uygulama ve PR sizin elinizdedir.");
      return 0;
    }
    default:
      throw new OpsError("usage", "workspace alt komutu: add | list | rm | snapshots | diff | export");
  }
}

/** `ops skill lint [DİZİN...] [--builtin] [--strict] [--json]`: dosya sistemi denetimi; kasa/oturum GEREKTİRMEZ. */
async function skillCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  if (sub !== "lint") throw new OpsError("usage", "skill alt komutu: lint [DİZİN...] [--builtin] [--strict] [--json]");
  const { values, positionals } = parseArgs({ args: rest, options: { builtin: { type: "boolean" }, strict: { type: "boolean" }, json: { type: "boolean" } }, allowPositionals: true, strict: true });
  const roots = [...positionals.map((p) => resolve(p)), ...(values.builtin ? [BUILTIN_SKILLS_DIR] : []), ...(positionals.length === 0 && !values.builtin ? [c.paths.userSkillsDir] : [])];
  const results = (await Promise.all(roots.map((r) => lintSkillRoot(r)))).flat();
  if (values.json) out(c, JSON.stringify(results, null, 2));
  else out(c, results.length === 0 ? `(skill bulunamadı: ${roots.join(", ")})` : stripControlChars(renderLint(results)));
  const bad = results.some((r) => !r.ok) || (values.strict === true && results.some((r) => r.findings.some((f) => f.severity === "warn")));
  return bad ? 1 : 0;
}

/** `ops runbook list`: OPS_HOME/runbooks altındaki runbook'lar ve geçersiz olanların sebebi (kasa/oturum gerektirmez). */
async function runbookCommand(c: CliEnv, sub: string | undefined): Promise<number> {
  if (sub !== "list" && sub !== "lint") throw new OpsError("usage", "runbook alt komutu: list | lint");
  const reg = await RunbookRegistry.load(c.paths.runbooksDir);
  for (const r of reg.all()) {
    out(c, `${r.name}\t${r.steps.length} adım (${r.steps.filter((s) => s.tool).length} araç)\t${stripControlChars(r.title).slice(0, 80)}`);
  }
  for (const i of reg.issues) out(c, `✗ ${stripControlChars(i.file)}: ${stripControlChars(i.problem)}`);
  if (reg.count === 0 && reg.issues.length === 0) out(c, `(runbook yok: ${c.paths.runbooksDir}/<ad>.md)`);
  return reg.issues.length > 0 ? 1 : 0;
}

async function changeCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  const store = new ChangeStore(c.paths.changesDir);
  if (sub === "list") {
    const all = await store.list();
    out(c, all.length === 0 ? "(değişiklik önerisi yok)" : all.map((x) => `${x.id}\t${x.kind}\t${x.createdAt}\t${stripControlChars(x.title).slice(0, 80)}`).join("\n"));
    return 0;
  }
  if (sub === "show" || sub === "export") {
    const { values, positionals } = parseArgs({ args: rest, options: { out: { type: "string" } }, allowPositionals: true, strict: true });
    const id = positionals[0];
    if (!id) throw new OpsError("usage", `kullanım: ops change ${sub} ID${sub === "export" ? " --out DOSYA" : ""}`);
    const { changeSet: cs, content } = await store.get(id);
    if (sub === "show") {
      out(c, `# ${stripControlChars(cs.title)}  [${cs.kind}]  ${cs.id}  (${cs.createdAt}, oturum ${cs.sessionId})`);
      out(c, stripControlChars(cs.summary));
      for (const e of cs.evidence) out(c, `kanıt ${e.id} (${e.tool}): ${stripControlChars(e.summary).slice(0, 160)}`);
      if (cs.rollback) out(c, `geri alma: ${stripControlChars(cs.rollback)}`);
      out(c, `--- ${cs.file.name} (sha256 ${cs.file.sha256.slice(0, 12)}…, ${cs.file.bytes} bayt) ---`);
      out(c, stripControlChars(content).trimEnd());
      return 0;
    }
    if (!values.out) throw new OpsError("usage", "--out DOSYA gerekli");
    await writeFile(values.out, content, { flag: "wx", mode: 0o600 }).catch((e: NodeJS.ErrnoException) => {
      throw new OpsError("export_failed", e.code === "EEXIST" ? "hedef dosya zaten var (üzerine yazılmaz)" : `yazılamadı: ${e.code ?? "?"}`);
    });
    out(c, `${cs.file.name} (${cs.file.bytes} bayt) yazıldı: ${values.out}`);
    return 0;
  }
  throw new OpsError("usage", "change alt komutu: list | show | export");
}

async function mcpCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  if (sub !== "check") throw new OpsError("usage", "kullanım: ops mcp check [SUNUCU]");
  let text: string;
  try {
    text = await readFile(c.paths.mcpManifestFile, "utf8");
  } catch {
    throw new OpsError("mcp_manifest_missing", `manifest yok: ${c.paths.mcpManifestFile}`);
  }
  const manifest = parseMcpManifest(text);
  const sandbox = c.sandbox === undefined || c.sandbox === "detect" ? await detectSandbox() : c.sandbox;
  const adapter = new McpBridgeAdapter({ manifest, sandbox });
  const ids = rest[0] ? [rest[0]] : manifest.servers.map((s) => s.id);
  let bad = 0;
  for (const id of ids) {
    const r = await adapter.check(id);
    if (!r.ok) bad++;
    out(c, `${r.ok ? "✓" : "✗"} ${r.server}${r.serverName ? ` (${r.serverName}, protokol ${r.protocolVersion})` : ""}${r.missing.length ? `  eksik araçlar: ${r.missing.join(", ")}` : ""}${r.undeclared ? `  manifestte olmayan ${r.undeclared} sunucu aracı (açılmaz)` : ""}${r.error ? `  hata: ${stripControlChars(r.error)}` : ""}`);
  }
  return bad === 0 ? 0 : 1;
}

/** Kontrol terminalinden tek satır okur (politika düzenleme onayı). TTY yoksa REDDEDİLİR. */
async function confirmOnTty(c: CliEnv, question: string, want: string): Promise<boolean> {
  const tty = await (c.openTty ?? openDevTty)().catch(() => null);
  if (!tty) throw new OpsError("tty_required", "kontrol terminali (TTY) yok: onay verilemez");
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: tty.input, crlfDelay: Infinity });
  try {
    tty.output.write(question);
    const next = await Promise.race([
      rl[Symbol.asyncIterator]().next(),
      new Promise<null>((r) => setTimeout(() => r(null), 120_000).unref()),
    ]);
    return next !== null && !next.done && String(next.value).trim() === want;
  } finally {
    rl.close();
    tty.close?.();
  }
}

async function readIfExists(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

/** Yeniden kimlik doğrulama: kasa parolası kontrol terminalinden (yankısız); sohbet/opsd'ye parola GİTMEZ, yalnız kanıt. */
function makeReauth(c: CliEnv): () => Promise<{ method: string; verifiedAtMs: number }> {
  return async () => {
    const p = await reauthVaultPassphrase({ openTty: c.openTty ?? openDevTtyRaw, vaultFile: c.paths.vaultFile, ...(c.reauthVerify ? { verify: c.reauthVerify } : {}) });
    return { method: p.method, verifiedAtMs: p.verifiedAt.getTime() };
  };
}

async function policyCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  const userText = await readIfExists(c.paths.policyFile);
  const baseText = userText ?? (await readFile(BUILTIN_POLICY_FILE, "utf8"));
  const source = userText === null ? "yerleşik varsayılan (henüz kullanıcı dosyası yok)" : c.paths.policyFile;
  if (sub === undefined || sub === "list") {
    out(c, `Politika kaynağı: ${source}`);
    out(c, renderRuleList(parsePolicy(baseText), new Date()));
    return 0;
  }
  if (!["allow", "add", "rm"].includes(sub)) throw new OpsError("usage", "kullanım: ops policy list | allow … | add … | rm ID");
  const now = new Date();
  return await withRuntime(c, async (rt) => {
    // Kasa parolası withRuntime'da zaten istendi (yeniden kimlik doğrulama); değişiklik denetime yazılır.
    let next: string;
    let what: string;
    if (sub === "allow") {
      const { values } = parseArgs({ args: rest, options: { tool: { type: "string" }, profile: { type: "string" }, scope: { type: "string" }, ttl: { type: "string" }, id: { type: "string" }, description: { type: "string" } }, strict: true });
      if (!values.tool || !values.profile) throw new OpsError("usage", "--tool ve --profile gerekli (tam ad; joker yok)");
      const reg = rt.registry.get(values.profile);
      const rule = buildAllowRule({
        tool: values.tool,
        profile: values.profile,
        ...(values.scope ? { scope: list(values.scope) } : {}),
        ttlSec: values.ttl ? parseTtlSec(values.ttl) : DEFAULT_ALLOW_TTL_SEC,
        ...(values.description ? { description: values.description } : {}),
        ...(values.id ? { id: values.id } : {}),
        now,
        registered: reg ? { environment: reg.environment, classCeiling: reg.classCeiling } : undefined,
      });
      next = addRuleToText(baseText, rule);
      what = `ekle ${rule.id} (allow ${values.tool} @ ${values.profile}, bitiş ${rule.expires})`;
    } else if (sub === "add") {
      const { values } = parseArgs({ args: rest, options: { effect: { type: "string" }, id: { type: "string" }, tool: { type: "string" }, profile: { type: "string" }, environment: { type: "string" }, class: { type: "string" }, scope: { type: "string" }, description: { type: "string" } }, strict: true });
      if ((values.effect !== "ask" && values.effect !== "deny") || !values.id) throw new OpsError("usage", "--effect ask|deny ve --id gerekli (gevşetici 'allow' için `ops policy allow`)");
      const when = {
        ...(values.tool ? { tool: values.tool } : {}),
        ...(values.profile ? { profile: values.profile } : {}),
        ...(values.environment ? { environment: list(values.environment) as Environment[] } : {}),
        ...(values.class ? { class: list(values.class) as RiskClass[] } : {}),
        ...(values.scope ? { scope: list(values.scope) } : {}),
      };
      if (Object.keys(when).length === 0) throw new OpsError("usage", "en az bir koşul gerekli (--tool/--profile/--environment/--class/--scope): her şeyi kapsayan kural yazılmaz");
      next = addRuleToText(baseText, { id: values.id, ...(values.description ? { description: values.description } : {}), when, effect: values.effect });
      what = `ekle ${values.id} (${values.effect})`;
    } else {
      const id = rest[0];
      if (!id) throw new OpsError("usage", "kullanım: ops policy rm KURAL-ID");
      next = removeRuleFromText(baseText, id);
      what = `sil ${id}`;
    }
    const before = policyHash(parsePolicy(baseText));
    const after = policyHash(parsePolicy(next));
    out(c, `Politika kaynağı: ${source}\n${renderPolicyDiff(baseText, next)}`);
    out(c, `Politika sürümü ${before.slice(0, 12)} → ${after.slice(0, 12)}. Değişiklik YALNIZ yeni oturumda geçerli olur (oturum başında anlık görüntü).`);
    if (!(await confirmOnTty(c, "Bu değişiklik uygulansın mı? 'evet' yazın: ", "evet"))) {
      out(c, "Uygulanmadı (onay verilmedi).");
      return 1;
    }
    // denetim ÖNCE: yazılamıyorsa dosya değişmez (fail-closed)
    await rt.audit.append({ event: "policy_change", sessionId: rt.session.id, message: `${what}; sürüm ${before.slice(0, 12)}→${after.slice(0, 12)}` }).catch(() => {
      throw new OpsError("audit_unavailable", "denetim kaydı yazılamadı: politika değişmedi");
    });
    // Yedek ve politika atomik yazılır: sabit adlı geçici/yedek yola dikilmiş symlink izlenmez (O_EXCL + rename).
    if (userText !== null) await writeFileAtomic(`${c.paths.policyFile}.bak`, userText).catch(() => undefined);
    await writeFileAtomic(c.paths.policyFile, next);
    out(c, `Politika yazıldı: ${c.paths.policyFile}${userText !== null ? " (önceki sürüm .bak)" : ""}`);
    return 0;
  });
}

async function breakGlassCommand(c: CliEnv, sub: string | undefined, rest: string[]): Promise<number> {
  const verbs = ["start", "end", "status", "review"];
  const verb = sub && verbs.includes(sub) ? sub : "start";
  const args = sub && verbs.includes(sub) ? rest : sub ? [sub, ...rest] : rest;
  if (verb === "review") {
    const { values } = parseArgs({ args, options: { session: { type: "string" } }, strict: true });
    const recs = await readAuditRecords(c.paths.auditLog);
    const sessions = [...new Set(recs.filter((r) => r.event === "break_glass").map((r) => r.sessionId))];
    const sid = values.session ?? sessions.at(-1);
    if (!sid) {
      out(c, "Break-glass kaydı yok.");
      return 0;
    }
    const md = renderBreakGlassReview(recs, sid);
    out(c, md ?? `Bu oturumda break-glass kaydı yok: ${sid}`);
    return md ? 0 : 1;
  }
  const client = await OpsdClient.connect(c.paths.socket).catch((e: unknown) => {
    if (e instanceof OpsError) throw e; // güvensiz/çok uzun soket yolu: asıl sebep gösterilir
    throw new OpsError("opsd_unreachable", `opsd'ye bağlanılamadı (${c.paths.socket}). Break-glass çalışan bir oturumun tavanını yükseltir: önce \`ops daemon\`; gömülü sohbette \`/breakglass\` kullanın`);
  });
  try {
    if (verb === "status") {
      const st = await client.breakGlassStatus();
      out(c, st.length ? st.map(stripControlChars).join("\n") : "(etkin break-glass yok)");
      return 0;
    }
    if (verb === "end") {
      const { values } = parseArgs({ args, options: { profile: { type: "string" } }, strict: true });
      if (!values.profile) throw new OpsError("usage", "kullanım: ops break-glass end --profile ID");
      out(c, stripControlChars(await client.breakGlassEnd(values.profile)));
      return 0;
    }
    const { values } = parseArgs({ args, options: { profile: { type: "string" }, ceiling: { type: "string" }, ttl: { type: "string" }, reason: { type: "string" } }, strict: true });
    if (!values.profile || !values.ceiling || !values.ttl || !values.reason) throw new OpsError("usage", "--profile, --ceiling, --ttl ve --reason gerekli (gerekçe ve süre zorunlu)");
    if (!RISK_CLASSES.includes(values.ceiling as RiskClass)) throw new OpsError("usage", `--ceiling şunlardan biri olmalı: ${RISK_CLASSES.join(", ")}`);
    const proof = await makeReauth(c)();
    const lines = await client.breakGlassStart({ profile: values.profile, ceiling: values.ceiling as RiskClass, ttlSec: parseDurationSec(values.ttl), reason: values.reason, reauth: proof });
    for (const l of lines) out(c, stripControlChars(l));
    out(c, "Denetim, redaksiyon ve onay kapıları AÇIK kalır; yalnız sınıf tavanı geçici yükseldi. Süre bitince otomatik düşer; inceleme dosyası oturum sonunda yazılır.");
    return 0;
  } finally {
    client.close();
  }
}

export async function runCli(c: CliEnv): Promise<number> {
  const [cmd, sub, ...rest] = c.argv;
  try {
    switch (cmd) {
      case undefined:
      case "help":
      case "--help":
        out(c, USAGE);
        return cmd === undefined ? 2 : 0;

      case "init": {
        await ensureHome(c.paths);
        await withRuntime(c, async () => undefined);
        out(c, `Hazır: ${c.paths.home} (kasa ve denetim anahtarı oluşturuldu)`);
        return 0;
      }

      case "profile": {
        if (sub === "rbac") {
          const { values } = parseArgs({ args: rest, options: { "sa-namespace": { type: "string" }, namespace: { type: "string" }, "cluster-read": { type: "boolean" }, name: { type: "string" } }, strict: true });
          const ns = list(values.namespace);
          if (!values["sa-namespace"] || ns.length === 0) throw new OpsError("usage", "--sa-namespace ve --namespace gerekli");
          out(c, generateReadOnlyRbac({ serviceAccountNamespace: values["sa-namespace"], namespaces: ns, clusterRead: values["cluster-read"] === true, ...(values.name ? { name: values.name } : {}) }));
          return 0;
        }
        if (sub === "add") {
          const [kind, ...r2] = rest;
          if (kind === "db") return await addDatabaseProfile(c, r2);
          if (kind === "pipeline" || kind === "scm") return await addTokenProfile(c, kind, r2);
          if (kind !== "k8s") throw new OpsError("usage", "profil türü: 'k8s', 'db', 'pipeline' veya 'scm' (bu sürümde)");
          const { values } = parseArgs({
            args: r2,
            options: { id: { type: "string" }, kubeconfig: { type: "string" }, env: { type: "string" }, context: { type: "string" }, scope: { type: "string" }, ceiling: { type: "string" }, name: { type: "string" }, "ambient-env": { type: "string" }, "ambient-path": { type: "string" }, "allow-external-token-file": { type: "boolean" }, replace: { type: "boolean" } },
            strict: true,
          });
          if (!values.id || !values.kubeconfig || !values.env) throw new OpsError("usage", "--id, --kubeconfig ve --env gerekli");
          if (!ENVIRONMENTS.includes(values.env as Environment)) throw new OpsError("usage", `--env şunlardan biri olmalı: ${ENVIRONMENTS.join(", ")}`);
          const ceiling = (values.ceiling ?? "read") as RiskClass;
          if (!RISK_CLASSES.includes(ceiling)) throw new OpsError("usage", `--ceiling şunlardan biri olmalı: ${RISK_CLASSES.join(", ")}`);
          const text = await readFile(values.kubeconfig, "utf8");
          const sandbox = c.sandbox === undefined || c.sandbox === "detect" ? await detectSandbox() : c.sandbox;
          const res = await withRuntime(c, (rt) =>
            rt.profiles.addKubeconfig({
              id: values.id as string,
              environment: values.env as Environment,
              kubeconfigText: text,
              baseDir: values.kubeconfig?.replace(/[^/]*$/, "") || ".",
              classCeiling: ceiling,
              sandboxAvailable: sandbox !== null,
              ...(values.context ? { context: values.context } : {}),
              ...(values.scope ? { allowedScopes: list(values.scope) } : {}),
              ...(values.name ? { displayName: values.name } : {}),
              ...(values["ambient-env"] ? { ambientOptInEnv: list(values["ambient-env"]) } : {}),
              ...(values["ambient-path"] ? { ambientPaths: list(values["ambient-path"]) } : {}),
              ...(values["allow-external-token-file"] ? { allowExternalTokenFile: true } : {}),
              ...(values.replace ? { replace: true } : {}),
            }),
          );
          out(c, `Profil eklendi: ${res.profile.id} (${res.profile.environment}, tavan ${res.profile.classCeiling}, kapsam ${res.profile.allowedScopes.join("|")}, kimlik ${res.profile.credentialSource.kind})`);
          // uyarılar kubeconfig'ten gelen adlar/yollar taşır (üçüncü taraf girdisi): terminal kaçışları basılmaz
          for (const w of res.warnings) out(c, `⚠ ${stripControlChars(w)}`);
          out(c, "Kimlik materyali yalnız kasada. Orijinal kubeconfig dosyası ürünün denetimi dışında kalır: güvenle taşıyın/silin. `ops profile doctor` ile fiili yetkiyi doğrulayın.");
          return 0;
        }
        if (sub === "list") {
          const rows = await withRuntime(c, async (rt) => rt.registry.list());
          out(c, rows.length === 0 ? "(profil yok)" : rows.map((p) => `${p.id}\t${p.kind}\t${p.environment}\ttavan ${p.classCeiling}\tkapsam ${p.allowedScopes.join("|")}\t${p.credentialSource.kind}\t${stripControlChars(p.displayName)}`).join("\n"));
          return 0;
        }
        if (sub === "rm") {
          const id = rest[0];
          if (!id) throw new OpsError("usage", "kullanım: ops profile rm ID");
          const removed = await withRuntime(c, (rt) => rt.profiles.remove(id));
          out(c, removed ? `Silindi: ${id}` : `Bulunamadı: ${id}`);
          return removed ? 0 : 1;
        }
        if (sub === "doctor") {
          const id = rest[0];
          if (!id) throw new OpsError("usage", "kullanım: ops profile doctor ID");
          const rep = await withRuntime(c, (rt) => rt.diagnose(id));
          out(c, renderDoctor(rep));
          return rep.bindable ? 0 : 1;
        }
        throw new OpsError("usage", "profile alt komutu: add | list | rm | doctor | rbac");
      }

      case "explain-policy": {
        const { values } = parseArgs({ args: c.argv.slice(1), options: { last: { type: "string" }, code: { type: "string" } }, strict: true });
        if (values.code) {
          out(c, `${values.code}: ${explainReason(values.code)}`);
          return 0;
        }
        const n = Number(values.last ?? "10");
        const recs = (await readAuditRecords(c.paths.auditLog)).filter((r) => r.reasonCode && (r.decision === "deny" || r.decision === "ask") && (r.event === "result" || r.event === "intent" || r.event === "approval")).slice(-n);
        if (recs.length === 0) out(c, "Reddedilen/sorulan çağrı bulunamadı.");
        for (const r of recs) out(c, `[${r.ts}] ${r.tool ?? "-"} ${r.profile ? `(${r.profile}) ` : ""}→ ${r.decision} ${r.reasonCode}\n    ${explainReason(r.reasonCode as string)}${r.message ? `\n    ayrıntı: ${r.message}` : ""}`);
        return 0;
      }

      case "provider": {
        if (sub === "list") {
          out(c, providerNames().map((n) => `${n}${c.env["OPS_PROVIDER"] === n ? "  (etkin: OPS_PROVIDER)" : ""}`).join("\n"));
          return 0;
        }
        if (sub === "set-key") {
          const name = rest[0];
          if (!name || !providerNames().includes(name)) throw new OpsError("usage", `kullanım: ops provider set-key AD (kayıtlı: ${providerNames().join(", ")})`);
          const key = await readPassphrase(c.env, c.io, `${name} API anahtarı: `, "OPS_PROVIDER_KEY_FILE");
          try {
            await withRuntime(c, (rt) => rt.store.set(providerKeyName(name), key));
          } finally {
            key.fill(0);
          }
          out(c, `${name} anahtarı kasaya yazıldı (değer gösterilmez).`);
          return 0;
        }
        throw new OpsError("usage", "provider alt komutu: list | set-key AD");
      }

      case "doctor": {
        const home = c.env["HOME"] ?? "";
        const amb = home ? await scanAmbientCredentials(home) : [];
        const det = c.sandbox === undefined || c.sandbox === "detect" ? await detectSandboxDetailed({ env: c.env, vmStateDir: c.paths.vmDir }) : { sandbox: c.sandbox, reason: c.sandbox ? "verildi" : "kapalı" };
        const sb = det.sandbox;
        out(c, `OS sandbox: ${sb ? `${sb.kind} — ${det.reason}` : `YOK (${det.reason}) — kabuk, çalışma alanı/IaC, MCP köprüsü ve exec kimlik eklentileri çalışmaz`}`);
        if (sb instanceof VmSandbox) {
          out(c, `  paylaşımlar: ${sb.state.shares.map((s) => `${s.host} [${s.mode}]`).join(", ")}`);
          out(c, `  konuk araç dizinleri: ${sb.toolDirs.join(":")}`);
          for (const l of await guestToolVersions(sb)) out(c, l);
        }
        const envNames = scanAmbientEnv(c.env);
        out(c, amb.length === 0 && envNames.length === 0 ? "Ortam kimliği bulunamadı." : "Ürünün DENETİMİ DIŞINDAKİ ortam kimlikleri (içerik okunmadı):");
        for (const a of amb) out(c, `  ${a.path}  ${a.what}  mod ${a.mode}${a.groupOrWorldReadable ? "  ⚠ grup/dünya okuyabilir" : ""}`);
        for (const n of envNames) out(c, `  ortam değişkeni: ${n}`);
        try {
          const st = await stat(c.paths.vaultFile);
          out(c, `Kasa: ${c.paths.vaultFile} (mod ${(st.mode & 0o777).toString(8)})`);
        } catch {
          out(c, "Kasa: yok (`ops init`)");
        }
        return 0;
      }

      case "audit": {
        if (sub !== "verify") throw new OpsError("usage", "kullanım: ops audit verify");
        const res = await withRuntime(c, async (rt) => {
          const key = await (await import("@ops/broker")).ensureAuditKey(rt.store);
          return verifyAudit(new FileAuditStorage(c.paths.auditLog), key, new FileHeadAnchor(c.paths.auditAnchor));
        });
        if (res.ok) {
          out(c, `Denetim zinciri DOĞRU: ${res.records} kayıt, baş seq ${res.head?.seq ?? "-"}`);
          return 0;
        }
        out(c, `Denetim zinciri BOZUK (${res.problems.length} sorun):`);
        for (const p of res.problems.slice(0, 20)) out(c, `  [${p.code}] ${p.message}`);
        return 1;
      }

      case "usage": {
        out(c, formatUsage(usageFromAudit(await readAuditRecords(c.paths.auditLog))));
        return 0;
      }

      case "replay": {
        const { values: rv } = parseArgs({ args: c.argv.slice(1), options: { session: { type: "string" }, policy: { type: "string" }, json: { type: "boolean" }, verbose: { type: "boolean" } }, strict: true });
        return await withRuntime(c, async (rt) => {
          // Bu komutun kendi oturumu hedef olamaz: kayıtlar çalışma zamanı açıldıktan sonra okunur
          const all = await readAuditRecords(c.paths.auditLog);
          const prior = all.filter((r) => r.sessionId !== rt.session.id);
          const sessionId = rv.session && rv.session !== "last" ? rv.session : lastSessionId(prior, true);
          if (!sessionId || !prior.some((r) => r.sessionId === sessionId)) throw new OpsError("usage", rv.session ? `oturum bulunamadı: ${rv.session.slice(0, 60)}` : "denetimde incelenecek önceki oturum yok");
          let whatIf: WhatIfDeps | undefined;
          if (rv.policy) {
            const file = rv.policy === "current" ? ((await stat(c.paths.policyFile).then(() => true, () => false)) ? c.paths.policyFile : BUILTIN_POLICY_FILE) : resolve(rv.policy);
            const engine = new PolicyEngine(await loadPolicyFile(file), { now: () => at });
            let at = new Date();
            whatIf = {
              policyHash: engine.versionHash,
              decide: (input, when) => {
                at = when;
                return engine.decide(input);
              },
              tool: (name) => rt.toolRegistry.get(name)?.def.descriptor,
              profile: (id) => rt.registry.get(id),
            };
          }
          const report = buildReplay(prior, { sessionId, ...(whatIf ? { whatIf } : {}) });
          const key = await ensureAuditKey(rt.store);
          const chain = await verifyAudit(new FileAuditStorage(c.paths.auditLog), key, new FileHeadAnchor(c.paths.auditAnchor));
          const chainText = chain.ok ? `DOĞRU (${chain.records} kayıt)` : `BOZUK (${chain.problems.length} sorun: ${[...new Set(chain.problems.map((p) => p.code))].join(", ")}) — aşağıdaki zaman çizelgesine GÜVENMEYİN`;
          out(c, rv.json ? JSON.stringify({ chain: { ok: chain.ok, records: chain.records }, ...report }, null, 2) : renderReplay(report, { verbose: rv.verbose === true, chain: chainText }));
          return !chain.ok || report.anomalies.some((a) => a.severity === "high") ? 1 : 0;
        });
      }

      case "workspace":
        return await workspaceCommand(c, sub, rest);

      case "vm":
        return await vmCommand({ paths: c.paths, env: c.env, io: c.io }, sub, rest);

      case "skill":
        return await skillCommand(c, sub, rest);

      case "runbook":
        return await runbookCommand(c, sub);

      case "change":
        return await changeCommand(c, sub, rest);

      case "mcp":
        return await mcpCommand(c, sub, rest);

      case "policy":
        return await policyCommand(c, sub, rest);

      case "break-glass":
        return await breakGlassCommand(c, sub, rest);

      case "daemon": {
        const { values: dv } = parseArgs({ args: c.argv.slice(1), options: { workspace: { type: "string" }, "local-only": { type: "boolean" }, quarantine: { type: "string" } }, strict: true });
        const gate = c.approval ?? new TtyApprovalGate({ openTty: openDevTty });
        const dq = quarantineMode(c, dv.quarantine);
        return await withRuntime(c, async (rt) => {
          const orch = await engineFor(c, rt, dv["local-only"], dq);
          const d = new Opsd({ runtime: rt, orchestrator: orch, socketPath: c.paths.socket, onShutdown: () => stopper.abort() });
          const stopper = new AbortController();
          c.stop?.addEventListener("abort", () => stopper.abort(), { once: true });
          await d.listen();
          out(c, `opsd dinliyor: ${c.paths.socket}`);
          await new Promise<void>((resolve) => stopper.signal.addEventListener("abort", () => resolve(), { once: true }));
          await d.close();
          return 0;
        }, gate, dv.workspace, dv["local-only"], dq);
      }

      case "chat": {
        const { values: cv } = parseArgs({ args: c.argv.slice(1), options: { embedded: { type: "boolean" }, workspace: { type: "string" }, "local-only": { type: "boolean" }, quarantine: { type: "string" } }, strict: true });
        const embedded = cv.embedded === true;
        const cq = quarantineMode(c, cv.quarantine);
        if (cv.workspace && !embedded) throw new OpsError("usage", "--workspace yalnız --embedded veya `ops daemon --workspace ID` ile kullanılır (çalışma alanı opsd sürecine aittir)");
        if (embedded) {
          const gate = c.approval ?? new TtyApprovalGate({ openTty: openDevTty });
          await withRuntime(c, async (rt) => {
            await runChat(new LocalBackend(rt, await engineFor(c, rt, cv["local-only"], cq)), { input: c.io.input, output: c.io.output }, { approvalEvents: gate.events, reauth: makeReauth(c), ...(c.stop ? { stop: c.stop } : {}) });
            out(c, gate.summaryLine());
          }, gate, cv.workspace, cv["local-only"], cq);
          return 0;
        }
        const client = await OpsdClient.connect(c.paths.socket).catch((e: unknown) => {
          if (e instanceof OpsError) throw e; // güvensiz/çok uzun soket yolu: asıl sebep gösterilir
          throw new OpsError("opsd_unreachable", `opsd'ye bağlanılamadı (${c.paths.socket}). \`ops daemon\` çalıştırın veya \`ops chat --embedded\` kullanın`);
        });
        try {
          // Güvenlik kipleri opsd SÜRECİNE aittir: istemci istediği kipi çalışan daemon'un sağlamadığı halde sessizce
          // sürmez (fail-open olmaz); uyuşmazlıkta sohbet BAŞLAMAZ.
          const info = await client.ping();
          if (isLocalOnly(c, cv["local-only"]) && !info.localOnly) throw new OpsError("local_only", "istenen `local-only` kipi çalışan opsd'de KAPALI: `ops daemon --local-only` ile yeniden başlatın");
          if (cq && info.quarantine !== cq && !(cq === "digest" && info.quarantine === "model")) throw new OpsError("usage", `istenen karantina kipi '${cq}' ama çalışan opsd '${info.quarantine}': \`ops daemon --quarantine ${cq}\` ile yeniden başlatın`);
          await runChat(client, { input: c.io.input, output: c.io.output }, { reauth: makeReauth(c), ...(c.stop ? { stop: c.stop } : {}) });
        } finally {
          client.close();
        }
        return 0;
      }

      default:
        err(c, `bilinmeyen komut: ${String(cmd).slice(0, 40)}\n${USAGE}`);
        return 2;
    }
  } catch (e) {
    err(c, `✗ ${e instanceof OpsError ? `${e.code}: ` : ""}${e instanceof Error ? e.message : String(e)}`);
    return e instanceof OpsError && e.code === "usage" ? 2 : 1;
  }
}
