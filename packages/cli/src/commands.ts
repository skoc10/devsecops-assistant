import { readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import type { Readable, Writable } from "node:stream";
import { generateReadOnlyRbac } from "@ops/adapter-kubernetes";
import { FileAuditStorage, FileHeadAnchor, verifyAudit } from "@ops/audit";
import { scanAmbientCredentials, scanAmbientEnv } from "@ops/broker";
import { ENVIRONMENTS, OpsError, RISK_CLASSES } from "@ops/contracts";
import type { Environment, ModelProvider, RiskClass, SecretStore } from "@ops/contracts";
import { ChangeStore, formatUsage, usageFromAudit } from "@ops/core";
import { McpBridgeAdapter, parseMcpManifest } from "@ops/mcp-bridge";
import { stripControlChars } from "@ops/redaction";
import { WORKSPACE_ENGINES, WorkspaceManager, WorkspaceRegistry } from "@ops/workspace";
import type { WorkspaceEngine } from "@ops/workspace";
import { explainReason } from "@ops/policy";
import { detectSandbox } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { readAuditRecords, LocalBackend } from "./backend.ts";
import type { Sender } from "./backend.ts";
import { OpsdClient } from "./client.ts";
import { renderDoctor, runChat } from "./chat.ts";
import { TtyApprovalGate, openDevTty } from "./approval.ts";
import { Opsd } from "./opsd.ts";
import { ensureHome } from "./paths.ts";
import type { OpsPaths } from "./paths.ts";
import { readPassphrase } from "./prompt.ts";
import { registerBuiltinProviders } from "./builtin-providers.ts";
import { createProvider, isAgentRuntime, providerKeyName, providerNames } from "./providers.ts";
import type { ProviderFactory } from "./providers.ts";
import { createRuntime } from "./runtime.ts";
import type { Runtime } from "./runtime.ts";

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
}

const USAGE = [
  "kullanım: ops <komut>",
  "  init                               OPS_HOME ve kasayı oluştur",
  "  profile add k8s --id ID --kubeconfig YOL --env dev|stage|prod|sandbox [--context C] [--scope a,b] [--ceiling read]",
  "              [--name AD] [--ambient-env ADLAR] [--ambient-path DİZİN]",
  "  profile add db --id ID --env E --host H [--port 5432] --database D --user U --scope public,sales [--ca-file PEM]",
  "              [--default-schema S] [--datasource AD] [--name AD] [--tls verify-full|disable] [--replace]",
  "              (parola: OPS_DB_PASSWORD_FILE ile 0600 dosya veya yankısız TTY istemi; bağlantı DİZESİ kabul edilmez)",
  "  profile add pipeline|scm --id ID --env E --scope sahip/depo,sahip/* [--api-url https://api.github.com] [--ca-file PEM]",
  "              [--log-hosts h1,h2] [--name AD] [--replace]   (belirteç: OPS_GITHUB_TOKEN_FILE ile 0600 dosya veya yankısız TTY; salt okunur fine-grained belirteç önerilir)",
  "  profile list | rm ID | doctor ID",
  "  profile rbac --sa-namespace NS --namespace a,b [--cluster-read] [--name AD]   (manifest üretir, UYGULAMAZ)",
  "  doctor                             ortam kimlikleri ve sandbox durumu",
  "  audit verify                       denetim zincirini doğrula",
  "  usage                              token kullanım raporu (denetimden)",
  "  explain-policy [--last N | --code KOD]   reddedilen/sorulan çağrıları açıkla",
  "  provider list | set-key AD         sağlayıcıları listele / API anahtarını kasaya yaz (OPS_PROVIDER_KEY_FILE veya TTY)",
  "  workspace add --id ID --path DİZİN --engine terraform|opentofu|ansible [--write-paths g1,g2] [--deny-paths g1,g2] [--replace]",
  "  workspace list | rm ID | snapshots [ID]",
  "  workspace diff ID [--session S] [--path P]      ajanın değişiklikleri (anlık kopya ↔ özgün HEAD)",
  "  workspace export ID --out DOSYA [--session S]   değişiklikleri `git apply` ile uygulanabilir yama olarak yaz (depoya YAZMAZ)",
  "  change list | show ID | export ID --out DOSYA   ajanın önerdiği değişiklikler (ChangeSet); uygulamak size aittir",
  "  mcp check [SUNUCU]                 OPS_HOME/mcp-servers.yaml sunucularını sandbox'ta başlatıp manifestle karşılaştır (araç çağırmaz)",
  "  daemon [--workspace ID]            opsd'yi başlat (UDS)",
  "  chat [--embedded] [--workspace ID] sohbet (opsd'ye bağlanır; --embedded süreç içi)",
  "  (ortam) OPS_WORKDIR=DİZİN          shell.run iş alanı (salt-okunur; OS sandbox gerekir; ev dizini olamaz)",
  "  (ortam) OPS_WORKSPACE=ID           etkin IaC çalışma alanı; OPS_TOOL_DIRS=d1:d2 terraform/tofu/ansible dizinleri; OPS_IAC_PROVIDER_MIRROR=DİZİN yerel sağlayıcı aynası",
].join("\n");

const out = (c: CliEnv, s: string): void => void c.io.output.write(`${s}\n`);
const err = (c: CliEnv, s: string): void => void c.io.error.write(`${s}\n`);

async function withRuntime<T>(c: CliEnv, fn: (rt: Runtime) => Promise<T>, approval?: TtyApprovalGate, workspace?: string): Promise<T> {
  const ws = workspace ?? c.workspace ?? c.env["OPS_WORKSPACE"];
  const toolDirs = c.env["OPS_TOOL_DIRS"]?.split(":").filter(Boolean);
  const rt = await createRuntime({
    paths: c.paths,
    ...(ws ? { workspace: ws } : {}),
    ...(toolDirs?.length ? { toolDirs } : {}),
    ...(c.env["OPS_IAC_PROVIDER_MIRROR"] ? { providerMirror: c.env["OPS_IAC_PROVIDER_MIRROR"] } : {}),
    ...(approval ? { approval } : {}),
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
async function engineFor(c: CliEnv, rt: Runtime): Promise<Sender> {
  if (c.provider) return rt.createOrchestrator(c.provider);
  const sel = await (c.providerFactory ?? createProvider)({ env: c.env, store: rt.store, known: rt.known, sandbox: rt.sandbox });
  return isAgentRuntime(sel) ? rt.createRuntimeOrchestrator(sel) : rt.createOrchestrator(sel);
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
  out(c, `Profil eklendi: ${res.profile.id} (${res.profile.environment}, reader, şemalar ${res.profile.allowedScopes.join("|")}, çıktı bölgesi ${res.profile.egressClass})`);
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
            options: { id: { type: "string" }, kubeconfig: { type: "string" }, env: { type: "string" }, context: { type: "string" }, scope: { type: "string" }, ceiling: { type: "string" }, name: { type: "string" }, "ambient-env": { type: "string" }, "ambient-path": { type: "string" }, replace: { type: "boolean" } },
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
              ...(values.replace ? { replace: true } : {}),
            }),
          );
          out(c, `Profil eklendi: ${res.profile.id} (${res.profile.environment}, tavan ${res.profile.classCeiling}, kapsam ${res.profile.allowedScopes.join("|")}, kimlik ${res.profile.credentialSource.kind})`);
          for (const w of res.warnings) out(c, `⚠ ${w}`);
          out(c, "Kimlik materyali yalnız kasada. Orijinal kubeconfig dosyası ürünün denetimi dışında kalır: güvenle taşıyın/silin. `ops profile doctor` ile fiili yetkiyi doğrulayın.");
          return 0;
        }
        if (sub === "list") {
          const rows = await withRuntime(c, async (rt) => rt.registry.list());
          out(c, rows.length === 0 ? "(profil yok)" : rows.map((p) => `${p.id}\t${p.kind}\t${p.environment}\ttavan ${p.classCeiling}\tkapsam ${p.allowedScopes.join("|")}\t${p.credentialSource.kind}\t${p.displayName}`).join("\n"));
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
        const sb = c.sandbox === undefined || c.sandbox === "detect" ? await detectSandbox() : c.sandbox;
        out(c, `OS sandbox: ${sb ? sb.kind : "YOK — exec kimlik eklentileri çalışmaz, terminal dar kümeyle sınırlı kalır"}`);
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

      case "workspace":
        return await workspaceCommand(c, sub, rest);

      case "change":
        return await changeCommand(c, sub, rest);

      case "mcp":
        return await mcpCommand(c, sub, rest);

      case "daemon": {
        const { values: dv } = parseArgs({ args: c.argv.slice(1), options: { workspace: { type: "string" } }, strict: true });
        const gate = c.approval ?? new TtyApprovalGate({ openTty: openDevTty });
        return await withRuntime(c, async (rt) => {
          const orch = await engineFor(c, rt);
          const d = new Opsd({ runtime: rt, orchestrator: orch, socketPath: c.paths.socket, onShutdown: () => stopper.abort() });
          const stopper = new AbortController();
          c.stop?.addEventListener("abort", () => stopper.abort(), { once: true });
          await d.listen();
          out(c, `opsd dinliyor: ${c.paths.socket}`);
          await new Promise<void>((resolve) => stopper.signal.addEventListener("abort", () => resolve(), { once: true }));
          await d.close();
          return 0;
        }, gate, dv.workspace);
      }

      case "chat": {
        const { values: cv } = parseArgs({ args: c.argv.slice(1), options: { embedded: { type: "boolean" }, workspace: { type: "string" } }, strict: true });
        const embedded = cv.embedded === true;
        if (cv.workspace && !embedded) throw new OpsError("usage", "--workspace yalnız --embedded veya `ops daemon --workspace ID` ile kullanılır (çalışma alanı opsd sürecine aittir)");
        if (embedded) {
          const gate = c.approval ?? new TtyApprovalGate({ openTty: openDevTty });
          await withRuntime(c, async (rt) => {
            await runChat(new LocalBackend(rt, await engineFor(c, rt)), { input: c.io.input, output: c.io.output }, { approvalEvents: gate.events });
            out(c, gate.summaryLine());
          }, gate, cv.workspace);
          return 0;
        }
        const client = await OpsdClient.connect(c.paths.socket).catch(() => {
          throw new OpsError("opsd_unreachable", `opsd'ye bağlanılamadı (${c.paths.socket}). \`ops daemon\` çalıştırın veya \`ops chat --embedded\` kullanın`);
        });
        try {
          await runChat(client, { input: c.io.input, output: c.io.output });
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
