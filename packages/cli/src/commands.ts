import { readFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";
import type { Readable, Writable } from "node:stream";
import { generateReadOnlyRbac } from "@ops/adapter-kubernetes";
import { FileAuditStorage, FileHeadAnchor, verifyAudit } from "@ops/audit";
import { scanAmbientCredentials, scanAmbientEnv } from "@ops/broker";
import { ENVIRONMENTS, OpsError, RISK_CLASSES } from "@ops/contracts";
import type { Environment, ModelProvider, RiskClass, SecretStore } from "@ops/contracts";
import { formatUsage, usageFromAudit } from "@ops/core";
import { detectSandbox } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";
import { readAuditRecords, LocalBackend } from "./backend.ts";
import type { Sender } from "./backend.ts";
import { OpsdClient } from "./client.ts";
import { renderDoctor, runChat } from "./chat.ts";
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
  /** `daemon` komutunun beklemesini durduran sinyal (test). */
  readonly stop?: AbortSignal;
}

const USAGE = [
  "kullanım: ops <komut>",
  "  init                               OPS_HOME ve kasayı oluştur",
  "  profile add k8s --id ID --kubeconfig YOL --env dev|stage|prod|sandbox [--context C] [--scope a,b] [--ceiling read]",
  "              [--name AD] [--ambient-env ADLAR] [--ambient-path DİZİN]",
  "  profile list | rm ID | doctor ID",
  "  profile rbac --sa-namespace NS --namespace a,b [--cluster-read] [--name AD]   (manifest üretir, UYGULAMAZ)",
  "  doctor                             ortam kimlikleri ve sandbox durumu",
  "  audit verify                       denetim zincirini doğrula",
  "  usage                              token kullanım raporu (denetimden)",
  "  provider list | set-key AD         sağlayıcıları listele / API anahtarını kasaya yaz (OPS_PROVIDER_KEY_FILE veya TTY)",
  "  daemon                             opsd'yi başlat (UDS)",
  "  chat [--embedded]                  sohbet (opsd'ye bağlanır; --embedded süreç içi)",
].join("\n");

const out = (c: CliEnv, s: string): void => void c.io.output.write(`${s}\n`);
const err = (c: CliEnv, s: string): void => void c.io.error.write(`${s}\n`);

async function withRuntime<T>(c: CliEnv, fn: (rt: Runtime) => Promise<T>): Promise<T> {
  const rt = await createRuntime({
    paths: c.paths,
    ...(c.store ? { store: c.store } : { passphrase: () => readPassphrase(c.env, c.io) }),
    ...(c.scryptParams ? { scryptParams: c.scryptParams } : {}),
    ...(c.sandbox !== undefined ? { sandbox: c.sandbox } : {}),
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
          if (kind !== "k8s") throw new OpsError("usage", "profil türü: yalnız 'k8s' (bu sürümde)");
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

      case "daemon": {
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
        });
      }

      case "chat": {
        const embedded = sub === "--embedded" || rest.includes("--embedded");
        if (embedded) {
          await withRuntime(c, async (rt) => {
            await runChat(new LocalBackend(rt, await engineFor(c, rt)), { input: c.io.input, output: c.io.output });
          });
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
