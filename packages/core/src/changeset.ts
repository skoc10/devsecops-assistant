import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { ADAPTER_CONTRACT, AdapterManifestSchema, OpsError, defineTool } from "@ops/contracts";
import type { Adapter, AdapterCall, Profile, RawToolOutput, Target, ToolDefinition } from "@ops/contracts";
import { KnownSecrets, scrubText } from "@ops/redaction";
import type { EvidenceStore } from "./evidence.ts";

export const CHANGE_KINDS = ["k8s-manifest", "sql", "iac", "text"] as const;
export type ChangeKind = (typeof CHANGE_KINDS)[number];

/** Önerilen bir değişikliğin yerel kaydı: ajan UYGULAMAZ; kullanıcı kendi sürecinde (PR, kubectl, pipeline) uygular. */
export interface ChangeSet {
  readonly version: 1;
  readonly id: string;
  readonly createdAt: string;
  readonly sessionId: string;
  readonly title: string;
  readonly summary: string;
  readonly kind: ChangeKind;
  readonly evidence: readonly { readonly id: string; readonly tool: string; readonly summary: string; readonly subjects: readonly string[] }[];
  readonly file: { readonly name: string; readonly sha256: string; readonly bytes: number };
  readonly rollback?: string;
}

const ID = /^cs-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$/;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$/;
const sha256 = (b: string | Buffer): string => createHash("sha256").update(b).digest("hex");

/** `$OPS_HOME/changes/<id>/{changeset.json, <dosya>}` (0700/0600). Kullanıcının çalışma kopyasına dokunmaz. */
export class ChangeStore {
  private readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }

  async put(cs: Omit<ChangeSet, "id" | "createdAt" | "file" | "version">, content: string, fileName: string, now: Date): Promise<ChangeSet> {
    const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
    const id = `cs-${stamp}-${randomBytes(3).toString("hex")}`;
    const full: ChangeSet = { version: 1, id, createdAt: now.toISOString(), ...cs, file: { name: fileName, sha256: sha256(content), bytes: Buffer.byteLength(content) } };
    const d = join(this.dir, id);
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    await chmod(this.dir, 0o700);
    await mkdir(d, { mode: 0o700 });
    await writeFile(join(d, fileName), content, { mode: 0o600, flag: "wx" });
    await writeFile(join(d, "changeset.json"), `${JSON.stringify(full, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    return full;
  }

  async list(): Promise<ChangeSet[]> {
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch {
      return [];
    }
    const out: ChangeSet[] = [];
    for (const n of names.filter((x) => ID.test(x)).sort().reverse()) {
      try {
        out.push(await this.meta(n));
      } catch {
        /* bozuk kayıt listeye alınmaz */
      }
    }
    return out;
  }

  private async meta(id: string): Promise<ChangeSet> {
    if (!ID.test(id)) throw new OpsError("changeset_invalid", "değişiklik kimliği geçersiz");
    const cs = JSON.parse(await readFile(join(this.dir, id, "changeset.json"), "utf8")) as ChangeSet;
    if (cs.version !== 1 || cs.id !== id || !FILE_NAME.test(cs.file.name)) throw new OpsError("changeset_invalid", "changeset.json geçersiz");
    return cs;
  }

  /** Kaydı ve içeriği okur; içerik hash'i meta ile uyuşmazsa (elle değiştirilmiş) reddeder. */
  async get(id: string): Promise<{ changeSet: ChangeSet; content: string }> {
    const changeSet = await this.meta(id);
    const content = await readFile(join(this.dir, id, changeSet.file.name), "utf8");
    if (sha256(content) !== changeSet.file.sha256) throw new OpsError("changeset_tampered", "içerik hash'i changeset.json ile uyuşmuyor (kayıt sonradan değiştirilmiş)");
    return { changeSet, content };
  }
}

const limits = { timeoutMs: 5_000, maxBytes: 100_000, maxItems: 10, maxOutputTokens: 400 };

const propose = defineTool(
  {
    name: "change.propose",
    description: "Önerdiğiniz değişikliği (manifest, SQL, IaC diff'i, metin) kanıtlara bağlı bir ChangeSet dosyası olarak yerel kaydeder. UYGULAMAZ; ilk kullanımda sorar.",
    class: "read",
    scope: "local",
    localWrite: true,
    profileKind: null,
    sensitivity: "internal",
    idempotent: false,
    limits,
    untrustedOutput: false,
    toolset: "change",
    typicalOutputTokens: 120,
  },
  z.strictObject({
    title: z.string().min(3).max(120),
    summary: z.string().min(3).max(1_000),
    kind: z.enum(CHANGE_KINDS),
    filename: z.string().regex(FILE_NAME),
    content: z.string().min(1).max(60_000),
    evidence: z.array(z.string().regex(/^ev-\d+$/)).min(1).max(10),
    rollback: z.string().max(500).optional(),
  }),
);

export interface ChangeAdapterOptions {
  readonly store: ChangeStore;
  readonly evidence: EvidenceStore;
  readonly sessionId: () => string;
  readonly now?: () => Date;
}

/** Yerel `change.propose` aracı (kimliksiz, `local-write`: ilk kullanımda onay, sonra oturum izni). */
export function createChangeAdapter(opts: ChangeAdapterOptions): { adapter: Adapter; definitions: ToolDefinition[] } {
  const definitions = [propose];
  const manifest = AdapterManifestSchema.parse({
    id: "change-local",
    version: "0.1.0",
    contract: ADAPTER_CONTRACT,
    kind: "cli",
    profileKinds: [],
    credentialKinds: [],
    capabilities: [],
    tools: definitions.map((d) => d.descriptor),
  });
  const adapter: Adapter = {
    manifest,
    validateProfile: () => ["yerel adapter profil kullanmaz"],
    resolveTarget: (_t: string, _a: unknown, p: Profile): Target => ({ profileId: p.id, kind: p.kind, endpoint: p.targetPin.endpoint, scopes: [], refs: [] }),
    async invoke(call: AdapterCall): Promise<RawToolOutput> {
      if (call.tool !== "change.propose") throw new OpsError("unknown_tool", `bilinmeyen araç: ${call.tool}`);
      const a = call.args as { title: string; summary: string; kind: ChangeKind; filename: string; content: string; evidence: string[]; rollback?: string };
      const ev = a.evidence.map((id) => {
        const e = opts.evidence.get(id);
        if (!e) throw new OpsError("evidence_not_found", `kanıt bulunamadı: ${id}`);
        return e;
      });
      // değişiklik kaydında secret taşınmaz (ham metin ve başlık/özet dahil)
      const known = new KnownSecrets();
      for (const [label, text] of [["içerik", a.content], ["başlık", a.title], ["özet", a.summary], ["geri alma", a.rollback ?? ""]] as const) {
        if (scrubText(text, known) !== text) throw new OpsError("secret_in_content", `${label} secret benzeri bir değer içeriyor: kaydedilmedi`);
      }
      const cs = await opts.store.put(
        {
          sessionId: opts.sessionId(),
          title: a.title,
          summary: a.summary,
          kind: a.kind,
          evidence: ev.map((e) => ({ id: e.id, tool: e.tool, summary: e.summary, subjects: [...e.subjects].slice(0, 10) })),
          ...(a.rollback ? { rollback: a.rollback } : {}),
        },
        a.content,
        a.filename,
        (opts.now ?? (() => new Date()))(),
      );
      return {
        data: { id: cs.id, file: cs.file.name, bytes: cs.file.bytes, sha256: cs.file.sha256, note: "kayıt yerelde (OPS_HOME/changes); uygulamak kullanıcıya aittir: `ops change show/export`" },
        summary: `değişiklik önerisi kaydedildi: ${cs.id}`,
        taint: ev.some((e) => e.taint === "untrusted") ? "untrusted" : "trusted",
      };
    },
  };
  return { adapter, definitions };
}
