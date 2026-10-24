import { Scalar, isScalar, parseDocument, visit } from "yaml";
import { z } from "zod";
import { RISK_CLASSES, SensitivitySchema, TOOLSET_PATTERN, TOOL_NAME_PATTERN } from "@ops/contracts";

/**
 * Kullanıcı manifesti (`mcp-servers.yaml`): dış MCP sunucularını SARAR. MCP spesifikasyonu araç
 * açıklamalarını/annotation'larını GÜVENİLMEZ sayar; bu yüzden sınıf, argüman şeması, hassasiyet ve
 * limitler BURADAN gelir, sunucudan alınmaz. v0: yalnız `read` sınıfı, kimlik yok, ağ yok (veya
 * açıkça onaylanmış kısıtsız host ağı).
 */

const ABS_PATH = z
  .string()
  .max(300)
  .refine((p) => p.startsWith("/") && !p.includes("\0") && !p.split("/").includes(".."), "mutlak yol olmalı ve '..' içermemeli");

const SHA256 = z.string().regex(/^[0-9a-f]{64}$/, "64 haneli küçük harf sha256 beklenir");

const ARG_NAME = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const NO_CONTROL = /^[^\u0000-\u001f\u007f]*$/;

const StringArg = z.strictObject({
  type: z.literal("string"),
  required: z.boolean().default(false),
  maxLength: z.number().int().min(1).max(2000).default(200),
  pattern: z
    .string()
    .max(200)
    .refine((p) => {
      try {
        new RegExp(p);
        return true;
      } catch {
        return false;
      }
    }, "geçersiz düzenli ifade")
    .optional(),
  enum: z.array(z.string().max(100)).min(1).max(50).optional(),
});
const IntegerArg = z.strictObject({
  type: z.literal("integer"),
  required: z.boolean().default(false),
  min: z.number().int().default(0),
  max: z.number().int().default(1000),
});
const BooleanArg = z.strictObject({ type: z.literal("boolean"), required: z.boolean().default(false) });
export const ArgSpecSchema = z.discriminatedUnion("type", [StringArg, IntegerArg, BooleanArg]);
export type ArgSpec = z.infer<typeof ArgSpecSchema>;

export const McpToolSchema = z.strictObject({
  /** SUNUCUDAKİ araç adı (tools/call'a aynen gider). */
  name: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/),
  /** Modele gösterilen açıklama: BİZİM metnimiz (sunucununki değil). */
  description: z.string().min(1).max(400),
  class: z.enum(RISK_CLASSES).default("read"),
  sensitivity: SensitivitySchema.default("internal"),
  args: z.record(z.string().regex(ARG_NAME), ArgSpecSchema).default({}),
  maxOutputTokens: z.number().int().min(100).max(3000).default(1500),
  typicalOutputTokens: z.number().int().min(0).max(3000).default(600),
});
export type McpToolSpec = z.infer<typeof McpToolSchema>;

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
/** v0: sunuculara kimlik VERİLMEZ; secret benzeri adlar reddedilir. */
const SECRET_ENV = /(pass|secret|token|key|credential|auth|cookie)/i;

export const McpServerSchema = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9]{0,15}$/),
  /** Çalıştırılacak İKİLİ (mutlak yol); içeriği `sha256` ile pinlenir ve her çağrıda yeniden doğrulanır. */
  command: ABS_PATH,
  sha256: SHA256,
  args: z.array(z.string().max(200).refine((a) => !a.includes("\0"), "NUL")).max(20).default([]),
  /** Komutun yüklediği ek dosyalar (betik paketi vb.): her biri pinlenir ve salt-okunur bağlanır. */
  files: z.array(z.strictObject({ path: ABS_PATH, sha256: SHA256 })).max(10).default([]),
  env: z
    .record(z.string().regex(ENV_NAME), z.string().max(200).refine((v) => !v.includes("\0"), "NUL"))
    .default({})
    .refine((e) => Object.keys(e).length <= 10, "en çok 10 ortam değişkeni")
    .refine((e) => Object.keys(e).every((k) => !SECRET_ENV.test(k)), "v0: sunuculara kimlik/secret ortam değişkeni verilmez"),
  /** Çalışma zamanı kütüphaneleri vb. için ek SALT-OKUNUR yollar (ör. node kurulum öneki). */
  roBinds: z.array(ABS_PATH).max(10).default([]),
  /** `none`: ağ ad alanı ayrı (ENFORCED). `host`: kısıtsız host ağı — allowlist YOK (Planned); açık onay ister. */
  network: z.enum(["none", "host"]).default("none"),
  acknowledgeUnrestrictedNetwork: z.boolean().optional(),
  toolset: z.string().regex(TOOLSET_PATTERN).optional(),
  timeoutMs: z.number().int().min(1000).max(120_000).default(30_000),
  maxOutputBytes: z.number().int().min(1000).max(1_000_000).default(400_000),
  tools: z.array(McpToolSchema).min(1).max(20),
});
export type McpServerSpec = z.infer<typeof McpServerSchema>;

export const McpManifestSchema = z
  .strictObject({ servers: z.array(McpServerSchema).min(1).max(10) })
  .superRefine((m, ctx) => {
    const ids = new Set<string>();
    const names = new Set<string>();
    m.servers.forEach((s, i) => {
      if (ids.has(s.id)) ctx.addIssue({ code: "custom", message: `yinelenen sunucu kimliği: ${s.id}`, path: ["servers", i, "id"] });
      ids.add(s.id);
      if (s.network === "host" && s.acknowledgeUnrestrictedNetwork !== true) {
        ctx.addIssue({ code: "custom", message: "`network: host` kısıtsız ağdır (allowlist yok): `acknowledgeUnrestrictedNetwork: true` gerekir", path: ["servers", i, "network"] });
      }
      s.tools.forEach((t, j) => {
        if (t.class !== "read") {
          ctx.addIssue({ code: "custom", message: `v0 köprüsü yalnız 'read' sınıfını kabul eder (araç '${t.name}': '${t.class}')`, path: ["servers", i, "tools", j, "class"] });
        }
        const opsName = mcpToolName(s.id, t.name);
        if (!TOOL_NAME_PATTERN.test(opsName)) ctx.addIssue({ code: "custom", message: `araç adı geçersiz: ${opsName}`, path: ["servers", i, "tools", j, "name"] });
        if (names.has(opsName)) ctx.addIssue({ code: "custom", message: `yinelenen araç adı: ${opsName}`, path: ["servers", i, "tools", j, "name"] });
        names.add(opsName);
      });
    });
  });
export type McpManifest = z.infer<typeof McpManifestSchema>;

/** Ürün içi araç adı: `mcp.<sunucu>.<araç>` (küçük harf, `-` → `_`). */
export function mcpToolName(serverId: string, tool: string): string {
  return `mcp.${serverId}.${tool.toLowerCase().replace(/-/g, "_")}`;
}

export function toolsetOf(s: McpServerSpec): string {
  return s.toolset ?? `mcp-${s.id}`;
}

const MAX_MANIFEST_BYTES = 64 * 1024;

export class McpManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpManifestError";
  }
}

/** YAML manifesti çözer ve doğrular. Takma ad (alias) ve yinelenen anahtar YASAK. */
export function parseMcpManifest(text: string): McpManifest {
  if (Buffer.byteLength(text) > MAX_MANIFEST_BYTES) throw new McpManifestError("manifest çok büyük (> 64 KiB)");
  const doc = parseDocument(text, { uniqueKeys: true });
  if (doc.errors.length > 0) throw new McpManifestError(`manifest YAML hatası: ${(doc.errors[0]?.message ?? "").split("\n")[0]?.slice(0, 160)}`);
  // `sha256: 000…0` veya `12e3…` YAML'da sayıdır (hassasiyet kaybolur → pin yanlış karşılaştırılır). Pin alanları
  // her zaman özgün metinleriyle DİZGE okunur.
  visit(doc, {
    Pair(_k, pair) {
      if (isScalar(pair.key) && pair.key.value === "sha256" && isScalar(pair.value) && typeof pair.value.value !== "string") {
        const src = (pair.value as Scalar).source;
        if (typeof src === "string") pair.value = new Scalar(src);
      }
    },
  });
  let js: unknown;
  try {
    js = doc.toJS({ maxAliasCount: 0 });
  } catch {
    throw new McpManifestError("manifestte YAML takma adı (alias) kullanılamaz");
  }
  const r = McpManifestSchema.safeParse(js);
  if (!r.success) {
    const i = r.error.issues[0];
    throw new McpManifestError(`manifest geçersiz: ${(i?.path ?? []).join(".")}: ${i?.message ?? "?"}`.slice(0, 300));
  }
  return r.data;
}

/** Argüman şemasından girdi doğrulayıcı (strictObject: fazladan alan reddedilir). */
export function buildInputSchema(tool: McpToolSpec): z.ZodType {
  const shape: Record<string, z.ZodType> = {};
  for (const [name, spec] of Object.entries(tool.args)) {
    let t: z.ZodType;
    if (spec.type === "string") {
      let s = z.string().max(spec.maxLength).regex(NO_CONTROL, "kontrol karakteri içeremez");
      if (spec.pattern) s = s.regex(new RegExp(spec.pattern));
      t = spec.enum ? z.enum(spec.enum as [string, ...string[]]) : s;
    } else if (spec.type === "integer") {
      t = z.number().int().min(spec.min).max(spec.max);
    } else {
      t = z.boolean();
    }
    shape[name] = spec.required ? t : t.optional();
  }
  return z.strictObject(shape);
}
