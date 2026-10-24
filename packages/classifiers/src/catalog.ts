import { z } from "zod";
import { parse } from "yaml";
import { OpsError, RiskClassSchema, NetworkModeSchema } from "@ops/contracts";

const Positional = z.strictObject({
  /** `none`: konumsal argüman yok · `path`: iş alanı içi yol · `ref`: git revizyonu · `any`: serbest kısa metin. */
  kind: z.enum(["none", "path", "ref", "any"]),
  min: z.number().int().min(0).default(0),
  max: z.number().int().min(0).default(10),
  /** İlk konumsal argüman desen/süzgeçtir (yol sayılmaz). */
  firstIsPattern: z.boolean().default(false),
  /** `--` sonrası konumsal türü. */
  afterDoubleDash: z.enum(["none", "path"]).optional(),
});

const Subcommand = z.strictObject({
  path: z.array(z.string().regex(/^[a-z][a-z0-9-]*$/)).max(3),
  flags: z.array(z.string().regex(/^--?[A-Za-z0-9][A-Za-z0-9=_-]*$/)).default([]),
  valueFlags: z.array(z.string().regex(/^--?[A-Za-z0-9][A-Za-z0-9_-]*$/)).default([]),
  valuePattern: z.string().default("^[A-Za-z0-9_.:@/+= -]{1,100}$"),
  positional: Positional.default({ kind: "none", min: 0, max: 0, firstIsPattern: false }),
});

const Hardening = z.strictObject({
  /** İkiliden hemen sonra eklenen sabit argümanlar (ör. git sertleştirme). */
  prefix: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  /** Alt komut adından sonra eklenen sabit argümanlar. */
  appendAfter: z.record(z.string(), z.array(z.string())).default({}),
});

const CommandEntry = z.strictObject({
  binary: z.string().regex(/^[a-z][a-z0-9_.-]*$/),
  description: z.string().optional(),
  class: RiskClassSchema,
  network: NetworkModeSchema.default("none"),
  hardening: Hardening.optional(),
  subcommands: z.array(Subcommand).min(1),
});

export const CatalogSchema = z
  .strictObject({ version: z.literal(1), commands: z.array(CommandEntry).min(1) })
  .superRefine((doc, ctx) => {
    doc.commands.forEach((c, i) => {
      if (c.class === "read" && c.network === "open") {
        ctx.addIssue({ code: "custom", message: "`read` sınıfı `network: open` komutu kabul etmez", path: ["commands", i, "network"] });
      }
      for (const s of c.subcommands) {
        try {
          new RegExp(s.valuePattern);
        } catch {
          ctx.addIssue({ code: "custom", message: "valuePattern geçerli bir regex değil", path: ["commands", i] });
        }
      }
    });
    const bins = new Set<string>();
    doc.commands.forEach((c, i) => {
      if (bins.has(c.binary)) ctx.addIssue({ code: "custom", message: `yinelenen ikili: ${c.binary}`, path: ["commands", i, "binary"] });
      bins.add(c.binary);
    });
  });

export type CommandCatalog = z.infer<typeof CatalogSchema>;
export type CommandEntryT = z.infer<typeof CommandEntry>;
export type SubcommandT = z.infer<typeof Subcommand>;

export function parseCatalog(yamlText: string): CommandCatalog {
  let raw: unknown;
  try {
    raw = parse(yamlText);
  } catch {
    throw new OpsError("catalog_invalid", "komut kataloğu okunamadı (YAML geçersiz)");
  }
  const r = CatalogSchema.safeParse(raw);
  if (!r.success) {
    throw new OpsError("catalog_invalid", `komut kataloğu geçersiz — ${r.error.issues.map((i) => `${i.path.join(".") || "(kök)"}: ${i.message}`).join("; ")}`);
  }
  return r.data;
}

/** Kullanıcı kataloğu yerleşik olanı GENİŞLETİR; aynı ikili tanımlanırsa kullanıcı girdisi REDDEDİLİR (gevşetme yok). */
export function mergeCatalogs(base: CommandCatalog, user: CommandCatalog): CommandCatalog {
  const have = new Set(base.commands.map((c) => c.binary));
  for (const c of user.commands) {
    if (have.has(c.binary)) throw new OpsError("catalog_invalid", `kullanıcı kataloğu yerleşik komutu geçersiz kılamaz: ${c.binary}`);
  }
  return { version: 1, commands: [...base.commands, ...user.commands] };
}
