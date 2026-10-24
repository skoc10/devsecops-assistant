import { z } from "zod";
import { parse } from "yaml";
import { OpsError, TOOLSET_PATTERN } from "@ops/contracts";

export const SKILL_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const FrontMatter = z.object({ name: z.string(), description: z.string() }).passthrough();

/** `ops.skill.yaml`: ürüne özgü alanlar (SKILL.md `metadata`'sı yalnız string→string olduğundan ayrı dosya). */
export const SidecarSchema = z.strictObject({
  requires: z.strictObject({ adapters: z.array(z.string().regex(/^[a-z][a-z0-9-]*$/)).default([]) }).default({ adapters: [] }),
  requests: z.strictObject({ toolsets: z.array(z.string().regex(TOOLSET_PATTERN)).default([]) }).default({ toolsets: [] }),
  model_hint: z.enum(["small", "large"]).optional(),
  runbook: z.array(z.string().min(1).max(300)).max(30).optional(),
});
export type Sidecar = z.infer<typeof SidecarSchema>;

export interface ParsedSkillMd {
  readonly name: string;
  readonly description: string;
  readonly body: string;
}

export function parseSkillMd(text: string): ParsedSkillMd {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!m) throw new OpsError("skill_invalid", "SKILL.md ön bilgi (front matter) içermiyor");
  let fm: unknown;
  try {
    fm = parse(m[1] as string);
  } catch {
    throw new OpsError("skill_invalid", "SKILL.md ön bilgisi YAML olarak okunamadı");
  }
  const r = FrontMatter.safeParse(fm);
  if (!r.success) throw new OpsError("skill_invalid", "SKILL.md ön bilgisinde name ve description zorunlu");
  return { name: r.data.name, description: r.data.description.trim(), body: (m[2] as string).trim() };
}

export function parseSidecar(text: string | undefined): { sidecar: Sidecar; problems: string[] } {
  if (text === undefined) return { sidecar: SidecarSchema.parse({}), problems: [] };
  let raw: unknown;
  try {
    raw = parse(text) ?? {};
  } catch {
    return { sidecar: SidecarSchema.parse({}), problems: ["ops.skill.yaml okunamadı (YAML geçersiz)"] };
  }
  const r = SidecarSchema.safeParse(raw);
  if (!r.success) {
    return { sidecar: SidecarSchema.parse({}), problems: r.error.issues.map((i) => `ops.skill.yaml ${i.path.join(".") || "(kök)"}: ${i.message}`) };
  }
  return { sidecar: r.data, problems: [] };
}
