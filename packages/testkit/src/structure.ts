import { AdapterManifestSchema, ToolDescriptorSchema } from "@ops/contracts";
import type { Adapter } from "@ops/contracts";

/**
 * Adapter yapı denetimi (conformance v0, davranışsız kısım). Boş liste = uygun.
 * Davranış denetimleri (sızıntı, hedef reddi, çıktı tavanı) kategori testlerinde ayrıca yapılır.
 */
export function checkAdapterStructure(adapter: Adapter): string[] {
  const problems: string[] = [];
  const m = AdapterManifestSchema.safeParse(adapter.manifest);
  if (!m.success) {
    problems.push(`manifest geçersiz: ${m.error.issues.map((i) => i.message).join("; ")}`);
    return problems;
  }
  const seen = new Set<string>();
  for (const t of m.data.tools) {
    const d = ToolDescriptorSchema.safeParse(t);
    if (!d.success) {
      problems.push(`araç tanımı geçersiz (${t.name}): ${d.error.issues.map((i) => i.message).join("; ")}`);
      continue;
    }
    if (seen.has(t.name)) problems.push(`yinelenen araç adı: ${t.name}`);
    seen.add(t.name);
    const schema = t.inputSchema;
    if (schema["type"] === "object" && schema["additionalProperties"] !== false) {
      problems.push(`girdi şeması additionalProperties:false değil: ${t.name}`);
    }
    if (t.scope === "target" && t.profileKind === null) {
      problems.push(`hedef araç profilsiz olamaz: ${t.name}`);
    }
    if (t.profileKind !== null && !m.data.profileKinds.includes(t.profileKind)) {
      problems.push(`araç profil türü manifestte yok: ${t.name}`);
    }
    if (t.limits.maxOutputTokens > 8000) {
      problems.push(`araç çıktı tavanı çok yüksek (>8000 token): ${t.name}`);
    }
    if (t.description.length > 400) problems.push(`açıklama çok uzun: ${t.name}`);
  }
  return problems;
}
