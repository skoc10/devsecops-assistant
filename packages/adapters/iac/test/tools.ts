import { accessSync, constants } from "node:fs";
import { join } from "node:path";
import { fsOf } from "@ops/sandbox";
import type { Sandbox } from "@ops/sandbox";

/**
 * Gerçek IaC ikilileri testler için `OPS_TOOL_DIRS` (iki nokta ile ayrılmış) veya bilinen kurulum
 * dizinlerinde aranır; yoksa ilgili testler uyarıyla ATLANIR (CI'da kurulur).
 */
export const TOOL_DIRS: string[] = [...(process.env["OPS_TOOL_DIRS"]?.split(":") ?? []), "/opt/ops-tools/bin", "/opt/ops-tools/venv/bin", "/usr/local/bin", "/usr/bin"].filter(Boolean);

/** Sandbox'ın İKİLİ dosya sisteminde arar (VM kipinde konuk; ADR-0011 §6). Sandbox'ta çalışacak araçlar için. */
export async function findTool(name: string, sandbox: Sandbox | null): Promise<string | null> {
  const fs = fsOf(sandbox);
  for (const d of TOOL_DIRS) {
    const p = join(d, name);
    if (await fs.executable(p)) return p;
  }
  return null;
}

/** HOST'ta doğrudan çalıştırılacak yardımcı ikili (sandbox'sız adımlar: sağlayıcı aynası üretimi, diferansiyel test). */
export function findHostTool(name: string): string | null {
  for (const d of TOOL_DIRS) {
    const p = join(d, name);
    try {
      accessSync(p, constants.X_OK);
      return p;
    } catch {
      /* sonraki */
    }
  }
  return null;
}
