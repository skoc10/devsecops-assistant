import { accessSync, constants } from "node:fs";
import { join } from "node:path";

/**
 * Gerçek IaC ikilileri testler için `OPS_TOOL_DIRS` (iki nokta ile ayrılmış) veya bilinen kurulum
 * dizinlerinde aranır; yoksa ilgili testler uyarıyla ATLANIR (CI'da kurulur).
 */
export const TOOL_DIRS: string[] = [...(process.env["OPS_TOOL_DIRS"]?.split(":") ?? []), "/opt/ops-tools/bin", "/opt/ops-tools/venv/bin", "/usr/local/bin", "/usr/bin"].filter(Boolean);

export function findTool(name: string): string | null {
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
