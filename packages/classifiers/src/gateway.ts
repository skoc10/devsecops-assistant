import type { RiskClass } from "@ops/contracts";
import type { CommandCatalog } from "./catalog.ts";
import { classifyShell } from "./classify.ts";

/**
 * PEP sınıflayıcı eki (`GatewayDeps.classifiers`): `shell.run` için kabuk dizgisini katalogla
 * sınıflar; sınıflanamazsa `"unclassified"` (= destroy muamelesi, ret). Başka araçlara dokunmaz.
 */
export function shellCommandClassifier(catalog: CommandCatalog, jailRoot: string) {
  return (tool: string, args: unknown): RiskClass | "unclassified" | undefined => {
    if (tool !== "shell.run") return undefined;
    const cmd = (args as { command?: unknown } | null)?.command;
    if (typeof cmd !== "string") return "unclassified";
    const r = classifyShell(cmd, catalog, jailRoot);
    return r.ok ? r.class : "unclassified";
  };
}
