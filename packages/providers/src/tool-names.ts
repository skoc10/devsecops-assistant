import { createHash } from "node:crypto";
import { OpsError, TOOL_NAME_PATTERN } from "@ops/contracts";

/**
 * Araç adı kodlaması (OpenAI işlev adı ve Anthropic araç adı: `^[a-zA-Z0-9_-]{1,64}$`; `.` geçersiz).
 * Basit biçim `.` ↔ `__` TERSİNİR yalnız adda `__` yoksa ve hiçbir parça `_` ile bitmiyorsa. Aksi halde (ör. MCP aracı
 * `mcp.srv.get__item`) deterministik bir TAKMA AD (`x_<hash>_<ad>`) üretilir ve çözme tablosuna yazılır; böylece tek
 * bir kodlanamayan araç TÜM model çağrılarını bozmaz ve çakışma sessiz olmaz.
 */
const aliases = new Map<string, string>();
const MAX = 64;

export function encodeToolName(name: string): string {
  if (!TOOL_NAME_PATTERN.test(name)) throw new OpsError("tool_name_unencodable", `araç adı biçimi geçersiz: ${name.slice(0, 60)}`);
  const simple = name.replaceAll(".", "__");
  if (!name.includes("__") && !name.split(".").some((s) => s.endsWith("_")) && simple.length <= MAX) return simple;
  const alias = `x_${createHash("sha256").update(name).digest("hex").slice(0, 10)}_${name.replace(/[^a-zA-Z0-9]+/g, "-").slice(0, 40)}`;
  const prev = aliases.get(alias);
  if (prev !== undefined && prev !== name) throw new OpsError("tool_name_unencodable", `araç adı takma adı çakışıyor: ${name.slice(0, 60)}`);
  aliases.set(alias, name);
  return alias;
}

export function decodeToolName(wire: string): string {
  return aliases.get(wire) ?? wire.replaceAll("__", ".");
}
