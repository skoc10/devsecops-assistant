import { wrapUntrusted } from "@ops/redaction";
import type { ToolResult } from "@ops/contracts";

/**
 * Araç sonucunun modele giden metni. Untrusted sonuçlar rastgele nonce'lu zarfa konur (M6);
 * zarf TEK BAŞINA savunma değildir: asıl kontrol politikadır (taint → ask).
 */
export function formatForModel(r: ToolResult): string {
  if (r.status === "denied") {
    return `REDDEDİLDİ [${r.reasonCode ?? "policy_deny"}]: ${r.summary}`;
  }
  const body: Record<string, unknown> = {
    id: r.evidenceId,
    tool: r.tool,
    status: r.status,
    summary: r.summary,
  };
  if (r.truncated) body["truncated"] = true;
  if (r.byReference) {
    body["byReference"] = true;
    body["hint"] = "Sonuç token tavanını aştı; evidence.get(id, select, offset, limit) ile dilimleyin.";
    body["tokensFull"] = r.tokens.estimate;
  } else if (r.view !== undefined) {
    body["view"] = r.view;
  }
  if (r.reasonCode) body["reasonCode"] = r.reasonCode;
  const json = JSON.stringify(body);
  return r.taint === "untrusted" ? wrapUntrusted(json, r.tool).text : json;
}
