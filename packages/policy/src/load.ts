import { readFile } from "node:fs/promises";
import { OpsError } from "@ops/contracts";
import { parse } from "yaml";
import { PolicyDocumentSchema } from "./schema.ts";
import type { PolicyDocument } from "./schema.ts";

export function parsePolicy(yamlText: string): PolicyDocument {
  let raw: unknown;
  try {
    raw = parse(yamlText);
  } catch (e) {
    throw new OpsError("policy_invalid", "policy.yaml okunamadı", { cause: e instanceof Error ? e.message : String(e) });
  }
  const r = PolicyDocumentSchema.safeParse(raw);
  if (!r.success) {
    const issues = r.error.issues.map((i) => `${i.path.join(".") || "(kök)"}: ${i.message}`);
    throw new OpsError("policy_invalid", `policy.yaml geçersiz — ${issues.join("; ")}`, { issues });
  }
  return r.data;
}

export async function loadPolicyFile(path: string): Promise<PolicyDocument> {
  return parsePolicy(await readFile(path, "utf8"));
}
