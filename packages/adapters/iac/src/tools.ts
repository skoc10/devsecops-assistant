import { z } from "zod";
import { defineTool } from "@ops/contracts";
import type { ToolDefinition, ToolDescriptorMeta } from "@ops/contracts";

const base = {
  scope: "local",
  profileKind: null,
  network: "none",
  class: "read",
  idempotent: true,
  toolset: "iac",
  sensitivity: "internal",
  untrustedOutput: false,
} as const satisfies Partial<ToolDescriptorMeta>;

const p = z.string().min(1).max(200);

export const projectInspect = defineTool(
  {
    ...base,
    name: "iac.project.inspect",
    description: "IaC projesi özeti (Terraform/OpenTofu veya Ansible): sağlayıcılar, modüller, değişken/çıktı adları, playbook/rol, ön-tarama bulguları. State/tfvars/vault okunmaz.",
    limits: { timeoutMs: 15_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_500 },
    typicalOutputTokens: 700,
  },
  z.strictObject({}),
);

export const fmt = defineTool(
  {
    ...base,
    name: "iac.fmt",
    description: "terraform/tofu fmt: dosyaları biçimlendirir (anlık kopyada). check:true yalnız değişecekleri listeler.",
    localWrite: true,
    idempotent: false,
    limits: { timeoutMs: 60_000, maxBytes: 100_000, maxItems: 100, maxOutputTokens: 800 },
    typicalOutputTokens: 150,
  },
  z.strictObject({ check: z.boolean().optional() }),
);

export const validate = defineTool(
  {
    ...base,
    name: "iac.validate",
    description: "init -backend=false + validate -json (sandbox, ağsız). Önce HCL ön-taraması: kod çalıştıran yapı varsa ÇALIŞMAZ. Tanılar kompakt döner.",
    limits: { timeoutMs: 150_000, maxBytes: 200_000, maxItems: 30, maxOutputTokens: 1_500 },
    typicalOutputTokens: 400,
  },
  z.strictObject({}),
);

export const lint = defineTool(
  {
    ...base,
    name: "iac.lint",
    description: "Terraform: tflint (kuruluysa). Ansible: ansible-playbook --syntax-check + ansible-lint (offline, ürünün kendi yapılandırmasıyla).",
    limits: { timeoutMs: 180_000, maxBytes: 300_000, maxItems: 40, maxOutputTokens: 1_500 },
    typicalOutputTokens: 500,
  },
  z.strictObject({ playbook: p.optional() }),
);

export const scan = defineTool(
  {
    ...base,
    name: "iac.scan",
    description: "Güvenlik tarayıcısı SARIF sonucunu (çalışma alanındaki .sarif/.json) okur ve özetler; ürün kendi tarayıcısını çalıştırmaz.",
    limits: { timeoutMs: 20_000, maxBytes: 1_000_000, maxItems: 40, maxOutputTokens: 1_500 },
    typicalOutputTokens: 600,
  },
  z.strictObject({ path: p, maxResults: z.number().int().min(1).max(40).optional() }),
);

export const docsLookup = defineTool(
  {
    ...base,
    name: "iac.docs.lookup",
    description: "Kaynak/veri kaynağı şeması (öznitelikler, zorunlu mu, tür) — yerel `providers schema -json` çıktısından YALNIZ istenen tür. Sağlayıcı yerel aynada olmalı.",
    limits: { timeoutMs: 150_000, maxBytes: 300_000, maxItems: 80, maxOutputTokens: 1_500 },
    typicalOutputTokens: 700,
  },
  z.strictObject({ type: z.string().regex(/^[a-z][a-z0-9_]{0,80}$/), kind: z.enum(["resource", "data"]).optional() }),
);

export const inventoryList = defineTool(
  {
    ...base,
    name: "ansible.inventory.list",
    description: "Statik Ansible envanteri: grup/host adları ve değişken ADLARI (değerler çıkmaz). Dinamik envanter çalıştırılmaz.",
    limits: { timeoutMs: 15_000, maxBytes: 200_000, maxItems: 100, maxOutputTokens: 1_200 },
    typicalOutputTokens: 400,
  },
  z.strictObject({ path: p.optional() }),
);

export const IAC_TOOLS: readonly ToolDefinition[] = [projectInspect, fmt, validate, lint, scan, docsLookup, inventoryList];
