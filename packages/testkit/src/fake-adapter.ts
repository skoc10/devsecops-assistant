import { ADAPTER_CONTRACT, AdapterManifestSchema } from "@ops/contracts";
import type {
  ActionPreview,
  Adapter,
  AdapterCall,
  AdapterKind,
  AdapterManifest,
  Profile,
  ProfileKind,
  RawToolOutput,
  RiskClass,
  Target,
  ToolDefinition,
} from "@ops/contracts";

export interface FakeToolSpec {
  readonly def: ToolDefinition;
  readonly handler: (call: AdapterCall) => RawToolOutput | Promise<RawToolOutput>;
  /** Hedef kapsamlarını/başvurularını argümandan çıkarır (varsayılan: `namespace` argümanı). */
  readonly targetOf?: (args: Record<string, unknown>) => { scopes?: string[]; refs?: string[] };
  /** Adapter'ın kendi sınıflaması (yalnız yükseltir). */
  readonly classifyAs?: (args: Record<string, unknown>) => RiskClass | undefined;
}

/** Kayıt tutan, davranışı yapılandırılabilir sahte adapter (PEP ve orkestratör testleri için). */
export class FakeAdapter implements Adapter {
  readonly manifest: AdapterManifest;
  readonly calls: AdapterCall[] = [];
  /** Hedef çözümünü bozmak için: pin uyuşmazlığı testleri. */
  endpointOverride: string | null = null;
  /** Mutasyon önizlemesi (testler atar). Atanmazsa adapter önizleme DESTEKLEMEZ. */
  preview?: (call: AdapterCall) => Promise<ActionPreview>;
  private readonly specs: Map<string, FakeToolSpec>;

  constructor(id: string, kind: AdapterKind, profileKind: ProfileKind, tools: readonly FakeToolSpec[]) {
    this.specs = new Map(tools.map((t) => [t.def.descriptor.name, t]));
    this.manifest = AdapterManifestSchema.parse({
      id,
      version: "0.0.0",
      contract: ADAPTER_CONTRACT,
      kind,
      profileKinds: [profileKind],
      credentialKinds: ["static"],
      capabilities: [],
      tools: tools.map((t) => t.def.descriptor),
    });
  }

  validateProfile(profile: Profile): string[] {
    return this.manifest.profileKinds.includes(profile.kind) ? [] : [`profil türü desteklenmiyor: ${profile.kind}`];
  }

  resolveTarget(tool: string, args: unknown, profile: Profile): Target {
    const spec = this.specs.get(tool);
    const a = (args ?? {}) as Record<string, unknown>;
    const fromSpec = spec?.targetOf?.(a);
    const ns = typeof a["namespace"] === "string" ? [a["namespace"]] : [];
    return {
      profileId: profile.id,
      kind: profile.kind,
      endpoint: this.endpointOverride ?? profile.targetPin.endpoint,
      scopes: fromSpec?.scopes ?? ns,
      refs: fromSpec?.refs ?? [],
    };
  }

  classify(tool: string, args: unknown): RiskClass | undefined {
    return this.specs.get(tool)?.classifyAs?.((args ?? {}) as Record<string, unknown>);
  }

  async invoke(call: AdapterCall): Promise<RawToolOutput> {
    this.calls.push(call);
    const spec = this.specs.get(call.tool);
    if (!spec) throw new Error(`bilinmeyen araç: ${call.tool}`);
    return spec.handler(call);
  }
}
