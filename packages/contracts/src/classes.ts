import { z } from "zod";

/** Hedef sistem üzerindeki etki sınıfları, artan sırayla. */
export const RISK_CLASSES = ["read", "mutate", "deploy", "destroy"] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];
export const RiskClassSchema = z.enum(RISK_CLASSES);

export function riskRank(c: RiskClass): number {
  return RISK_CLASSES.indexOf(c);
}

export function maxRisk(...classes: RiskClass[]): RiskClass {
  let best: RiskClass = "read";
  for (const c of classes) {
    if (riskRank(c) > riskRank(best)) best = c;
  }
  return best;
}

export function riskAtLeast(c: RiskClass, min: RiskClass): boolean {
  return riskRank(c) >= riskRank(min);
}

/** Sınıflanamayan her şey `destroy` muamelesi görür (fail-closed). */
export const UNCLASSIFIED_RISK: RiskClass = "destroy";

export const ENVIRONMENTS = ["dev", "stage", "prod", "sandbox"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];
export const EnvironmentSchema = z.enum(ENVIRONMENTS);

/** `target`: hedef sisteme etki; `local`: yalnız yerel çalışma alanı. */
export const SCOPE_AXES = ["target", "local"] as const;
export type ScopeAxis = (typeof SCOPE_AXES)[number];
export const ScopeAxisSchema = z.enum(SCOPE_AXES);

export const NETWORK_MODES = ["none", "allowlisted", "open"] as const;
export type NetworkMode = (typeof NETWORK_MODES)[number];
export const NetworkModeSchema = z.enum(NETWORK_MODES);

/** Veri maruziyet bölgeleri, artan maruziyet sırasıyla. */
export const TRUST_ZONES = ["local", "private-net", "tenant-cloud", "third-party-cloud"] as const;
export type TrustZone = (typeof TRUST_ZONES)[number];
export const TrustZoneSchema = z.enum(TRUST_ZONES);

export function zoneRank(z: TrustZone): number {
  return TRUST_ZONES.indexOf(z);
}

/** İki bölgeden daha kısıtlayıcı (daha az maruz) olanı döndürür. */
export function stricterZone(a: TrustZone, b: TrustZone): TrustZone {
  return zoneRank(a) <= zoneRank(b) ? a : b;
}

/** Sağlayıcı bölgesi, verinin gidebileceği en uzak bölgeyi aşmıyorsa `true`. */
export function zoneAllows(providerZone: TrustZone, maxAllowed: TrustZone): boolean {
  return zoneRank(providerZone) <= zoneRank(maxAllowed);
}

export const SENSITIVITIES = ["none", "internal", "pii", "secret-adjacent"] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];
export const SensitivitySchema = z.enum(SENSITIVITIES);

export function sensitivityRank(s: Sensitivity): number {
  return SENSITIVITIES.indexOf(s);
}

export function maxSensitivity(...items: Sensitivity[]): Sensitivity {
  let best: Sensitivity = "none";
  for (const s of items) {
    if (sensitivityRank(s) > sensitivityRank(best)) best = s;
  }
  return best;
}

/** Hassasiyet düzeyinin gidebileceği en uzak bölge (profil `egressClass` ile ayrıca kısıtlanır). */
export const SENSITIVITY_ZONE_CAP: Readonly<Record<Sensitivity, TrustZone>> = {
  none: "third-party-cloud",
  internal: "third-party-cloud",
  pii: "tenant-cloud",
  "secret-adjacent": "local",
};
