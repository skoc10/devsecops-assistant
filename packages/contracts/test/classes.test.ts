import { describe, expect, it } from "vitest";
import {
  maxRisk,
  maxSensitivity,
  riskAtLeast,
  riskRank,
  SENSITIVITY_ZONE_CAP,
  stricterZone,
  UNCLASSIFIED_RISK,
  zoneAllows,
} from "../src/index.ts";

describe("risk sınıfları", () => {
  it("read < mutate < deploy < destroy sıralaması", () => {
    expect(riskRank("read")).toBeLessThan(riskRank("mutate"));
    expect(riskRank("mutate")).toBeLessThan(riskRank("deploy"));
    expect(riskRank("deploy")).toBeLessThan(riskRank("destroy"));
  });

  it("maxRisk en yükseği döndürür; boş girdi read", () => {
    expect(maxRisk("read", "deploy", "mutate")).toBe("deploy");
    expect(maxRisk()).toBe("read");
  });

  it("riskAtLeast", () => {
    expect(riskAtLeast("deploy", "mutate")).toBe(true);
    expect(riskAtLeast("read", "mutate")).toBe(false);
  });

  it("sınıflanamayan destroy muamelesi görür (fail-closed)", () => {
    expect(UNCLASSIFIED_RISK).toBe("destroy");
  });
});

describe("güven bölgeleri ve hassasiyet", () => {
  it("sağlayıcı bölgesi izin verilen en uzak bölgeyi aşamaz", () => {
    expect(zoneAllows("local", "local")).toBe(true);
    expect(zoneAllows("third-party-cloud", "local")).toBe(false);
    expect(zoneAllows("tenant-cloud", "third-party-cloud")).toBe(true);
  });

  it("stricterZone daha az maruz olanı seçer", () => {
    expect(stricterZone("tenant-cloud", "local")).toBe("local");
    expect(stricterZone("private-net", "third-party-cloud")).toBe("private-net");
  });

  it("secret-adjacent veri yalnız yerel bölgeye gidebilir", () => {
    expect(SENSITIVITY_ZONE_CAP["secret-adjacent"]).toBe("local");
    expect(SENSITIVITY_ZONE_CAP["pii"]).toBe("tenant-cloud");
  });

  it("maxSensitivity", () => {
    expect(maxSensitivity("none", "pii", "internal")).toBe("pii");
    expect(maxSensitivity()).toBe("none");
  });
});
