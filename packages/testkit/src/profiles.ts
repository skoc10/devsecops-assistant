import { createHmac, randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProfileSchema } from "@ops/contracts";
import type { Profile, ProfileInput } from "@ops/contracts";

/** Çalıştırmaya (süreç) özgü rastgele anahtar: sahte profiller yalnız bu süreçte geçerlidir. */
const RUN_KEY = randomBytes(32);

function canonical(p: { id: string; kind: string; environment: string; targetPin: { endpoint: string } }): string {
  return JSON.stringify([p.id, p.kind, p.environment, p.targetPin.endpoint]);
}

export function signFixture(p: Pick<Profile, "id" | "kind" | "environment" | "targetPin">): string {
  return createHmac("sha256", RUN_KEY).update(canonical(p)).digest("hex");
}

/** `testFixtureSig` bu süreçte üretilmiş ve profil alanlarıyla eşleşiyor mu? */
export function verifyFixtureSignature(p: Profile): boolean {
  if (!p.testFixtureSig) return false;
  const expected = signFixture(p);
  return expected.length === p.testFixtureSig.length && expected === p.testFixtureSig;
}

/**
 * Sahte (fixture) profil. Uç noktalar `.invalid` TLD'sindedir (RFC 2606): gerçek bir hedefe
 * çözülemez. Profil, bu süreçte üretilmiş HMAC imzasıyla damgalanır.
 */
export function makeTestProfile(over: Partial<ProfileInput> = {}): Profile {
  const base: ProfileInput = {
    id: "test-k8s",
    kind: "k8s",
    displayName: "Test kümesi",
    environment: "sandbox",
    targetPin: { endpoint: "https://k8s.test.invalid:6443" },
    classCeiling: "read",
    allowedScopes: ["default", "payments"],
    credentialSource: { kind: "static" },
    egressClass: "third-party-cloud",
    ...over,
  };
  const parsed = ProfileSchema.parse(base);
  return { ...parsed, testFixtureSig: signFixture(parsed) };
}

export interface TestHome {
  readonly path: string;
  cleanup(): Promise<void>;
}

/** İzole `OPS_HOME`: gerçek kasa ve profiller testten erişilemez. */
export async function createTestHome(): Promise<TestHome> {
  const path = await mkdtemp(join(tmpdir(), "ops-home-"));
  await chmod(path, 0o700);
  return {
    path,
    cleanup: async () => {
      await rm(path, { recursive: true, force: true });
    },
  };
}
