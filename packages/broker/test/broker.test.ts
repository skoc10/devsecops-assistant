import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KnownSecrets } from "@ops/redaction";
import { buildKubeconfig, generateTestPki, makeCanary, makeTestProfile } from "@ops/testkit";
import { importKubeconfig, LocalBroker, MemorySecretStore, credentialKey } from "../src/index.ts";
import type { LeaseRequest } from "@ops/contracts";

const server = "https://127.0.0.1:6443";

async function setup(opts: { auth?: "token" | "cert" } = {}) {
  const pki = await generateTestPki();
  const tok = makeCanary("lease-token");
  const text =
    opts.auth === "cert"
      ? buildKubeconfig({ server, caPem: pki.caPem, clientCertPem: pki.clientCertPem, clientKeyPem: pki.clientKeyPem })
      : buildKubeconfig({ server, caPem: pki.caPem, token: tok.value });
  const imp = await importKubeconfig(text);
  const store = new MemorySecretStore();
  const profile = makeTestProfile({ id: "k1", credentialSource: { kind: "static", ambientDependencies: [] } });
  await store.set(credentialKey(profile.id), new Uint8Array(Buffer.from(JSON.stringify(imp.blob))));
  const broker = new LocalBroker({ store });
  const known = new KnownSecrets();
  const req = (ttlSec = 60): LeaseRequest => ({ profile, purpose: "k8s.resources.list", callId: "c1", ttlSec });
  return { pki, tok, store, profile, broker, known, req };
}

describe("LocalBroker", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolver yalnız lease etkinken malzeme verir; release sonrası lease_inactive", async () => {
    const { broker, known, req, tok, pki } = await setup();
    const lease = await broker.acquire(req(), known);
    expect(broker.activeLeases).toBe(1);
    const cred = broker.resolver.k8s(lease.handle);
    expect(cred.token).toBe(tok.value);
    expect(cred.caPem).toBe(pki.caPem);
    await lease.release();
    expect(broker.activeLeases).toBe(0);
    expect(() => broker.resolver.k8s(lease.handle)).toThrow(expect.objectContaining({ code: "lease_inactive" }));
    await lease.release(); // idempotent
    expect(broker.activeLeases).toBe(0);
  });

  it("tutamaç opaktır: JSON/inspect çıktısında malzeme yok", async () => {
    const { broker, known, req, tok } = await setup();
    const lease = await broker.acquire(req(), known);
    expect(JSON.stringify(lease.handle)).not.toContain(tok.value);
    expect(JSON.stringify(lease)).not.toContain(tok.value);
    expect(String(Object.keys(lease.handle))).not.toMatch(/token|key|pem/i);
    await lease.release();
  });

  it("sahte (broker'a ait olmayan) tutamaç çözülemez", async () => {
    const { broker } = await setup();
    const fake = { kind: "credential-handle", profileId: "k1", leaseId: "x" } as never;
    expect(() => broker.resolver.k8s(fake)).toThrow(expect.objectContaining({ code: "lease_inactive" }));
  });

  it("TTL dolunca lease düşer", async () => {
    vi.useFakeTimers();
    const { broker, known, req } = await setup();
    const lease = await broker.acquire(req(5), known);
    vi.advanceTimersByTime(4_000);
    expect(() => broker.resolver.k8s(lease.handle)).not.toThrow();
    vi.advanceTimersByTime(2_000);
    expect(() => broker.resolver.k8s(lease.handle)).toThrow(expect.objectContaining({ code: "lease_inactive" }));
    expect(broker.activeLeases).toBe(0);
  });

  it("eşzamanlı lease sınırı", async () => {
    const { store, profile, known, req } = await setup();
    const broker = new LocalBroker({ store, maxConcurrentLeases: 2 });
    const a = await broker.acquire(req(), known);
    await broker.acquire(req(), known);
    await expect(broker.acquire(req(), known)).rejects.toMatchObject({ code: "lease_limit" });
    await a.release();
    await expect(broker.acquire({ ...req(), profile }, known)).resolves.toBeDefined();
  });

  it("acquire token/istemci anahtarını M3'e kaydeder (ham ve base64)", async () => {
    const { broker, known, req, tok } = await setup();
    const lease = await broker.acquire(req(), known);
    expect(known.scrub(`hata: ${tok.value}`)).not.toContain(tok.value);
    expect(known.scrub(`b64=${Buffer.from(tok.value).toString("base64")}`)).not.toContain(Buffer.from(tok.value).toString("base64"));
    await lease.release();
  });

  it("prime ilk çağrıdan ÖNCE M3'e kaydeder ve lease açmaz", async () => {
    const { broker, known, profile, tok } = await setup();
    await broker.prime!(profile, known);
    expect(broker.activeLeases).toBe(0);
    expect(known.scrub(`x ${tok.value} y`)).not.toContain(tok.value);
  });

  it("istemci sertifikası kimliğinde özel anahtar M3'e girer", async () => {
    const { broker, known, req, pki } = await setup({ auth: "cert" });
    const lease = await broker.acquire(req(), known);
    const keyLine = pki.clientKeyPem.split("\n").find((l) => l.length > 30)!;
    expect(known.scrub(`leak ${keyLine}`)).not.toContain(keyLine);
    expect(broker.resolver.k8s(lease.handle).clientKeyPem).toBe(pki.clientKeyPem);
    await lease.release();
  });

  it("kasada kimlik yoksa credential_missing; bozuksa credential_corrupt", async () => {
    const { store, profile, known, req } = await setup();
    const empty = new LocalBroker({ store: new MemorySecretStore() });
    await expect(empty.acquire(req(), known)).rejects.toMatchObject({ code: "credential_missing" });
    await store.set(credentialKey(profile.id), new TextEncoder().encode("{bozuk"));
    await expect(new LocalBroker({ store }).acquire(req(), known)).rejects.toMatchObject({ code: "credential_corrupt" });
    expect(new LocalBroker({ store }).activeLeases).toBe(0);
  });

  it("static dışındaki kaynak açık hata verir (sessizce düşmez)", async () => {
    const { broker, known, req } = await setup();
    const exec = makeTestProfile({ id: "e1", credentialSource: { kind: "sts", ambientDependencies: [] } as never });
    await expect(broker.acquire({ ...req(), profile: exec }, known)).rejects.toMatchObject({ code: "credential_source_unsupported" });
  });

  it("hata mesajları secret içermez", async () => {
    const { store, profile, known, req, tok } = await setup();
    await store.set(credentialKey(profile.id), new TextEncoder().encode(`{bozuk ${tok.value}`));
    const err = await new LocalBroker({ store }).acquire(req(), known).catch((e: Error) => e);
    expect(String((err as Error).message)).not.toContain(tok.value);
  });
});
