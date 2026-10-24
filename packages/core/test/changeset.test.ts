import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FakeApprovalGate } from "@ops/testkit";
import { ChangeStore, createChangeAdapter } from "../src/index.ts";
import { makeHarness } from "./harness.ts";

const dirs: string[] = [];
afterEach(async () => {
  for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
});

async function setup(approve = true) {
  const dir = await mkdtemp(join(tmpdir(), "ops-cs-"));
  dirs.push(dir);
  const gate = new FakeApprovalGate(() => approve);
  const h = await makeHarness({ approval: gate });
  const store = new ChangeStore(join(dir, "changes"));
  let t = Date.parse("2026-10-24T12:00:00Z");
  const change = createChangeAdapter({ store, evidence: h.evidence, sessionId: () => h.session.id, now: () => new Date((t += 1000)) });
  h.registry.register(change.adapter, change.definitions);
  const list = await h.call("k8s.resources.list", { kind: "Pod", namespace: "payments" });
  const args = (over: Record<string, unknown> = {}) => ({
    title: "api replikasını 3 yap",
    summary: "payments/api 0/2 hazır; bellek sınırı yükseltilmeli",
    kind: "k8s-manifest",
    filename: "api.yaml",
    content: "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: api, namespace: payments }\nspec: { replicas: 3 }\n",
    evidence: [list.evidenceId],
    rollback: "kubectl scale deploy/api --replicas=2",
    ...over,
  });
  return { h, store, gate, args, dir };
}

describe("ChangeSet: change.propose + ChangeStore", () => {
  it("ilk kullanımda onay ister (local-write), kayıt 0600/0700, içerik+meta+kanıt özeti yazılır, oturum izni sonraki çağrıyı sormaz", async () => {
    const { h, store, gate, args, dir } = await setup();
    const r = await h.call("change.propose", args());
    expect(r.status, JSON.stringify(r)).toBe("ok");
    expect(gate.requests).toHaveLength(1);
    expect(gate.requests[0]!.summary).toMatchObject({ tool: "change.propose", class: "read" });
    const [cs] = await store.list();
    expect(cs).toMatchObject({ kind: "k8s-manifest", title: "api replikasını 3 yap", sessionId: "s-test", rollback: "kubectl scale deploy/api --replicas=2" });
    expect(cs!.id).toMatch(/^cs-20261024T1200\d\dZ-[0-9a-f]{6}$/);
    expect(cs!.evidence[0]).toMatchObject({ tool: "k8s.resources.list" });
    expect((await stat(join(dir, "changes"))).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, "changes", cs!.id, "api.yaml"))).mode & 0o777).toBe(0o600);
    const got = await store.get(cs!.id);
    expect(got.content).toContain("replicas: 3");
    // ikinci çağrı: oturum yazma izni (taint'siz bağlam)
    const again = await h.call("change.propose", args({ filename: "api2.yaml" }));
    expect(again.status).toBe("ok");
    expect(gate.requests).toHaveLength(1);
    expect((await store.list()).map((x) => x.file.name)).toEqual(["api2.yaml", "api.yaml"]); // yeniden eskiye
  });

  it("onay reddedilirse hiçbir şey yazılmaz", async () => {
    const { h, store, args } = await setup(false);
    expect(await h.call("change.propose", args())).toMatchObject({ reasonCode: "approval_denied" });
    expect(await store.list()).toEqual([]);
  });

  it("secret benzeri içerik/başlık/özet/geri alma ve bilinmeyen kanıt kaydedilmez; dosya adı kaçışı şemada reddedilir", async () => {
    const { h, store, args } = await setup();
    const key = "AKIAABCDEFGHIJKLMNOP";
    for (const over of [{ content: `token: ${key}` }, { title: `anahtar ${key}` }, { summary: `s ${key}` }, { rollback: key }]) {
      const r = await h.call("change.propose", args(over));
      expect(r.status).toBe("error");
      expect(r.summary).toMatch(/secret benzeri/);
    }
    expect((await h.call("change.propose", args({ evidence: ["ev-999"] }))).summary).toMatch(/kanıt bulunamadı/);
    for (const filename of ["../x.yaml", "a/b.yaml", ".hidden", "x y.yaml", "x".repeat(70)]) {
      expect(await h.call("change.propose", args({ filename }))).toMatchObject({ reasonCode: "schema_invalid" });
    }
    expect(await h.call("change.propose", args({ evidence: [] }))).toMatchObject({ reasonCode: "schema_invalid" });
    expect(await store.list()).toEqual([]);
  });

  it("untrusted kanıta dayanan öneri untrusted işaretlenir; kayıt sonradan değiştirilirse get() reddeder (tamper)", async () => {
    const { h, store, args, dir } = await setup();
    const logs = await h.call("k8s.pods.logs", { namespace: "payments", pod: "api-1" });
    const r = await h.call("change.propose", args({ evidence: [logs.evidenceId] }));
    expect(r.taint).toBe("untrusted");
    const [cs] = await store.list();
    await writeFile(join(dir, "changes", cs!.id, "api.yaml"), "spec: { replicas: 0 }\n");
    await expect(store.get(cs!.id)).rejects.toMatchObject({ code: "changeset_tampered" });
    await expect(store.get("../etc/passwd")).rejects.toMatchObject({ code: "changeset_invalid" });
    expect(await readFile(join(dir, "changes", cs!.id, "changeset.json"), "utf8")).toContain('"version": 1');
  });
});
