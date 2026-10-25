import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isOpsError } from "@ops/contracts";
import {
  AuditLog,
  canonicalJson,
  FileAuditStorage,
  FileHeadAnchor,
  MemoryAuditStorage,
  MemoryHeadAnchor,
  verifyAudit,
} from "../src/index.ts";
import { chainHash } from "../src/chain.ts";

const key = randomBytes(32);
const base = { event: "intent" as const, sessionId: "s1" };

async function fill(log: AuditLog, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    await log.append({ ...base, callId: `c${i}`, tool: "k8s.resources.list", decision: "allow", reasonCode: "allowed" });
  }
}

describe("hash zinciri (S-08)", () => {
  it("kayıtları zincirler ve doğrulama temiz geçer", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await fill(log, 5);
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(true);
    expect(v.records).toBe(5);
    expect(v.head?.seq).toBe(4);
    const second = JSON.parse(storage.lines[1] as string) as { prevHash: string };
    const first = JSON.parse(storage.lines[0] as string) as { hash: string };
    expect(second.prevHash).toBe(first.hash);
  });

  it("ortadaki kaydın değiştirilmesini yakalar", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await fill(log, 4);
    const rec = JSON.parse(storage.lines[2] as string) as Record<string, unknown>;
    rec["decision"] = "deny";
    storage.lines[2] = JSON.stringify(rec);
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(false);
    expect(v.problems.some((p) => p.code === "hash_mismatch" && p.seq === 2)).toBe(true);
  });

  it("ortadaki kaydın silinmesini yakalar", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await fill(log, 5);
    storage.lines.splice(2, 1);
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.code)).toContain("seq_gap");
  });

  it("yeniden sıralamayı yakalar", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await fill(log, 4);
    const [a, b] = [storage.lines[1] as string, storage.lines[2] as string];
    storage.lines[1] = b;
    storage.lines[2] = a;
    expect((await verifyAudit(storage, key)).ok).toBe(false);
  });

  it("anahtarsız saldırgan günlüğü baştan yazarsa gerçek anahtarla doğrulanmaz", async () => {
    const real = new MemoryAuditStorage();
    await fill(await AuditLog.open({ storage: real, key }), 3);
    const forged = new MemoryAuditStorage();
    await fill(await AuditLog.open({ storage: forged, key: randomBytes(32) }), 3);
    const v = await verifyAudit(forged, key);
    expect(v.ok).toBe(false);
    expect(v.problems[0]?.code).toBe("hash_mismatch");
  });

  it("kuyruk kesmeyi yalnız çapa varsa tespit eder (sınır belgelenmiş)", async () => {
    const storage = new MemoryAuditStorage();
    const anchor = new MemoryHeadAnchor();
    await fill(await AuditLog.open({ storage, key, anchor }), 6);
    storage.lines.splice(4); // son 2 kaydı kes
    // çapasız: kesme fark edilmez (tamper-önleme değil, kısmî tespit)
    expect((await verifyAudit(storage, key)).ok).toBe(true);
    // çapalı: yakalanır
    const v = await verifyAudit(storage, key, anchor);
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.code)).toContain("tail_truncated");
  });

  it("kesilmiş günlüğü yeniden AÇMAYI reddeder", async () => {
    const storage = new MemoryAuditStorage();
    const anchor = new MemoryHeadAnchor();
    await fill(await AuditLog.open({ storage, key, anchor }), 4);
    storage.lines.splice(2);
    await expect(AuditLog.open({ storage, key, anchor })).rejects.toMatchObject({ code: "audit_truncated" });
  });

  it("bozuk son kaydı olan günlüğü açmayı reddeder", async () => {
    const storage = new MemoryAuditStorage();
    await fill(await AuditLog.open({ storage, key }), 2);
    storage.lines[1] = "{bozuk";
    await expect(AuditLog.open({ storage, key })).rejects.toMatchObject({ code: "audit_corrupt" });
  });

  it("açıp devam ettiğinde zincir sürer", async () => {
    const storage = new MemoryAuditStorage();
    await fill(await AuditLog.open({ storage, key }), 2);
    await fill(await AuditLog.open({ storage, key }), 2);
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(true);
    expect(v.records).toBe(4);
  });

  it("eşzamanlı yazımlar sıralı ve geçerli bir zincir üretir", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await Promise.all(Array.from({ length: 40 }, (_, i) => log.append({ ...base, callId: `p${i}` })));
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(true);
    expect(v.records).toBe(40);
  });
});

describe("kanonik JSON (MAC girdisi)", () => {
  const prev = "0".repeat(64);
  const withProto = (inner: string) =>
    JSON.parse(`{"ts":"t","event":"intent","sessionId":"s","principal":"p","seq":0,"prevHash":"${prev}","argsRedacted":{"path":"/safe","__proto__":${inner}}}`) as unknown;

  it("`__proto__` anahtarı MAC girdisinden düşmez: yalnız onunla ayrışan iki kaydın hash'i farklıdır", () => {
    const a = withProto('{"path":"/etc/shadow"}');
    const b = withProto('{"path":"TAMAMEN BAŞKA"}');
    expect(canonicalJson(a)).toContain('"__proto__":{"path":"/etc/shadow"}');
    expect(chainHash(key, prev, a)).not.toBe(chainHash(key, prev, b));
    // ilkel değerli `__proto__` da (ayarlayıcı sessizce yutardı) girdide kalır
    expect(canonicalJson(withProto("1"))).toContain('"__proto__":1');
  });

  it("olağan kayıtta çıktı bayt bayt aynı kalır (mevcut günlükler doğrulanmaya devam eder)", () => {
    // Beklenen değerler düzeltme ÖNCESİ uygulamayla üretildi; tamsayı biçimli anahtar sırası dahil.
    const fixedKey = new Uint8Array(32).fill(0x2a);
    const p = "ab".repeat(32);
    const rec = {
      ts: "2026-02-03T04:05:06.000Z",
      event: "intent",
      sessionId: "s-1",
      principal: "local-user",
      callId: "c1",
      tool: "k8s.resources.list",
      decision: "allow",
      reasonCode: "allowed",
      seq: 7,
      prevHash: p,
      message: 'çğış ‹r›   "tırnak"',
      target: undefined,
      argsRedacted: { namespace: "default", "10": "on", "2": "iki", b: [3, { z: null, a: true, u: undefined }], A: { constructor: "c", toString: "t" } },
      redactionCounts: { secret: 2, email: 1 },
      tokens: { output: 2, input: 1, cacheRead: 0 },
    };
    expect(canonicalJson(rec)).toBe(
      `{"argsRedacted":{"2":"iki","10":"on","A":{"constructor":"c","toString":"t"},"b":[3,{"a":true,"z":null}],"namespace":"default"},"callId":"c1","decision":"allow","event":"intent","message":"çğış ‹r›   \\"tırnak\\"","prevHash":"${p}","principal":"local-user","reasonCode":"allowed","redactionCounts":{"email":1,"secret":2},"seq":7,"sessionId":"s-1","tokens":{"cacheRead":0,"input":1,"output":2},"tool":"k8s.resources.list","ts":"2026-02-03T04:05:06.000Z"}`,
    );
    expect(chainHash(fixedKey, p, rec)).toBe("432a7ffa712e854e307e002d3dcfc0bce8108a4788b18a5a760d41437e434cf7");
  });

  it("anahtarsız düzenleme: argsRedacted'e `__proto__` eklenen kayıt doğrulanmaz", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await log.append({ ...base, callId: "c1", tool: "k8s.resources.list", argsRedacted: { namespace: "default" } });
    await log.append({ ...base, event: "result", callId: "c1" });
    storage.lines[0] = (storage.lines[0] as string).replace(
      '{"namespace":"default"}',
      '{"namespace":"default","__proto__":{"command":"kubectl delete ns prod --force"}}',
    );
    const v = await verifyAudit(storage, key);
    expect(v.ok).toBe(false);
    expect(v.problems).toContainEqual(expect.objectContaining({ seq: 0, code: "hash_mismatch" }));
  });

  it("yazım yolu `__proto__` argüman anahtarını korur ve kayıt doğrulanır", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key, scrub: (s) => s.replaceAll("GIZLI", "‹r›") });
    const args = JSON.parse('{"namespace":"default","__proto__":{"allNamespaces":true,"note":"GIZLI"}}') as unknown;
    const rec = await log.append({ ...base, callId: "c1", tool: "k8s.resources.list", argsRedacted: args });
    expect(Object.keys(rec.argsRedacted as object)).toEqual(["namespace", "__proto__"]);
    expect(storage.lines[0]).toContain('"__proto__":{"allNamespaces":true,"note":"‹r›"}');
    expect((await verifyAudit(storage, key)).ok).toBe(true);
  });
});

describe("fail-closed (S-08)", () => {
  it("depolama hatasında append reddedilir ve günlük bozuk işaretlenir", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    await log.append({ ...base });
    storage.failNext = true;
    const err = await log.append({ ...base }).catch((e: unknown) => e);
    expect(isOpsError(err) && err.code).toBe("audit_unavailable");
    expect(log.broken).toBe(true);
    // depo düzelse bile bozuk günlük kayıt kabul etmez: çağıran araç çağrısını çalıştırmamalı
    await expect(log.append({ ...base })).rejects.toMatchObject({ code: "audit_unavailable" });
    expect(storage.lines).toHaveLength(1);
  });

  it("çapa yazma hatası da fail-closed", async () => {
    const storage = new MemoryAuditStorage();
    const anchor = new MemoryHeadAnchor();
    const log = await AuditLog.open({ storage, key, anchor });
    anchor.failNext = true;
    await expect(log.append({ ...base })).rejects.toMatchObject({ code: "audit_unavailable" });
    expect(log.broken).toBe(true);
  });

  it("çağıran hatası (şema dışı alan) günlüğü bozmaz", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({ storage, key });
    const bad = { ...base, rawOutput: "ham çıktı" } as never;
    await expect(log.append(bad)).rejects.toMatchObject({ code: "audit_invalid_entry" });
    expect(log.broken).toBe(false);
    await expect(log.append({ ...base })).resolves.toBeTruthy();
  });

  it("kısa anahtarı reddeder", async () => {
    await expect(AuditLog.open({ storage: new MemoryAuditStorage(), key: new Uint8Array(4) })).rejects.toMatchObject({
      code: "audit_key_invalid",
    });
  });
});

describe("içerik temizliği", () => {
  it("scrub kancası metin ve argüman alanlarına uygulanır; büyük çıktı/argüman kısaltılır", async () => {
    const storage = new MemoryAuditStorage();
    const log = await AuditLog.open({
      storage,
      key,
      scrub: (s) => s.replaceAll("GIZLI", "‹r›"),
      maxOutputChars: 20,
      maxArgsChars: 60,
    });
    const rec = await log.append({
      ...base,
      message: "token GIZLI burada",
      argsRedacted: { a: "GIZLI", b: ["x GIZLI"] },
      outputRedacted: `GIZLI ${"y".repeat(100)}`,
    });
    expect(rec.message).toBe("token ‹r› burada");
    expect(rec.argsRedacted).toEqual({ a: "‹r›", b: ["x ‹r›"] });
    expect(rec.outputRedacted?.endsWith("…[kesildi]")).toBe(true);
    expect(JSON.stringify(rec)).not.toContain("GIZLI");

    const big = await log.append({ ...base, argsRedacted: { v: "z".repeat(500) } });
    expect(big.argsRedacted).toMatchObject({ _truncated: true });
  });

  it("ts ve principal doldurulur", async () => {
    const log = await AuditLog.open({
      storage: new MemoryAuditStorage(),
      key,
      now: () => new Date("2026-02-03T04:05:06Z"),
    });
    const rec = await log.append({ ...base });
    expect(rec.ts).toBe("2026-02-03T04:05:06.000Z");
    expect(rec.principal).toBe("local-user");
  });
});

describe("dosya depolama", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ops-audit-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("0600 dosya, 0700 dizin; yeniden açılınca zincir sürer ve doğrulanır", async () => {
    const path = join(dir, "audit", "audit.jsonl");
    const anchorPath = join(dir, "anchor", "head.json");
    const mk = () =>
      AuditLog.open({ storage: new FileAuditStorage(path), key, anchor: new FileHeadAnchor(anchorPath) });
    await fill(await mk(), 3);
    await fill(await mk(), 2);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, "audit"))).mode & 0o777).toBe(0o700);
    expect((await stat(anchorPath)).mode & 0o777).toBe(0o600);
    const v = await verifyAudit(new FileAuditStorage(path), key, new FileHeadAnchor(anchorPath));
    expect(v.ok).toBe(true);
    expect(v.records).toBe(5);
  });

  it("dosyadan bir bayt değişince doğrulama kırılır", async () => {
    const path = join(dir, "audit.jsonl");
    await fill(await AuditLog.open({ storage: new FileAuditStorage(path), key }), 3);
    const text = await readFile(path, "utf8");
    await writeFile(path, text.replace('"allow"', '"deny"'));
    const v = await verifyAudit(new FileAuditStorage(path), key);
    expect(v.ok).toBe(false);
  });
});
