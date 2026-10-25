import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { diffFile } from "../src/index.ts";

const run = promisify(execFile);
let dir = "";
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ops-diff-"));
  await run("git", ["init", "-q"], { cwd: dir });
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Gerçek `git apply` ile: before + patch = after mı? */
async function roundTrip(before: string | null, after: string | null): Promise<void> {
  const name = "f.txt";
  const d = diffFile(name, before, after);
  if (before === after) {
    expect(d.patch).toBe("");
    return;
  }
  if (before === null) await rm(join(dir, name), { force: true });
  else await writeFile(join(dir, name), before);
  await writeFile(join(dir, "p.patch"), d.patch);
  await run("git", ["apply", "--whitespace=nowarn", "p.patch"], { cwd: dir });
  if (after === null) await expect(readFile(join(dir, name))).rejects.toThrow();
  else expect(await readFile(join(dir, name), "utf8")).toBe(after);
}

describe("diffFile (git apply ile doğrulanır)", () => {
  it("basit değişiklikler, yeni/silinen dosya, satırsonu farkı", async () => {
    await roundTrip("a\nb\nc\n", "a\nB\nc\n");
    await roundTrip("a\nb\nc\n", "a\nb\nc\nd\n");
    await roundTrip("a\nb\nc\n", "b\nc\n");
    await roundTrip(null, "yeni\ndosya\n");
    await roundTrip("eski\n", null);
    await roundTrip("a\nb", "a\nb\n"); // yalnız EOL eklendi
    await roundTrip("a\nb\n", "a\nb"); // yalnız EOL kaldırıldı
    await roundTrip("a\nb", "a\nc"); // ikisi de EOL'suz
    await roundTrip("", "x\n");
    await roundTrip("x\n", "");
    await roundTrip("tek", "tek");
  });

  it("boş dosya oluşturma/silme yamada kaybolmaz (ör. .gitkeep)", async () => {
    expect(diffFile("bos.txt", null, "").patch).toBe("diff --git a/bos.txt b/bos.txt\nnew file mode 100644\n");
    expect(diffFile("bos.txt", "", null).patch).toBe("diff --git a/bos.txt b/bos.txt\ndeleted file mode 100644\n");
    expect(diffFile("bos.txt", "", "").patch).toBe("");
    await roundTrip(null, "");
    await roundTrip("", null);
  });

  it("uzak bölgelerde birden çok hunk", async () => {
    const before = Array.from({ length: 60 }, (_, i) => `satır ${i}`).join("\n") + "\n";
    const after = before.replace("satır 3\n", "DEĞİŞTİ 3\n").replace("satır 30\n", "DEĞİŞTİ 30\n").replace("satır 57\n", "DEĞİŞTİ 57\n");
    const d = diffFile("f.txt", before, after);
    expect(d.patch.match(/^@@/gm)?.length).toBe(3);
    expect(d.additions).toBe(3);
    expect(d.deletions).toBe(3);
    await roundTrip(before, after);
  });

  it("çok büyük dosya: tam değiştirme düşüşü yine uygulanabilir", async () => {
    const before = Array.from({ length: 4_000 }, (_, i) => `a${i}`).join("\n") + "\n";
    const after = Array.from({ length: 4_000 }, (_, i) => `b${i}`).join("\n") + "\n";
    await roundTrip(before, after);
  });

  it("özellik: rastgele satır dizileri için patch uygulanınca sonuç = after", async () => {
    const line = fc.constantFrom("a", "b", "c", "d", "", " ", "x y", "}", "{");
    await fc.assert(
      fc.asyncProperty(fc.array(line, { maxLength: 25 }), fc.array(line, { maxLength: 25 }), fc.boolean(), fc.boolean(), fc.boolean(), fc.boolean(), async (a, b, eolA, eolB, absentA, absentB) => {
        const before = a.length === 0 ? "" : a.join("\n") + (eolA ? "\n" : "");
        const after = b.length === 0 ? "" : b.join("\n") + (eolB ? "\n" : "");
        // boş içerik: dosya yok (null) ya da var ama boş ("") — ikisi de denenir
        const bef = before === "" && absentA ? null : before;
        const aft = after === "" && absentB ? null : after;
        await roundTrip(bef, aft);
        return true;
      }),
      { numRuns: 120 },
    );
  }, 120_000);
});
