import { describe, expect, it } from "vitest";
import { BUILD_REPO, BUILD_SHA } from "@ops/testkit";
import { makeGhHarness } from "./harness.ts";

describe("scm araçları (PEP üzerinden, sahte GitHub)", () => {
  it("file.read: satır aralığı; içerik untrusted; bağlam tainted", async () => {
    const h = await makeGhHarness({ kind: "scm" });
    try {
      const r = await h.call("scm.file.read", { repo: BUILD_REPO, path: "README.md" });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      expect(h.evidenceJson(r)).toMatchObject({ path: "README.md", totalLines: 3, startLine: 1, shownLines: 3 });
      expect(h.evidenceJson(r).content).toContain("# payments");
      const part = await h.call("scm.file.read", { repo: BUILD_REPO, path: "README.md", startLine: 2, maxLines: 1 });
      expect(h.evidenceJson(part)).toMatchObject({ startLine: 2, shownLines: 1, content: "Hello." });
      expect(h.session.context.tainted).toBe(true);
      expect((await h.call("scm.file.read", { repo: BUILD_REPO, path: "nope.txt" })).status).toBe("error");
    } finally {
      await h.stop();
    }
  });

  it("gizli dosya desenleri kimlik kullanılmadan reddedilir: .env, anahtar, tfstate...; API'ye istek gitmez", async () => {
    const h = await makeGhHarness({ kind: "scm" });
    try {
      for (const path of [".env", "deploy/key.pem", "../etc/passwd", "/etc/passwd", ".git/config", "infra/prod.tfvars", "a/.aws/credentials"]) {
        const r = await h.call("scm.file.read", { repo: BUILD_REPO, path });
        expect(r, path).toMatchObject({ status: "denied", reasonCode: "target_unresolved" });
        expect(r.summary).toMatch(/yol reddedildi/);
      }
      expect(h.api.requests.length).toBe(0);
      const sink = await h.sinkFor([]);
      expect(sink.leaks(h.all)).toEqual([]);
    } finally {
      await h.stop();
    }
  });

  it("diff.get: gizli dosyanın yaması VERİLMEZ; diğer yamalar untrusted; secret hiçbir kanalda yok", async () => {
    const h = await makeGhHarness({ kind: "scm" });
    try {
      const r = await h.call("scm.diff.get", { repo: BUILD_REPO, base: "3".repeat(40), head: BUILD_SHA });
      expect(r.status, JSON.stringify(r)).toBe("ok");
      const j = h.evidenceJson(r);
      expect(j.files.map((f: { file: string }) => f.file)).toEqual(["src/app.ts", ".env"]);
      expect(j.files[0].patch).toContain("BATCH = 5000");
      expect(j.files[1].patch).toMatch(/yama verilmedi: gizli dosya deseni: \.env/);
      expect(j.commits[0]).toMatchObject({ sha: BUILD_SHA, author: "dev-ayse" });
      const sink = await h.sinkFor([r]);
      expect(sink.leaks(h.all)).toEqual([]);
      expect(h.session.context.tainted).toBe(true);
    } finally {
      await h.stop();
    }
  });

  it("pr.list ve commit.list: tipli alanlar + serbest metin (başlık/mesaj) yalnız untrusted çıktıda; zaman penceresi", async () => {
    const h = await makeGhHarness({ kind: "scm" });
    try {
      const prs = await h.call("scm.pr.list", { repo: BUILD_REPO, state: "all" });
      const pj = h.evidenceJson(prs);
      expect(pj.items.map((i: { number: number }) => i.number).sort()).toEqual([41, 42]);
      expect(pj.items.find((i: { number: number }) => i.number === 41)).toMatchObject({ state: "closed", head: "feature/batch", base: "main", headSha: BUILD_SHA });
      expect(h.evidence.get(prs.evidenceId!)?.taint).toBe("untrusted");

      const commits = await h.call("scm.commit.list", { repo: BUILD_REPO, since: "2h" });
      const cj = h.evidenceJson(commits);
      expect(cj.items.map((i: { sha: string }) => i.sha)).toEqual([BUILD_SHA]); // diğer commit 2 saat penceresinin dışında
      expect(cj.items[0].message).toMatch(/Raise batch size/);
      expect((await h.call("scm.commit.list", { repo: BUILD_REPO })).reasonCode).toBe("schema_invalid");
      const open = await h.call("scm.pr.list", { repo: BUILD_REPO });
      expect(h.evidenceJson(open).items.map((i: { number: number }) => i.number)).toEqual([42]);
    } finally {
      await h.stop();
    }
  });

  it("pipeline araçları scm profilinde, scm araçları pipeline profilinde ÇALIŞMAZ (tür uyuşmazlığı)", async () => {
    const h = await makeGhHarness({ kind: "scm" });
    try {
      const r = await h.gateway.invoke({ tool: "pipeline.runs.list", args: { repo: BUILD_REPO, since: "1h" }, profile: h.profile.id, providerZone: "local" });
      expect(r.status).toBe("denied");
      expect(h.api.requests.length).toBe(0);
    } finally {
      await h.stop();
    }
    const p = await makeGhHarness({ kind: "pipeline" });
    try {
      const r = await p.gateway.invoke({ tool: "scm.file.read", args: { repo: BUILD_REPO, path: "README.md" }, profile: p.profile.id, providerZone: "local" });
      expect(r.status).toBe("denied");
      expect(p.api.requests.length).toBe(0);
    } finally {
      await p.stop();
    }
  });

  it("doktor (scm): fine-grained uyarı, klasik yazma kapsamı hata", async () => {
    const h = await makeGhHarness({ kind: "scm", oauthScopes: "repo" });
    try {
      const r = await h.doctor();
      expect(r.bindable).toBe(false);
      expect(r.findings.map((f) => f.code)).toContain("classic_write_scope");
    } finally {
      await h.stop();
    }
  });
});
