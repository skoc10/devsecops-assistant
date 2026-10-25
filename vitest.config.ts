import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "packages/adapters/*/test/**/*.test.ts",
      "packages/runtimes/*/test/**/*.test.ts",
      "test/**/*.test.ts",
    ],
    // Ayrı yapılandırmalarda koşanlar ana koşuya girmez, "atlanan test yok" kapısında görünmez:
    //  - gerçek küme (kind) testleri: vitest.kind.config.ts / `pnpm test:kind`, CI'da `kind` işi (kendi kapısıyla);
    //  - VM gerektiren testler: vitest.vm.config.ts / `pnpm test:vm`, CI'da koşmaz (ADR-0011).
    exclude: [...configDefaults.exclude, "**/*.kind.test.ts", "**/*.vm.test.ts"],
    environment: "node",
    testTimeout: 20_000,
    pool: "forks",
    // macOS'ta varsayılan koşu VM'i KULLANMAZ (geçici dizinler paylaşım altında olmazdı; VM takımı `pnpm test:vm`).
    // Linux'ta dokunulmaz: CI bwrap'ı tespit eder. Kullanıcı OPS_SANDBOX'ı kendisi verdiyse korunur.
    env: process.platform === "darwin" && !process.env["OPS_SANDBOX"] ? { OPS_SANDBOX: "none" } : {},
  },
});
