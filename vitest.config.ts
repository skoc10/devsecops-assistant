import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "packages/adapters/*/test/**/*.test.ts",
      "packages/runtimes/*/test/**/*.test.ts",
      "test/**/*.test.ts",
    ],
    // VM gerektiren testler ayrı yapılandırmadadır (vitest.vm.config.ts / `pnpm test:vm`): CI'da koşmaz ve
    // "atlanan test yok" kapısında görünmez (ADR-0011).
    exclude: ["**/node_modules/**", "**/*.vm.test.ts"],
    environment: "node",
    testTimeout: 20_000,
    pool: "forks",
    // macOS'ta varsayılan koşu VM'i KULLANMAZ (geçici dizinler paylaşım altında olmazdı; VM takımı `pnpm test:vm`).
    // Linux'ta dokunulmaz: CI bwrap'ı tespit eder. Kullanıcı OPS_SANDBOX'ı kendisi verdiyse korunur.
    env: process.platform === "darwin" && !process.env["OPS_SANDBOX"] ? { OPS_SANDBOX: "none" } : {},
  },
});
