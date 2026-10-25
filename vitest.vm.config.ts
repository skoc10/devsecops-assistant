import { defineConfig } from "vitest/config";

/**
 * Sandbox VM'ine karşı koşan takım (ADR-0011): VM'e özgü testler + sandbox gerektiren MEVCUT takımlar.
 * `vm/run-vm-tests.sh` ortamı kurar (OPS_SANDBOX=vm, OPS_TEST_VM=1, paylaşım altında TMPDIR) ve bunu çağırır.
 */
export default defineConfig({
  test: {
    include: [
      "packages/sandbox/test/**/*.test.ts",
      "packages/terminal/test/**/*.test.ts",
      "packages/workspace/test/**/*.test.ts",
      "packages/adapters/iac/test/**/*.test.ts",
      "packages/mcp-bridge/test/**/*.test.ts",
      "packages/cli/test/terminal-e2e.test.ts",
      "packages/cli/test/iac-e2e.test.ts",
    ],
    environment: "node",
    // ssh üzerinden her çağrı ~50 ms ek; IaC init/plan dakikaya yaklaşabilir
    testTimeout: 180_000,
    hookTimeout: 180_000,
    pool: "forks",
  },
});
