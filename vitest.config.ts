import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "packages/adapters/*/test/**/*.test.ts",
      "packages/runtimes/*/test/**/*.test.ts",
      "test/**/*.test.ts",
    ],
    environment: "node",
    testTimeout: 20_000,
    pool: "forks",
  },
});
