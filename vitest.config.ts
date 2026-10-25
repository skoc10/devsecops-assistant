import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "packages/adapters/*/test/**/*.test.ts",
      "packages/runtimes/*/test/**/*.test.ts",
      "test/**/*.test.ts",
    ],
    // Gerçek küme (kind) testleri ayrı yapılandırmada koşar (`pnpm test:kind`, CI'da `kind` işi): ana koşuda
    // kümesiz atlanıp "atlanan test yok" kapısını düşürmesinler.
    exclude: [...configDefaults.exclude, "**/*.kind.test.ts"],
    environment: "node",
    testTimeout: 20_000,
    pool: "forks",
  },
});
