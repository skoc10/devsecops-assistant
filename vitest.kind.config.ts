import { defineConfig } from "vitest/config";

/**
 * Gerçek Kubernetes kümesine (CI'da `kind`) karşı entegrasyon testleri. Küme `OPS_TEST_KUBECONFIG` (yönetici
 * kubeconfig yolu) ile verilir; yoksa testler atlanır. CI'da atlanan test kapısı bu koşuda da çalışır.
 * Testler aynı kümeyi paylaşır: dosyalar sırayla koşar.
 */
export default defineConfig({
  test: {
    include: ["packages/**/test/**/*.kind.test.ts"],
    exclude: ["**/node_modules/**"],
    environment: "node",
    testTimeout: 120_000,
    hookTimeout: 240_000,
    pool: "forks",
    fileParallelism: false,
  },
});
