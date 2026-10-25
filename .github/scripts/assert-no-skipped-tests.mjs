// CI kapısı: vitest JSON raporunda atlanan (skip/todo) test varsa çıkış 1.
// Sandbox, gerçek PostgreSQL, IaC ve gerçek küme (kind) testleri ortam eksikse kendini atlar; CI'da bu sessiz kapsam kaybıdır.
// Gerçek küme testleri (*.kind.test.ts) ayrı yapılandırmada (vitest.kind.config.ts) CI'ın `kind` işinde koşar ve bu kapıdan
// AYRICA geçer. VM gerektiren testler (*.vm.test.ts) varsayılan yapılandırmanın DIŞINDADIR (vitest.vm.config.ts, `pnpm test:vm`):
// bu rapora hiç girmezler, dolayısıyla "atlanmış" sayılmazlar — VM yolu CI'da doğrulanmaz (ADR-0011).
import { readFileSync } from "node:fs";
import { relative } from "node:path";

const file = process.argv[2];
if (!file) {
  console.error("kullanım: node assert-no-skipped-tests.mjs <vitest-report.json>");
  process.exit(2);
}
const report = JSON.parse(readFileSync(file, "utf8"));
const skipped = [];
for (const suite of report.testResults ?? []) {
  for (const t of suite.assertionResults ?? []) {
    if (t.status !== "passed" && t.status !== "failed") skipped.push(`${relative(process.cwd(), suite.name)} › ${t.fullName} (${t.status})`);
  }
}
const total = report.numTotalTests ?? 0;
if (total === 0) {
  console.error("::error::raporda hiç test yok");
  process.exit(1);
}
if (skipped.length > 0) {
  console.error(`::error::${skipped.length} test atlandı (CI ortamı eksik: bubblewrap / PostgreSQL / IaC araçları / kind kümesi — OPS_TEST_KUBECONFIG?)`);
  for (const s of skipped) console.error(`  - ${s}`);
  process.exit(1);
}
console.log(`atlanan test yok (${total} test)`);
