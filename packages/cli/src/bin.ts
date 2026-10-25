#!/usr/bin/env node
import { runCli } from "./commands.ts";
import { resolvePaths } from "./paths.ts";

const abort = new AbortController();
// İlk Ctrl-C: süren iş (sohbet turu / daemon) düzgünce durdurulur. İkincisi: takılmış istem ne olursa olsun çık.
let interrupts = 0;
process.on("SIGINT", () => {
  interrupts += 1;
  if (interrupts > 1) process.exit(130);
  abort.abort();
});
process.on("SIGTERM", () => abort.abort());

const code = await runCli({
  argv: process.argv.slice(2),
  env: process.env,
  io: { input: process.stdin, output: process.stdout, error: process.stderr },
  paths: resolvePaths(),
  stop: abort.signal,
});
process.exit(code);
