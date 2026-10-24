#!/usr/bin/env node
import { runCli } from "./commands.ts";
import { resolvePaths } from "./paths.ts";

const abort = new AbortController();
process.on("SIGINT", () => abort.abort());
process.on("SIGTERM", () => abort.abort());

const code = await runCli({
  argv: process.argv.slice(2),
  env: process.env,
  io: { input: process.stdin, output: process.stdout, error: process.stderr },
  paths: resolvePaths(),
  stop: abort.signal,
});
process.exit(code);
