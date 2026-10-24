export { parseShell, MAX_COMMAND_CHARS } from "./shell-parse.ts";
export type { Connector, ParseResult, SimpleCommand } from "./shell-parse.ts";
export { parseCatalog, mergeCatalogs, CatalogSchema } from "./catalog.ts";
export type { CommandCatalog, CommandEntryT, SubcommandT } from "./catalog.ts";
export { classifyShell, classifyCommand, checkJailedPath } from "./classify.ts";
export type { ClassifyResult, ExecPlan, ResolvedCommand } from "./classify.ts";
export { shellCommandClassifier } from "./gateway.ts";
