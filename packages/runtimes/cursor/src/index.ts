import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** `cursor-host` betiğinin mutlak yolu (sandbox içinde `node <bu yol>` ile çalıştırılır). */
export const CURSOR_HOST_PATH = join(dirname(fileURLToPath(import.meta.url)), "host-main.ts");

export { CursorRuntime, isAllowedToolName } from "./runtime.ts";
export type { CursorRuntimeConfig } from "./runtime.ts";
export { buildCursorLaunchOptions, assertSafeLaunch, LaunchError, BUILTIN_DENY, encodeName } from "./launch.ts";
export type { LaunchInput } from "./launch.ts";
export { mapSdkMessage } from "./map.ts";
export type { MappedEvent } from "./map.ts";
export type { CursorAgentOptions, CursorCustomTool, CursorSdk, SdkMessage } from "./sdk.ts";
export type { HostToParent, ParentToHost, ToolSpecWire } from "./protocol.ts";
