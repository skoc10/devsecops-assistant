export { Counter, redacted, isRedactedToken, mapStrings } from "./counter.ts";
export { PATTERN_RULES, applyPatternRules, looksLikeHighEntropySecret } from "./patterns.ts";
export type { PatternRule, PatternOptions } from "./patterns.ts";
export { KnownSecrets, secretNeedles, canonicalNeedles, MIN_KNOWN_SECRET_BYTES } from "./known.ts";
export { applyStructural, registerProfile, getProfile, DEFAULT_PROFILE } from "./structural.ts";
export type { StructuralProfile } from "./structural.ts";
export {
  DEFAULT_MASKING,
  DEFAULT_COLUMN_RULES,
  MaskingContext,
  maskByDetectors,
  maskTable,
} from "./masking.ts";
export type { ColumnRule, MaskAction, MaskingRules, Table } from "./masking.ts";
export { truncateString, clampList } from "./limits.ts";
export { stripControlChars, wrapUntrusted } from "./envelope.ts";
export type { Envelope } from "./envelope.ts";
export {
  buildTrie,
  projectFields,
  dropEmpty,
  tabulateDeep,
  clampListsDeep,
  clusterLogLines,
  normalizeLogLine,
  fitToTokens,
  compactForModel,
} from "./compact.ts";
export type { Compacted, CompactOptions, LogCluster, LogView, TableView, ListWrapper } from "./compact.ts";
export { processOutput, scrubText } from "./pipeline.ts";
export type { OutputPolicy, ProcessedOutput } from "./pipeline.ts";
