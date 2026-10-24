import type { PolicyDocument } from "./schema.ts";

/**
 * Varsayılan politika: kural yok, yalnız bütçeler. Taban davranış koddadır (okuma serbest;
 * mutate+ ve yerel yazma `ask`; tavan ve taint sert kontrolleri).
 */
export const DEFAULT_POLICY: PolicyDocument = {
  version: 1,
  budgets: {
    maxToolCalls: 60,
    maxResultTokens: 1500,
    softSessionTokens: 150_000,
    hardSessionTokens: 400_000,
  },
  rules: [],
};
