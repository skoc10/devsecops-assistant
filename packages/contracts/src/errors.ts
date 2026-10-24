/** Ürünün bilinen hata kodları. Mesajlar redakte edilebilir olmalı: secret içermez. */
export class OpsError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;

  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "OpsError";
    this.code = code;
    this.details = details;
  }
}

export function isOpsError(e: unknown): e is OpsError {
  return e instanceof OpsError;
}
