/** Anahtarları sıralı, `undefined` alanları atılmış kararlı JSON (hash girdisi için). */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    // Prototipsiz nesne: `__proto__` adlı anahtar (JSON.parse onu kendi alanı yapar) prototip ayarlayıcısına
    // düşüp MAC girdisinden SESSİZCE düşmez; her kendi anahtarı temsil edilir. Olağan kayıtlarda çıktı
    // bayt bayt aynıdır (anahtar sırası kuralları prototipten bağımsızdır): mevcut günlükler doğrulanmaya devam eder.
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}
