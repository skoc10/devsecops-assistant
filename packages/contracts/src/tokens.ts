/**
 * Token tahmini (sağlayıcıdan bağımsız, kaba). Gerçek sayım sağlayıcıdan gelen `usage` ile yapılır;
 * bu yalnız bütçe/tavan kararları ve kompaktlaştırma içindir. JSON ve Türkçe karışık içerik için
 * ~3,5 bayt/token varsayılır (yüksek tarafta kalmak için).
 */
export function estimateTokens(text: string): number {
  if (text.length === 0) return 0;
  const bytes = Buffer.byteLength(text, "utf8");
  return Math.ceil(bytes / 3.5);
}
