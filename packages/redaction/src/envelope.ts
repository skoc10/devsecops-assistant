import { randomBytes } from "node:crypto";

/**
 * M6: taint zarfı. Zarf TEK BAŞINA güvenlik sınırı DEĞİLDİR (asıl savunma politikadır: bağlam
 * etiketi → taint altında `ask`); amacı veriyi talimattan ayırt edilebilir kılmak ve gizli
 * kontrol karakterlerini temizlemektir.
 */

// ANSI CSI, OSC, diğer ESC dizileri
const ANSI = /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\)|[@-Z\\-_])/g;
// C0 (\n \t \r hariç), DEL, C1
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;
// Çift yönlü geçersiz kılma ve sıfır genişlikli karakterler (gizli talimat saklamak için kullanılır)
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

export function stripControlChars(s: string): string {
  // `\r` imleci satır başına götürüp önceki metnin üstüne yazdırır: satır sonuna çevrilir (CRLF tek satır sonu olur)
  return s.replace(ANSI, "").replace(/\r\n?/g, "\n").replace(CONTROL, "").replace(INVISIBLE, "");
}

export interface Envelope {
  readonly text: string;
  readonly nonce: string;
}

/** Veriyi, içeriğin taklit edemeyeceği rastgele işaretli bir zarfa koyar. */
export function wrapUntrusted(content: string, source: string): Envelope {
  const nonce = randomBytes(6).toString("hex");
  // içerik zarf etiketini taklit edip erken kapatamasın
  const safe = stripControlChars(content).replace(/<\/?\s*untrusted[^>]*>/gi, "‹etiket›");
  const attrSource = source.replace(/[^A-Za-z0-9._:/-]/g, "_");
  return {
    nonce,
    text: `<untrusted nonce="${nonce}" source="${attrSource}">\n${safe}\n</untrusted nonce="${nonce}">`,
  };
}
