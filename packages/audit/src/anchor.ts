import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Zincir başı çapası (v2): kuyruk kesmeyi tespit için baş ikinci bir konuma yazılır ve zincir anahtarıyla
 * MAC'lenir. Anahtarsız saldırgan, kesilmiş günlüğün son kaydından çapa "üretemez".
 *
 * `since`: çapanın kesintisiz izlediği ilk seq. Çapa yokken ya da doğrulanamazken (MAC'siz eski biçim, sahte,
 * biçimsiz) dolu bir günlüğe yazılırsa çapa o kayıtta yeniden kurulur ve `since` o kaydın seq'i olur. Bu iz
 * MAC kapsamındadır, sonraki çapalara taşınır ve `verifyAudit` onu `anchor_reset` olarak bildirir: çapayı
 * silip/bozup ardından bir yazım yaptırmak kesmeyi "aklamaz".
 *
 * Eski (v1, `{seq, hash}`) çapa: ürün yayın öncesi olduğundan göç yapılmaz ve içeriğine GÜVENİLMEZ.
 * Doğrulama onu `anchor_unauthenticated` olarak bildirir; ilk yazım çapayı `since` > 0 ile yeniden kurar,
 * böylece eski kurulumlarda doğrulama kalıcı bir `anchor_reset` bulgusu gösterir (sessiz güven yok).
 *
 * Sınır: çapa sahteciliğe karşı korur, geri almaya (rollback) karşı değil. Daha önce yazılmış geçerli bir
 * çapa kopyası geri yüklenirse o noktadan sonraki kesme tespit edilemez; çapa günlükle aynı dizindedir.
 */
export interface AnchorRecord {
  readonly v: 2;
  readonly seq: number;
  readonly hash: string;
  readonly since: number;
  readonly mac: string;
}

export type AnchorCheck =
  | { readonly status: "none" }
  | { readonly status: "ok"; readonly seq: number; readonly hash: string; readonly since: number }
  | { readonly status: "unauthenticated"; readonly reason: string };

// Alan ayrımı: çapa MAC girdisi hiçbir zincir hash girdisiyle (`prevHash\n{...}`) çakışamaz.
const DOMAIN = "ops-audit-anchor/v2";
const HEX64 = /^[a-f0-9]{64}$/;

function anchorMac(key: Uint8Array, seq: number, hash: string, since: number): string {
  return createHmac("sha256", key).update(`${DOMAIN}\n${seq}\n${hash}\n${since}`).digest("hex");
}

export function signAnchor(key: Uint8Array, head: { seq: number; hash: string }, since: number): AnchorRecord {
  return { v: 2, seq: head.seq, hash: head.hash, since, mac: anchorMac(key, head.seq, head.hash, since) };
}

const isCount = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * Ham çapa içeriğini (güvenilmez: dosyada JSON metni, bellekte nesne) doğrular. `none` yalnız çapa hiç yoksa;
 * MAC'siz, MAC'i tutmayan ya da biçimsiz çapa `unauthenticated` döner ve içeriği hiçbir karar için kullanılmaz.
 */
export function checkAnchor(key: Uint8Array, raw: unknown): AnchorCheck {
  if (raw === null || raw === undefined) return { status: "none" };
  let a: unknown = raw;
  if (typeof raw === "string") {
    try {
      a = JSON.parse(raw);
    } catch {
      return { status: "unauthenticated", reason: "okunamadı" };
    }
  }
  if (a === null || typeof a !== "object" || Array.isArray(a)) return { status: "unauthenticated", reason: "biçimsiz" };
  const { v, seq, hash, since, mac } = a as Record<string, unknown>;
  if (mac === undefined) return { status: "unauthenticated", reason: "MAC yok (eski biçim)" };
  if (v !== 2 || !isCount(seq) || !isCount(since) || since > seq || typeof hash !== "string" || !HEX64.test(hash) || typeof mac !== "string" || !HEX64.test(mac)) {
    return { status: "unauthenticated", reason: "biçimsiz" };
  }
  if (!timingSafeEqual(Buffer.from(anchorMac(key, seq, hash, since), "hex"), Buffer.from(mac, "hex"))) {
    return { status: "unauthenticated", reason: "MAC geçersiz" };
  }
  return { status: "ok", seq, hash, since };
}
