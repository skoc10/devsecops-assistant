// Süreçler arası kilit testi için ayrı süreçte çalışan yazıcı: aynı günlüğe N kayıt ekler.
// Kullanım: node append-worker.ts <günlük> <çapa> <anahtar-hex> <oturum> <adet>
import { AuditLog, FileAuditStorage, FileHeadAnchor } from "../../src/index.ts";

const [path, anchorPath, keyHex, sessionId, count] = process.argv.slice(2) as [string, string, string, string, string];
const log = await AuditLog.open({
  storage: new FileAuditStorage(path, { fsync: false }),
  key: Buffer.from(keyHex, "hex"),
  anchor: new FileHeadAnchor(anchorPath),
});
for (let i = 0; i < Number(count); i++) await log.append({ event: "intent", sessionId, callId: `${sessionId}-${i}` });
