/**
 * Pin karşılaştırması için uç noktayı normalleştirir. `host:port` biçimi URL olarak AYRIŞTIRILMAZ
 * (`db.example:5432` bir şema sanılır). Küçük harf, varsayılan port ve sondaki `/` atılır.
 */
export function normalizeEndpoint(endpoint: string): string {
  const raw = endpoint.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const defPort = u.protocol === "https:" ? "443" : u.protocol === "http:" ? "80" : "";
      const port = u.port && u.port !== defPort ? `:${u.port}` : "";
      return `${u.protocol.toLowerCase()}//${u.hostname.toLowerCase()}${port}${u.pathname.replace(/\/+$/, "")}`;
    } catch {
      return raw.toLowerCase();
    }
  }
  return raw.toLowerCase().replace(/\/+$/, "");
}
