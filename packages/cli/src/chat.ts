import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { DoctorReport } from "@ops/contracts";
import type { OrchestratorEvent } from "@ops/core";
import { stripControlChars } from "@ops/redaction";

export interface ProfileRow {
  readonly id: string;
  readonly kind: string;
  readonly environment: string;
  readonly classCeiling: string;
  readonly displayName: string;
  readonly bound: boolean;
}

/** Sohbet arayüzünün konuştuğu arka uç: süreç içi çalışma zamanı veya `opsd` istemcisi. */
export interface ChatBackend {
  send(text: string, signal?: AbortSignal): AsyncIterable<OrchestratorEvent>;
  bind(profileId: string): Promise<DoctorReport>;
  profiles(): Promise<ProfileRow[]>;
  usage(): Promise<string>;
}

/** Model/araç kaynaklı her metin terminale basılmadan önce kontrol/ANSI/bidi karakterlerinden arındırılır. */
const safe = (s: string): string => stripControlChars(s);
const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function renderEvent(e: OrchestratorEvent): string | null {
  switch (e.type) {
    case "tool_call":
      return `→ ${safe(e.name)}(${safe(clip(JSON.stringify(e.args ?? {}), 140))})`;
    case "tool_result":
      if (e.status === "ok") return `  ✓ ${e.evidenceId ?? ""} ${safe(clip(e.summary, 160))} (${e.tokens} tok${e.byReference ? ", referansla" : ""})`.replace("  ✓  ", "  ✓ ");
      if (e.status === "denied") return `  ✗ REDDEDİLDİ [${safe(e.reasonCode ?? "policy_deny")}] ${safe(clip(e.summary, 200))}`;
      return `  ✗ HATA [${safe(e.reasonCode ?? "adapter_error")}] ${safe(clip(e.summary, 200))}`;
    case "warning":
      return `⚠ ${safe(e.message)}`;
    case "text":
      return `… ${safe(clip(e.text, 300))}`;
    case "final":
      return `\n${safe(e.text)}\n`;
    case "error":
      return `✗ ${safe(e.code)}: ${safe(e.message)}`;
    case "usage":
      return null;
  }
}

const HELP = [
  "Komutlar:",
  "  /profiles          kayıtlı profilleri listele",
  "  /use <profil-id>   profili doktordan geçirip oturuma bağla",
  "  /usage             token kullanım raporu",
  "  /help              bu yardım",
  "  /quit              çık",
].join("\n");

export function renderDoctor(r: DoctorReport): string {
  const lines = [
    `Doktor: ${r.profileId} — ${r.bindable ? "BAĞLANABİLİR" : "BAĞLANAMAZ"} (bağlantı ${r.connected ? "tamam" : "yok"}, pin ${r.pinOk ? "tamam" : "UYUŞMUYOR"}${r.identity ? `, kimlik ${safe(r.identity)}` : ""}${r.effectiveClass ? `, fiili sınıf ${r.effectiveClass}` : ""}, beyan ${r.declaredCeiling})`,
  ];
  for (const f of r.findings) lines.push(`  [${f.severity}] ${f.code}: ${safe(f.message)}`);
  return lines.join("\n");
}

/** Satır tabanlı sohbet döngüsü. Terminal olmayan girdide de çalışır (test, boru). */
export async function runChat(backend: ChatBackend, io: { input: Readable; output: Writable }): Promise<void> {
  const out = (s: string): void => {
    io.output.write(`${s}\n`);
  };
  const rl = createInterface({ input: io.input, crlfDelay: Infinity });
  out("ops-assistant — /help ile komutlar. Secret'ları sohbete yapıştırmayın.");
  for await (const raw of rl) {
    const line = raw.trim();
    if (line === "") continue;
    if (line.startsWith("/")) {
      const [cmd, ...rest] = line.split(/\s+/);
      if (cmd === "/quit" || cmd === "/exit") break;
      if (cmd === "/help") out(HELP);
      else if (cmd === "/profiles") {
        const rows = await backend.profiles();
        out(rows.length === 0 ? "(kayıtlı profil yok — `ops profile add`)" : rows.map((r) => `${r.bound ? "*" : " "} ${r.id}  ${r.kind}/${r.environment}  tavan ${r.classCeiling}  ${safe(r.displayName)}`).join("\n"));
      } else if (cmd === "/use") {
        const id = rest[0];
        if (!id) out("kullanım: /use <profil-id>");
        else {
          try {
            out(renderDoctor(await backend.bind(id)));
          } catch (e) {
            out(`✗ ${safe(e instanceof Error ? e.message : String(e))}`);
          }
        }
      } else if (cmd === "/usage") out(await backend.usage());
      else out(`bilinmeyen komut: ${safe(cmd ?? "")}. /help`);
      continue;
    }
    for await (const ev of backend.send(line)) {
      const s = renderEvent(ev);
      if (s !== null) out(s);
    }
  }
  rl.close();
}
