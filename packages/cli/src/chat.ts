import type { EventEmitter } from "node:events";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { DoctorReport, RiskClass } from "@ops/contracts";
import { RISK_CLASSES } from "@ops/contracts";
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

/** Break-glass başlatma isteği (tel biçimi): yeniden kimlik doğrulama kanıtı İSTEMCİDE üretilir, parola taşınmaz. */
export interface BreakGlassStartArgs {
  readonly profile: string;
  readonly ceiling: RiskClass;
  readonly ttlSec: number;
  readonly reason: string;
  readonly reauth: { readonly method: string; readonly verifiedAtMs: number };
}

/** Sohbet arayüzünün konuştuğu arka uç: süreç içi çalışma zamanı veya `opsd` istemcisi. */
export interface ChatBackend {
  send(text: string, signal?: AbortSignal): AsyncIterable<OrchestratorEvent>;
  bind(profileId: string): Promise<DoctorReport>;
  profiles(): Promise<ProfileRow[]>;
  usage(): Promise<string>;
  /** Kanıtın (karantinadaki dahil) redakte içeriğini YALNIZ kullanıcı ekranı için döndürür; modele GİTMEZ. */
  evidenceShow(id: string): Promise<string>;
  /** Karantinadaki kanıtın ham içeriğini modele açar (bağlam, içerik alındığında tainted olur). */
  evidenceRelease(id: string): Promise<string>;
  /** Etkin break-glass banner satırları (boşsa yok). */
  breakGlassStatus(): Promise<string[]>;
  breakGlassStart(a: BreakGlassStartArgs): Promise<string[]>;
  breakGlassEnd(profileId: string): Promise<string>;
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
    case "plan":
      return safe(e.text);
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
  "  /show <ev-id>      kanıtın (karantinadaki ham logu dahil) redakte içeriğini YALNIZ ekranınıza basar; modele gitmez",
  "  /raw <ev-id>       karantinadaki ham içeriği modele açar (bağlam güvenilmez içerik alır; denetime yazılır)",
  "  /breakglass start <profil> <tavan> <süre> <gerekçe…>   geçici tavan yükseltme (≤30dk; yeniden kimlik doğrulama + gerekçe zorunlu)",
  "  /breakglass end <profil> | status",
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

export interface ChatOptions {
  readonly approvalEvents?: EventEmitter;
  /** Yeniden kimlik doğrulama (kontrol terminalinden). Yoksa `/breakglass start` reddedilir. */
  readonly reauth?: () => Promise<{ method: string; verifiedAtMs: number }>;
  /** Ctrl-C / SIGTERM: süren tur iptal edilir ve sohbet kapanır (takılmış model çağrısı süreci kilitlemez). */
  readonly stop?: AbortSignal;
}

/** Yineleyiciyi sinyal gelince bırakır: uzak arka uç sinyali tanımasa da döngü takılı kalmaz. */
async function* untilAborted<T>(source: AsyncIterable<T>, signal: AbortSignal): AsyncGenerator<T> {
  const it = source[Symbol.asyncIterator]();
  const aborted = new Promise<IteratorResult<T>>((resolve) => {
    if (signal.aborted) resolve({ done: true, value: undefined });
    else signal.addEventListener("abort", () => resolve({ done: true, value: undefined }), { once: true });
  });
  try {
    for (;;) {
      const r = await Promise.race([it.next(), aborted]);
      if (r.done) return;
      yield r.value;
    }
  } finally {
    void it.return?.();
  }
}

const DURATION = /^(\d{1,6})([smh]?)$/i;
function parseTtl(t: string): number | null {
  const m = DURATION.exec(t);
  if (!m) return null;
  const n = Number(m[1]);
  const u = (m[2] ?? "s").toLowerCase();
  return u === "h" ? n * 3600 : u === "m" ? n * 60 : n;
}

/** Satır tabanlı sohbet döngüsü. Terminal olmayan girdide de çalışır (test, boru). */
export async function runChat(backend: ChatBackend, io: { input: Readable; output: Writable }, opts: ChatOptions = {}): Promise<void> {
  const out = (s: string): void => {
    io.output.write(`${s}\n`);
  };
  const rl = createInterface({ input: io.input, crlfDelay: Infinity });
  // Girdi biterse (boru/dosya) arayüz kapanır ama yineleyici tamponlu satırları vermeye devam eder. Node 24, kapalı
  // arayüzde pause/resume'u `ERR_USE_AFTER_CLOSE` ile reddeder (Node 22 sessizce yok sayıyordu): onay/yeniden doğrulama
  // sırasında duraklatma kapanmışsa atlanır (Node 24 CI matrisinde bulundu).
  let rlClosed = false;
  rl.once("close", () => {
    rlClosed = true;
  });
  const pauseInput = (): void => {
    if (!rlClosed) rl.pause();
  };
  const resumeInput = (): void => {
    if (!rlClosed) rl.resume();
  };
  let turn: AbortController | null = null;
  const onStop = (): void => {
    turn?.abort();
    rl.close();
  };
  if (opts.stop?.aborted) onStop();
  else opts.stop?.addEventListener("abort", onStop, { once: true });
  // Onay istemi kontrol terminalinden okunur; sohbet girdisi o sırada DURAKLATILIR ki yanıt
  // sohbet satırı olarak (modele) gitmesin.
  opts.approvalEvents?.on("start", pauseInput);
  opts.approvalEvents?.on("end", resumeInput);
  out("ops-assistant — /help ile komutlar. Secret'ları sohbete yapıştırmayın.");
  // Kalıcı banner: etkin break-glass varken her istemden önce yeniden basılır.
  const banner = async (): Promise<void> => {
    try {
      for (const l of await backend.breakGlassStatus()) out(safe(l));
    } catch {
      /* banner yardımcıdır; sohbeti bozmasın */
    }
  };
  // Yineleyici banner'dan ÖNCE kurulur: aksi halde banner beklenirken gelen satırlar kaybolur.
  const lines = rl[Symbol.asyncIterator]();
  await banner();
  for (;;) {
    const next = await lines.next();
    if (next.done) break;
    const line = String(next.value).trim();
    if (line === "") continue;
    try {
      await handleLine(line);
    } catch (e) {
      if (e === QUIT) break;
      throw e;
    }
    await banner();
  }
  opts.stop?.removeEventListener("abort", onStop);
  rl.close();

  async function handleLine(line: string): Promise<void> {
    if (line.startsWith("/")) {
      const [cmd, ...rest] = line.split(/\s+/);
      if (cmd === "/quit" || cmd === "/exit") throw QUIT;
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
      else if (cmd === "/show" || cmd === "/raw") {
        const id = rest[0];
        if (!id || !/^ev-\d+$/.test(id)) out(`kullanım: ${cmd} <ev-id>  (ör. ${cmd} ev-3)`);
        else {
          try {
            out(safe(cmd === "/show" ? await backend.evidenceShow(id) : await backend.evidenceRelease(id)));
          } catch (e) {
            out(`✗ ${safe(e instanceof Error ? e.message : String(e))}`);
          }
        }
      }
      else if (cmd === "/breakglass") await breakGlassCommand(rest);
      else out(`bilinmeyen komut: ${safe(cmd ?? "")}. /help`);
      return;
    }
    const ac = new AbortController();
    turn = ac;
    try {
      for await (const ev of untilAborted(backend.send(line, ac.signal), ac.signal)) {
        const s = renderEvent(ev);
        if (s !== null) out(s);
      }
      if (ac.signal.aborted) out("⏹ tur iptal edildi");
    } finally {
      turn = null;
    }
  }

  async function breakGlassCommand(args: string[]): Promise<void> {
    const [sub, ...r] = args;
    try {
      if (sub === undefined || sub === "status") {
        const st = await backend.breakGlassStatus();
        out(st.length ? st.map(safe).join("\n") : "(etkin break-glass yok)");
      } else if (sub === "end") {
        if (!r[0]) out("kullanım: /breakglass end <profil>");
        else out(safe(await backend.breakGlassEnd(r[0])));
      } else if (sub === "start") {
        const [profile, ceiling, ttl, ...reason] = r;
        const ttlSec = ttl ? parseTtl(ttl) : null;
        if (!profile || !ceiling || ttlSec === null || reason.length === 0) {
          out("kullanım: /breakglass start <profil> <mutate|deploy|destroy> <süre: 30m|90s> <gerekçe…>");
        } else if (!(RISK_CLASSES as readonly string[]).includes(ceiling)) {
          out(`✗ tavan şunlardan biri olmalı: ${RISK_CLASSES.join(", ")}`);
        } else if (!opts.reauth) {
          out("✗ yeniden kimlik doğrulama bu arayüzde yapılandırılmamış: break-glass başlatılamaz");
        } else {
          // yanıt sohbet satırı olarak (modele) gitmesin: sohbet girdisi duraklatılır, parola kontrol terminalinden okunur
          pauseInput();
          let proof: { method: string; verifiedAtMs: number };
          try {
            proof = await opts.reauth();
          } finally {
            resumeInput();
          }
          const lines = await backend.breakGlassStart({ profile, ceiling: ceiling as RiskClass, ttlSec, reason: reason.join(" "), reauth: proof });
          for (const l of lines) out(safe(l));
        }
      } else out("kullanım: /breakglass start|end|status");
    } catch (e) {
      out(`✗ ${safe(e instanceof Error ? e.message : String(e))}`);
    }
  }
}

const QUIT = Symbol("quit");
