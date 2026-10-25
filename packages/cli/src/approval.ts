import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { ApprovalGate, ApprovalOutcome, ApprovalRequest, CanonicalActionSummary } from "@ops/contracts";
import { mapStrings, stripControlChars } from "@ops/redaction";

export interface TtyIo {
  readonly input: Readable;
  readonly output: Writable;
  close?(): void;
}

export interface ApprovalBudget {
  /** Pencerede bu sayıdan fazla onaydan sonra yazılı doğrulama + soğuma istenir (onay yorgunluğu, T7). */
  readonly maxPerWindow: number;
  readonly windowMs: number;
  readonly cooldownMs: number;
}

export const DEFAULT_APPROVAL_BUDGET: ApprovalBudget = { maxPerWindow: 5, windowMs: 10 * 60_000, cooldownMs: 3_000 };

export interface TtyApprovalOptions {
  /** Kontrol terminalini açar. Varsayılan `/dev/tty`; açılamazsa onay REDDEDİLİR (fail-closed). */
  readonly openTty: () => Promise<TtyIo | null>;
  readonly budget?: ApprovalBudget;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
/** Onay ekranına giren HER dinamik metin (model seçimi dahil) kontrol/ANSI/bidi karakterlerinden arındırılır. */
const safe = (s: string, n = 300): string => clip(stripControlChars(s), n);

export const CONFIRM_PHRASE = "ONAYLIYORUM";
const DIFF_LINES = 60;

/** Sınıfa göre artan sürtünme: kullanıcının yazması gereken metin. */
export function requiredAnswer(s: CanonicalActionSummary): string {
  const env = s.profile.environment;
  const resource = s.target?.refs[0]?.split("/").pop() ?? "";
  if (s.class === "destroy") return `${env}/${resource}`;
  if (s.class === "deploy" || env === "prod") return env;
  if (s.class === "mutate") return "evet";
  return "e"; // taint/policy kaynaklı okuma onayı
}

/** PEP'in render ettiği kanonik eylem özeti. Modelin düz metni buraya GİRMEZ (yalnız redakte argümanlar). */
export function renderSummary(s: CanonicalActionSummary, extra: { index: number; expiresInSec: number }): string {
  const lines = [
    "",
    "━━━ ONAY GEREKİYOR ━━━",
    `Araç:      ${safe(s.tool, 80)}   Sınıf: ${s.class}   Neden: ${safe(s.why, 60)}`,
    `Profil:    ${safe(s.profile.id, 60)} [${safe(s.profile.environment, 12)}] ${safe(s.profile.displayName, 60)}`,
    s.target ? `Hedef:     ${safe(s.target.endpoint, 120)} kapsam: ${safe(s.target.scopes.join(","), 120)}${s.target.refs.length ? `  kaynak: ${safe(s.target.refs.join(", "), 160)}` : ""}` : "Hedef:     (yerel)",
    `Argümanlar: ${safe(JSON.stringify(mapStrings(s.argsRedacted ?? {}, stripControlChars)), 400)}`,
  ];
  if (s.taintedContext) lines.push("⚠ Bağlamda UNTRUSTED içerik var (log/olay/dosya). Bu çağrı o içeriğin etkisiyle önerilmiş olabilir.");
  for (const e of s.citedEvidence) lines.push(`Kanıt:     ${safe(e.id, 20)} — ${safe(e.summary, 200)}`);
  if (s.note) lines.push(`Kapsam:    ${safe(s.note, 300)}`);
  const pv = s.preview;
  if (pv) {
    if (pv.targetVersion) lines.push(`Hedef sürüm: ${safe(pv.targetVersion, 80)}   (onay bu sürüme bağlıdır; çalıştırmadan önce yeniden doğrulanır)`);
    for (const i of (pv.impact ?? []).slice(0, 8)) lines.push(`Etki:      ${safe(i, 200)}`);
    if (pv.diff) {
      const all = pv.diff.split("\n");
      const shown = all.slice(0, DIFF_LINES);
      lines.push("Diff:");
      for (const l of shown) lines.push(`  ${safe(l, 160)}`);
      if (all.length > shown.length) lines.push(`  … (${all.length - shown.length} satır daha; eylem hash'i diff'in TAMAMINI kapsar)`);
    }
    if (pv.rollback) lines.push(`Geri alma: ${safe(pv.rollback, 240)}`);
  }
  lines.push(`Süre: ${extra.expiresInSec} sn   (bu oturumda ${extra.index}. onay)`);
  return lines.join("\n");
}

/**
 * Onay kapısı v0. Yanıt YALNIZ kontrol terminalinden (TTY) okunur; araç/sohbet soketinde onay uç
 * noktası yoktur. Kapı: kanonik özeti gösterir, sınıfa göre yazılı doğrulama ister ("hep izin
 * ver" YOK), zaman aşımı = ret, onay bütçesi aşılınca yazılı ifade + soğuma, TTY yoksa ret.
 */
export class TtyApprovalGate implements ApprovalGate {
  readonly events = new EventEmitter();
  private readonly o: TtyApprovalOptions;
  private readonly granted: number[] = [];
  private total = 0;
  private prod = 0;
  /**
   * Onaylar SIRAYLA sorulur (aynı anda tek istem). Aynı turdaki paralel çağrılar eşzamanlı istenirse özetler
   * terminalde iç içe geçer, tek yanıt başka bir isteği onaylayabilir ve bütçe artırım öncesi sayaçla
   * değerlendirildiği için atlanırdı.
   */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: TtyApprovalOptions) {
    this.o = opts;
  }

  /** Oturum sonu özeti: "K onay verdiniz, N prod". */
  summaryLine(): string {
    return `Bu oturumda ${this.total} onay verdiniz${this.prod ? `, ${this.prod} tanesi prod` : ""}.`;
  }

  request(req: ApprovalRequest): Promise<ApprovalOutcome> {
    const run = this.queue.then(() => this.prompt(req));
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async prompt(req: ApprovalRequest): Promise<ApprovalOutcome> {
    const tty = await this.o.openTty().catch(() => null);
    if (!tty) return { approved: false, reason: "onay terminali (TTY) yok: onay verilemez" };
    this.events.emit("start");
    const now = this.o.now ?? Date.now;
    const sleep = this.o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const budget = this.o.budget ?? DEFAULT_APPROVAL_BUDGET;
    const rl = createInterface({ input: tty.input, crlfDelay: Infinity });
    const lines = rl[Symbol.asyncIterator]();
    const ask = async (prompt: string, timeoutMs: number): Promise<string | null> => {
      tty.output.write(prompt);
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<null>((r) => {
        timer = setTimeout(() => r(null), timeoutMs);
      });
      const next = lines.next().then((x) => (x.done ? null : x.value.trim()));
      try {
        return await Promise.race([next, timeout]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    };

    try {
      const t = now();
      while (this.granted.length > 0 && (this.granted[0] as number) < t - budget.windowMs) this.granted.shift();
      const overBudget = this.granted.length >= budget.maxPerWindow;
      const index = this.total + 1;
      tty.output.write(`${renderSummary(req.summary, { index, expiresInSec: req.expiresInSec })}\n`);
      if (overBudget) {
        tty.output.write(`\n⚠ ${budget.windowMs / 60_000} dakikada ${this.granted.length} onay verdiniz. Devam için "${CONFIRM_PHRASE}" yazın (soğuma ${budget.cooldownMs / 1000} sn).\n`);
        await sleep(budget.cooldownMs);
        const phrase = await ask("> ", req.expiresInSec * 1000);
        if (phrase !== CONFIRM_PHRASE) return { approved: false, reason: phrase === null ? "onay zaman aşımına uğradı" : "onay bütçesi için doğrulama ifadesi yanlış" };
      }
      const want = requiredAnswer(req.summary);
      const verb = want === "e" ? "Onaylamak için 'e'" : `Onaylamak için '${safe(want, 80)}' yazın`;
      const answer = await ask(`\n${verb}, reddetmek için Enter: `, req.expiresInSec * 1000);
      if (answer === null) return { approved: false, reason: "onay zaman aşımına uğradı (varsayılan: ret)" };
      if (answer !== want) return { approved: false, reason: answer === "" ? "kullanıcı reddetti" : "doğrulama metni eşleşmedi (varsayılan: ret)" };
      this.granted.push(now());
      this.total += 1;
      if (req.summary.profile.environment === "prod") this.prod += 1;
      return { approved: true, approvalId: randomUUID(), actionHash: req.actionHash };
    } finally {
      rl.close();
      tty.close?.();
      this.events.emit("end");
    }
  }
}

/** Gerçek kontrol terminali (`/dev/tty`). Açılamazsa `null` (fail-closed). */
export async function openDevTty(): Promise<TtyIo | null> {
  const { createReadStream, createWriteStream } = await import("node:fs");
  try {
    const input = createReadStream("/dev/tty");
    const output = createWriteStream("/dev/tty");
    await new Promise<void>((resolve, reject) => {
      input.once("open", () => resolve());
      input.once("error", reject);
    });
    return { input, output, close: () => { input.destroy(); output.destroy(); } };
  } catch {
    return null;
  }
}

/**
 * Gerçek kontrol terminali, TTY AKIŞLARIYLA (`isTTY`/`setRawMode`): parola gibi YANKISIZ girdi gerektiren
 * istemler (yeniden kimlik doğrulama) için. Açılamazsa `null` (fail-closed).
 */
export async function openDevTtyRaw(): Promise<TtyIo | null> {
  try {
    const { openSync, closeSync } = await import("node:fs");
    const { ReadStream, WriteStream } = await import("node:tty");
    const rfd = openSync("/dev/tty", "r");
    const wfd = openSync("/dev/tty", "w");
    const input = new ReadStream(rfd);
    const output = new WriteStream(wfd);
    return {
      input,
      output,
      close: () => {
        input.destroy();
        output.destroy();
        for (const fd of [rfd, wfd]) {
          try {
            closeSync(fd);
          } catch {
            /* zaten kapalı */
          }
        }
      },
    };
  } catch {
    return null;
  }
}
