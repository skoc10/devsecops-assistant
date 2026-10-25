import { createInterface } from "node:readline";
import { OpsError } from "@ops/contracts";
import { EncryptedFileStore } from "@ops/broker";
import type { ReauthProof } from "@ops/core";
import type { TtyIo } from "./approval.ts";
import { readPassphrase } from "./prompt.ts";

export interface ReauthOptions {
  /** Kontrol terminali; açılamazsa yeniden doğrulama BAŞARISIZ (fail-closed). */
  readonly openTty: () => Promise<TtyIo | null>;
  readonly vaultFile: string;
  /** Test: parola doğrulayıcı (varsayılan: kasa dosyasına karşı). */
  readonly verify?: (passphrase: Uint8Array) => Promise<boolean>;
  readonly now?: () => Date;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly attempts?: number;
  readonly prompt?: string;
}

type TtyLike = TtyIo["input"] & { isTTY?: boolean; setRawMode?: (m: boolean) => void };

async function readLine(tty: TtyIo, question: string): Promise<Uint8Array> {
  tty.output.write(question);
  const rl = createInterface({ input: tty.input, crlfDelay: Infinity });
  try {
    const next = await rl[Symbol.asyncIterator]().next();
    if (next.done) throw new OpsError("break_glass_reauth", "parola okunamadı");
    return new Uint8Array(Buffer.from(String(next.value).replace(/\r?\n$/, ""), "utf8"));
  } finally {
    rl.close();
  }
}

/**
 * Yeniden kimlik doğrulama (tasarım §8.6): kasa parolası KONTROL TERMİNALİNDEN (yankısız) okunur — ortam
 * değişkeni/dosyası KABUL EDİLMEZ (insan başında olmalı) — ve kasa dosyasına karşı doğrulanır. En çok 3 deneme,
 * yanlışlar arasında bekleme. Tutulan kanıt yalnız `{yöntem, zaman}`dır; parola hiçbir yere yazılmaz.
 */
export async function reauthVaultPassphrase(o: ReauthOptions): Promise<ReauthProof> {
  const tty = await o.openTty().catch(() => null);
  if (!tty) throw new OpsError("break_glass_reauth", "kontrol terminali (TTY) yok: yeniden kimlik doğrulama yapılamaz");
  const verify = o.verify ?? ((p: Uint8Array) => EncryptedFileStore.verify(o.vaultFile, p));
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const attempts = o.attempts ?? 3;
  const question = o.prompt ?? "Yeniden kimlik doğrulama — kasa parolası: ";
  try {
    for (let i = 0; i < attempts; i++) {
      const input = tty.input as TtyLike;
      const pass = input.isTTY && input.setRawMode ? await readPassphrase({}, { input, output: tty.output }, question) : await readLine(tty, question);
      let ok = false;
      try {
        ok = await verify(pass);
      } finally {
        pass.fill(0);
      }
      if (ok) return { method: "vault-passphrase", verifiedAt: (o.now ?? (() => new Date()))() };
      tty.output.write("Parola yanlış.\n");
      if (i < attempts - 1) await sleep(1000);
    }
    throw new OpsError("break_glass_reauth", "yeniden kimlik doğrulama başarısız");
  } finally {
    tty.close?.();
  }
}

/** `30m`, `90s`, `1h` → saniye. Geçersiz → OpsError. */
export function parseDurationSec(text: string): number {
  const m = /^(\d{1,6})\s*([smh]?)$/i.exec(text.trim());
  if (!m) throw new OpsError("usage", `süre geçersiz: '${text.slice(0, 20)}' (örnek: 30m, 90s, 1h)`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  return unit === "h" ? n * 3600 : unit === "m" ? n * 60 : n;
}
