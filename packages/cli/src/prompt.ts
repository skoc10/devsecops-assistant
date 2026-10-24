import { readFile, stat } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { OpsError } from "@ops/contracts";

/**
 * Kasa parolasını okur. Kaynak sırası: (1) `OPS_PASSPHRASE_FILE` (0600 izinli dosya; ortam
 * DEĞİŞKENİNDE parola tutulmaz — alt süreçlere sızar), (2) TTY'de yankısız istem.
 */
export async function readPassphrase(
  env: Readonly<Record<string, string | undefined>>,
  io: { input: Readable & { isTTY?: boolean; setRawMode?: (m: boolean) => void }; output: Writable },
  question = "Kasa parolası: ",
  fileVar = "OPS_PASSPHRASE_FILE",
): Promise<Uint8Array> {
  const file = env[fileVar];
  if (file) {
    const st = await stat(file);
    if ((st.mode & 0o077) !== 0) throw new OpsError("passphrase_file_permissions", "parola dosyası yalnız sahibi tarafından okunabilir olmalı (chmod 600)");
    return new Uint8Array(Buffer.from((await readFile(file, "utf8")).replace(/\r?\n$/, ""), "utf8"));
  }
  if (!io.input.isTTY || !io.input.setRawMode) {
    throw new OpsError("passphrase_unavailable", `etkileşimli terminal yok: ${fileVar} ile dosya verin`);
  }
  io.output.write(question);
  io.input.setRawMode(true);
  io.input.resume();
  return new Promise<Uint8Array>((resolve, reject) => {
    const chars: string[] = [];
    const onData = (buf: Buffer): void => {
      for (const ch of buf.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          io.input.setRawMode?.(false);
          io.input.off("data", onData);
          io.output.write("\n");
          resolve(new Uint8Array(Buffer.from(chars.join(""), "utf8")));
          return;
        }
        if (ch === "\u0003") {
          io.input.setRawMode?.(false);
          io.input.off("data", onData);
          reject(new OpsError("aborted", "iptal edildi"));
          return;
        }
        if (ch === "\u007f") chars.pop();
        else chars.push(ch);
      }
    };
    io.input.on("data", onData);
  });
}
