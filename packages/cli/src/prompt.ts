import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { OpsError } from "@ops/contracts";

/**
 * Parola/belirteç dosyasını okur: sembolik bağ olmayan, BU kullanıcıya ait, yalnız sahibinin erişebildiği (0600)
 * normal dosya. Denetim açılan tanıtıcı üzerinde yapılır (O_NOFOLLOW + fstat): `lstat` ile okuma arasında dosya
 * bağla/FIFO ile değiştirilemez. `lstat` yalnız anlaşılır hata iletisi içindir.
 */
async function readSecretFile(file: string): Promise<string> {
  const bad = (why: string): never => {
    throw new OpsError("passphrase_file_permissions", `parola dosyası ${why}`);
  };
  if ((await lstat(file)).isSymbolicLink()) bad("sembolik bağ olamaz: gerçek dosyanın yolunu verin");
  const fh = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)).catch((e: NodeJS.ErrnoException) => {
    throw e.code === "ELOOP" || e.code === "EMLINK" ? new OpsError("passphrase_file_permissions", "parola dosyası sembolik bağ olamaz: gerçek dosyanın yolunu verin") : e;
  });
  try {
    const st = await fh.stat();
    if (!st.isFile()) bad("normal bir dosya olmalı");
    const uid = process.getuid?.();
    if (uid !== undefined && st.uid !== uid) bad(`bu kullanıcıya (uid ${uid}) ait olmalı (sahip uid ${st.uid})`);
    if ((st.mode & 0o077) !== 0) bad("yalnız sahibi tarafından okunabilir olmalı (chmod 600)");
    return await fh.readFile("utf8");
  } finally {
    await fh.close();
  }
}

/**
 * Kasa parolasını okur. Kaynak sırası: (1) `OPS_PASSPHRASE_FILE` (0600 izinli, kullanıcıya ait, bağ olmayan dosya;
 * ortam DEĞİŞKENİNDE parola tutulmaz — alt süreçlere sızar), (2) TTY'de yankısız istem.
 */
export async function readPassphrase(
  env: Readonly<Record<string, string | undefined>>,
  io: { input: Readable & { isTTY?: boolean; setRawMode?: (m: boolean) => void }; output: Writable },
  question = "Kasa parolası: ",
  fileVar = "OPS_PASSPHRASE_FILE",
): Promise<Uint8Array> {
  const file = env[fileVar];
  if (file) {
    return new Uint8Array(Buffer.from((await readSecretFile(file)).replace(/\r?\n$/, ""), "utf8"));
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
