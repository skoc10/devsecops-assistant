import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * Dosyayı geçici dosya + `rename` ile atomik ve 0600 yazar (dizin yoksa 0700 oluşturulur). Sabit adlı geçici yol
 * önceden dikilmiş bir symlink olabilir (ör. `vault.json.tmp` → başka bir dosya): eskisi silinir (`unlink`
 * symlink'in KENDİSİNİ siler, hedefini değil) ve yenisi O_CREAT|O_EXCL (`wx`) ile açılır — yol arada yeniden
 * dikilirse açma EEXIST ile başarısız olur. İzin ve yazım açılan fd üzerinden yapılır; yazım başka bir dosyaya
 * yönlenmez, symlink yerine taşınmaz.
 */
export async function writeFileAtomic(path: string, data: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  await unlink(tmp).catch((e: NodeJS.ErrnoException) => {
    if (e.code !== "ENOENT") throw e;
  });
  const fh = await open(tmp, "wx", 0o600);
  try {
    await fh.chmod(0o600); // umask'tan bağımsız; fchmod (symlink izlenmez)
    await fh.writeFile(data, "utf8");
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
}
