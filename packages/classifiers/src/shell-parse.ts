/**
 * Sıkı alt küme kabuk ayrıştırıcısı. Amaç tam bash'i anlamak DEĞİL, **güvenle anlaşılabilen**
 * küçük bir dilbilgisini kabul edip geri kalan HER ŞEYİ reddetmektir (reddedilen = sınıflanamaz =
 * `destroy` muamelesi). Kabul edilen dilbilgisinde kabuk genişlemesi (değişken, komut ikamesi,
 * glob, brace, tilde, yönlendirme, heredoc, alt kabuk, arka plan, ortam atama) YOKTUR; bu yüzden
 * argv, kabuğun göreceği argv ile birebir aynıdır.
 *
 * Kabul: basit komutlar; `|`, `&&`, `||`, `;` ile bağlı. Sözcük = çıplak karakterler
 * (`A-Za-z0-9_@%+=:,./-`; sözcük ortasında `~` ve `^`), tek tırnak (içinde her ASCII yazdırılabilir, `'` hariç) veya çift
 * tırnak (içinde `$`, `` ` ``, `\`, `!`, `"` yok); bitişik parçalar birleşir.
 */
export type Connector = "|" | "&&" | "||" | ";";

export interface SimpleCommand {
  readonly argv: readonly string[];
}

export type ParseResult =
  | { readonly ok: true; readonly commands: readonly SimpleCommand[]; readonly connectors: readonly Connector[] }
  | { readonly ok: false; readonly reason: string };

export const MAX_COMMAND_CHARS = 4096;
export const MAX_COMMANDS = 8;
export const MAX_WORDS = 64;
export const MAX_WORD_CHARS = 512;

const BARE = /[A-Za-z0-9_@%+=:,./-]/;
const PRINTABLE = /^[\x20-\x7e]*$/;

const fail = (reason: string): ParseResult => ({ ok: false, reason });

export function parseShell(input: string): ParseResult {
  if (typeof input !== "string" || input.length === 0) return fail("boş komut");
  if (input.length > MAX_COMMAND_CHARS) return fail("komut çok uzun");
  // ASCII yazdırılabilir + boşluk/tab. Yeni satır, NUL, kontrol karakteri, Unicode boşluk/bidi: ret.
  for (const ch of input) {
    if (ch === "\t") continue;
    if (!PRINTABLE.test(ch)) return fail("ASCII dışı veya kontrol karakteri");
  }

  const commands: SimpleCommand[] = [];
  const connectors: Connector[] = [];
  let words: string[] = [];
  let cur = "";
  let inWord = false;
  let totalWords = 0;

  const endWord = (): ParseResult | null => {
    if (!inWord) return null;
    if (cur.length > MAX_WORD_CHARS) return fail("sözcük çok uzun");
    words.push(cur);
    totalWords += 1;
    cur = "";
    inWord = false;
    return null;
  };
  const endCommand = (): ParseResult | null => {
    const e = endWord();
    if (e) return e;
    if (words.length === 0) return fail("boş komut (ardışık/baştaki bağlaç)");
    const first = words[0] as string;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) return fail("ortam değişkeni ataması");
    commands.push({ argv: words });
    words = [];
    return null;
  };

  let i = 0;
  while (i < input.length) {
    const ch = input[i] as string;
    if (ch === " " || ch === "\t") {
      const e = endWord();
      if (e) return e;
      i += 1;
      continue;
    }
    if (ch === "'") {
      const close = input.indexOf("'", i + 1);
      if (close < 0) return fail("kapanmamış tek tırnak");
      cur += input.slice(i + 1, close);
      inWord = true;
      i = close + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let buf = "";
      for (;;) {
        if (j >= input.length) return fail("kapanmamış çift tırnak");
        const c = input[j] as string;
        if (c === '"') break;
        if (c === "$" || c === "`" || c === "\\" || c === "!") return fail("çift tırnak içinde genişleme/kaçış karakteri");
        buf += c;
        j += 1;
      }
      cur += buf;
      inWord = true;
      i = j + 1;
      continue;
    }
    if (ch === "|" || ch === "&" || ch === ";") {
      const two = input.slice(i, i + 2);
      let conn: Connector;
      let len: number;
      if (two === "&&") (conn = "&&"), (len = 2);
      else if (two === "||") (conn = "||"), (len = 2);
      else if (ch === "|" && input[i + 1] !== "&") (conn = "|"), (len = 1);
      else if (ch === ";") (conn = ";"), (len = 1);
      else return fail(ch === "&" ? "arka plan/`&`" : "`|&`");
      const e = endCommand();
      if (e) return e;
      connectors.push(conn);
      if (commands.length >= MAX_COMMANDS) return fail("çok fazla komut");
      i += len;
      continue;
    }
    if (BARE.test(ch)) {
      cur += ch;
      inWord = true;
      i += 1;
      continue;
    }
    // `~` ve `^` yalnız sözcüğün ORTASINDA (HEAD~1, HEAD^) güvenlidir: sözcük başında veya `=`/`:`
    // sonrasında tilde genişlemesi olabilir.
    if ((ch === "~" || ch === "^") && inWord && cur.length > 0 && !/[=:]$/.test(cur)) {
      cur += ch;
      i += 1;
      continue;
    }
    // Kalan her şey: $ ` \ ( ) < > * ? [ ] { } ~ ! # vb.
    return fail(`desteklenmeyen kabuk yapısı: '${ch}'`);
  }

  // sondaki bağlaç: `a ;` kabul, `a &&` ret
  const endedWithSemicolon = connectors.length > 0 && inWord === false && words.length === 0 && connectors[connectors.length - 1] === ";" && commands.length === connectors.length;
  if (endedWithSemicolon) {
    connectors.pop();
  } else {
    const e = endCommand();
    if (e) return e;
  }
  if (commands.length === 0) return fail("komut yok");
  if (commands.length !== connectors.length + 1) return fail("bağlaç sayısı tutarsız");
  if (totalWords > MAX_WORDS) return fail("çok fazla sözcük");
  return { ok: true, commands, connectors };
}
