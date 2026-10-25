/**
 * Minimal HCL2 yapı çözümleyici (ön-tarama için). Amaç: blok ağacını (tür, etiketler, öznitelikler)
 * GÜVENİLİR çıkarmak; ifadeleri değerlendirmek DEĞİL. Yorumlar (#, //, blok yorumu), dize kaçışları,
 * `${...}`/`%{...}` iç içe enterpolasyon (içinde dize ve küme parantezi), heredoc (<<ID, <<-ID) ve tek
 * satırlık bloklar işlenir. Sözdizimi hatasında satır numaralı hata verir; çözümleyemediğimiz dosya
 * için ön-tarama "doğrulanamadı" der ve çalıştırma araçları reddedilir (fail-closed).
 */

export interface HclAttr {
  /** Basit dize değeriyse içerik (enterpolasyonsuz), değilse `undefined`. */
  readonly literal?: string;
  /** İfade metni (kırpılmış). */
  readonly text: string;
  readonly line: number;
}

export interface HclBlock {
  readonly type: string;
  readonly labels: string[];
  readonly attrs: Record<string, HclAttr>;
  readonly blocks: HclBlock[];
  readonly line: number;
}

export class HclError extends Error {
  readonly line: number;
  constructor(message: string, line: number) {
    super(`${message} (satır ${line})`);
    this.line = line;
  }
}

const MAX_DEPTH = 40;
const MAX_BLOCKS = 5_000;

class Lexer {
  pos = 0;
  line = 1;
  readonly src: string;
  blocks = 0;

  constructor(src: string) {
    this.src = src;
  }

  eof(): boolean {
    return this.pos >= this.src.length;
  }
  peek(o = 0): string {
    return this.src[this.pos + o] ?? "";
  }
  adv(): string {
    const c = this.src[this.pos++] ?? "";
    if (c === "\n") this.line++;
    return c;
  }

  /** Boşluk, satır sonu ve yorumları atlar. `stopAtNewline`: satır sonunda durur (öznitelik sonu). */
  skipTrivia(stopAtNewline: boolean): void {
    for (;;) {
      const c = this.peek();
      if (c === " " || c === "\t" || c === "\r") {
        this.adv();
      } else if (c === "\n") {
        if (stopAtNewline) return;
        this.adv();
      } else if (c === "#" || (c === "/" && this.peek(1) === "/")) {
        while (!this.eof() && this.peek() !== "\n") this.adv();
      } else if (c === "/" && this.peek(1) === "*") {
        const start = this.line;
        this.adv();
        this.adv();
        while (!this.eof() && !(this.peek() === "*" && this.peek(1) === "/")) this.adv();
        if (this.eof()) throw new HclError("kapanmamış /* yorumu", start);
        this.adv();
        this.adv();
      } else return;
    }
  }

  /** `"` ile başlayan dizeyi okur (imleç açılış tırnağında). Enterpolasyonlar iç içe işlenir. Ham metni ve düz içeriği döner. */
  readString(): { raw: string; literal: string | undefined } {
    const start = this.line;
    const begin = this.pos;
    this.adv();
    let literal = "";
    let simple = true;
    for (;;) {
      if (this.eof()) throw new HclError("kapanmamış dize", start);
      const c = this.peek();
      if (c === "\n") throw new HclError("dize satır sonuna kadar kapanmadı", start);
      if (c === "\\") {
        this.adv();
        const n = this.adv();
        literal += n === "n" ? "\n" : n === "t" ? "\t" : n;
        continue;
      }
      if (c === '"') {
        this.adv();
        break;
      }
      if ((c === "$" || c === "%") && this.peek(1) === c && this.peek(2) === "{") {
        // $${ ve %%{ kaçışı: düz metin
        literal += this.adv() + this.adv() + this.adv();
        continue;
      }
      if ((c === "$" || c === "%") && this.peek(1) === "{") {
        simple = false;
        this.adv();
        this.adv();
        this.skipInterpolation(start);
        continue;
      }
      literal += this.adv();
    }
    return { raw: this.src.slice(begin, this.pos), literal: simple ? literal : undefined };
  }

  /** `${` sonrası: eşleşen `}`'e kadar (iç içe küme parantezi, dize, yorum) atlar. */
  private skipInterpolation(startLine: number, depth = 0): void {
    if (depth > MAX_DEPTH) throw new HclError("enterpolasyon çok derin", startLine);
    let braces = 1;
    while (braces > 0) {
      if (this.eof()) throw new HclError("kapanmamış enterpolasyon", startLine);
      const c = this.peek();
      if (c === '"') {
        // iç dize (kendi enterpolasyonlarıyla)
        this.adv();
        for (;;) {
          if (this.eof()) throw new HclError("kapanmamış dize", startLine);
          const d = this.peek();
          if (d === "\\") {
            this.adv();
            this.adv();
          } else if (d === '"') {
            this.adv();
            break;
          } else if ((d === "$" || d === "%") && this.peek(1) === d && this.peek(2) === "{") {
            this.adv();
            this.adv();
            this.adv();
          } else if ((d === "$" || d === "%") && this.peek(1) === "{") {
            this.adv();
            this.adv();
            this.skipInterpolation(startLine, depth + 1);
          } else this.adv();
        }
      } else if (c === "{") {
        braces++;
        this.adv();
      } else if (c === "}") {
        braces--;
        this.adv();
      } else if (c === "<" && this.peek(1) === "<" && /[A-Za-z_-]/.test(this.peek(2))) {
        this.readHeredoc();
      } else this.adv();
    }
  }

  /** `<<ID` / `<<-ID` heredoc'unu (gövde + bitiş satırı) atlar; ham metni döner. */
  readHeredoc(): string {
    const start = this.line;
    const begin = this.pos;
    this.adv();
    this.adv();
    if (this.peek() === "-") this.adv();
    let id = "";
    while (/[A-Za-z0-9_]/.test(this.peek())) id += this.adv();
    if (id === "") throw new HclError("heredoc tanımlayıcısı yok", start);
    while (!this.eof() && this.peek() !== "\n") this.adv();
    for (;;) {
      if (this.eof()) throw new HclError(`heredoc '${id}' kapanmadı`, start);
      this.adv(); // satır sonu
      let ln = "";
      while (!this.eof() && this.peek() !== "\n") ln += this.adv();
      if (ln.trim() === id) break;
    }
    return this.src.slice(begin, this.pos);
  }
}

const IDENT = /[A-Za-z_][A-Za-z0-9_-]*/y;

function readIdent(lx: Lexer): string | null {
  IDENT.lastIndex = lx.pos;
  const m = IDENT.exec(lx.src);
  if (!m) return null;
  for (let i = 0; i < m[0].length; i++) lx.adv();
  return m[0];
}

/** Bir özniteliğin ifadesini satır sonuna (veya kapanmamış parantezlerin sonuna) kadar okur. */
function readExpr(lx: Lexer): { text: string; literal: string | undefined } {
  const begin = lx.pos;
  let depth = 0;
  let literal: string | undefined;
  let tokens = 0;
  let onlyString = false;
  for (;;) {
    lx.skipTrivia(depth === 0);
    if (lx.eof()) break;
    const c = lx.peek();
    if (c === "\n" && depth === 0) break;
    if (c === "\n") {
      lx.adv();
      continue;
    }
    if (c === '"') {
      const s = lx.readString();
      tokens++;
      onlyString = tokens === 1;
      literal = s.literal;
      continue;
    }
    if (c === "<" && lx.peek(1) === "<" && /[A-Za-z_-]/.test(lx.peek(2))) {
      lx.readHeredoc();
      tokens++;
      onlyString = false;
      literal = undefined;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break; // üst bloğun kapanışı (tek satırlık blok)
      depth--;
    } else if (c === "," && depth === 0) {
      break;
    }
    tokens++;
    onlyString = false;
    lx.adv();
  }
  const text = lx.src.slice(begin, lx.pos).trim();
  return { text: text.length > 400 ? `${text.slice(0, 400)}…` : text, literal: onlyString ? literal : undefined };
}

function parseBody(lx: Lexer, depth: number, closing: boolean): { attrs: Record<string, HclAttr>; blocks: HclBlock[] } {
  if (depth > MAX_DEPTH) throw new HclError("blok iç içeliği çok derin", lx.line);
  const attrs: Record<string, HclAttr> = {};
  const blocks: HclBlock[] = [];
  for (;;) {
    lx.skipTrivia(false);
    if (lx.eof()) {
      if (closing) throw new HclError("kapanmamış blok", lx.line);
      return { attrs, blocks };
    }
    if (lx.peek() === "}") {
      if (!closing) throw new HclError("beklenmeyen '}'", lx.line);
      lx.adv();
      return { attrs, blocks };
    }
    const line = lx.line;
    const name = readIdent(lx);
    if (name === null) throw new HclError(`beklenmeyen karakter '${lx.peek().replace(/[^\x20-\x7e]/g, "?")}'`, lx.line);
    lx.skipTrivia(true);
    const c = lx.peek();
    if (c === "=" && lx.peek(1) !== "=") {
      lx.adv();
      const e = readExpr(lx);
      attrs[name] = { text: e.text, ...(e.literal !== undefined ? { literal: e.literal } : {}), line };
      lx.skipTrivia(true);
      if (lx.peek() === ",") lx.adv();
      continue;
    }
    if (c === ":" ) throw new HclError("':' HCL'de öznitelik ayracı değildir ('=' kullanın)", lx.line);
    // blok: etiketler (dize veya tanımlayıcı) sonra '{'
    const labels: string[] = [];
    for (;;) {
      lx.skipTrivia(true);
      const d = lx.peek();
      if (d === '"') {
        const s = lx.readString();
        if (s.literal === undefined) throw new HclError("blok etiketi enterpolasyon içeremez", lx.line);
        labels.push(s.literal);
      } else if (d === "{") {
        break;
      } else {
        const id = readIdent(lx);
        if (id === null) throw new HclError(`blok '${name}' için '{' bekleniyordu`, lx.line);
        labels.push(id);
      }
    }
    lx.adv(); // '{'
    if (++lx.blocks > MAX_BLOCKS) throw new HclError("blok sayısı sınırı aşıldı", line);
    const inner = parseBody(lx, depth + 1, true);
    blocks.push({ type: name, labels, attrs: inner.attrs, blocks: inner.blocks, line });
  }
}

export function parseHcl(src: string): { attrs: Record<string, HclAttr>; blocks: HclBlock[] } {
  if (src.length > 1_000_000) throw new HclError("dosya çok büyük", 1);
  // BOM ve CRLF tolere edilir
  const text = src.replace(/^\uFEFF/, "");
  return parseBody(new Lexer(text), 0, false);
}

/** Bloğun altındaki tüm iç blokları (derin) dolaşır. */
export function* walkBlocks(blocks: readonly HclBlock[], parents: readonly HclBlock[] = []): Generator<{ block: HclBlock; parents: readonly HclBlock[] }> {
  for (const b of blocks) {
    yield { block: b, parents };
    yield* walkBlocks(b.blocks, [...parents, b]);
  }
}
