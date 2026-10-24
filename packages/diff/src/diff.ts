/** Birleşik (unified) diff: harici araç yok; `git apply` ile uygulanabilir çıktı. */

type Op = { readonly t: "=" | "-" | "+"; readonly line: string };

const MAX_LINES = 6_000;
const MAX_D = 700;

function myers(a: readonly string[], b: readonly string[]): Op[] | null {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  if (max === 0) return [];
  if (max > MAX_LINES) return null;
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  for (let d = 0; d <= Math.min(max, MAX_D); d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && (v[off + k - 1] as number) < (v[off + k + 1] as number))) x = v[off + k + 1] as number;
      else x = (v[off + k - 1] as number) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        // geri izleme
        const ops: Op[] = [];
        let cx = n;
        let cy = m;
        for (let dd = d; dd > 0; dd--) {
          const pv = trace[dd] as Int32Array;
          const kk = cx - cy;
          const down = kk === -dd || (kk !== dd && (pv[off + kk - 1] as number) < (pv[off + kk + 1] as number));
          const pk = down ? kk + 1 : kk - 1;
          const px = pv[off + pk] as number;
          const py = px - pk;
          while (cx > px && cy > py) {
            ops.push({ t: "=", line: a[cx - 1] as string });
            cx--;
            cy--;
          }
          if (down) {
            ops.push({ t: "+", line: b[cy - 1] as string });
            cy--;
          } else {
            ops.push({ t: "-", line: a[cx - 1] as string });
            cx--;
          }
        }
        while (cx > 0 && cy > 0) {
          ops.push({ t: "=", line: a[cx - 1] as string });
          cx--;
          cy--;
        }
        return ops.reverse();
      }
    }
  }
  return null;
}

/** Sondaki satırsonu eksikse son satıra `\u0000` işareti eklenir: EOL farkı da bir değişiklik sayılır. */
const splitLines = (s: string): string[] => {
  if (s === "") return [];
  const noEol = !s.endsWith("\n");
  const lines = s.split("\n");
  if (!noEol) lines.pop();
  else lines[lines.length - 1] = `${lines[lines.length - 1] as string}\u0000`;
  return lines;
};

export interface FileDiff {
  readonly patch: string;
  readonly additions: number;
  readonly deletions: number;
}

/** İki metin arasında `a/ b/` yol önekli unified diff; `null` ← yeni dosya, `null` → silinmiş. */
export function diffFile(path: string, before: string | null, after: string | null, context = 3): FileDiff {
  const A = splitLines(before ?? "");
  const B = splitLines(after ?? "");
  let ops = myers(A, B);
  if (ops === null) ops = [...A.map((line): Op => ({ t: "-", line })), ...B.map((line): Op => ({ t: "+", line }))];
  const additions = ops.filter((o) => o.t === "+").length;
  const deletions = ops.filter((o) => o.t === "-").length;
  const head: string[] = [`diff --git a/${path} b/${path}`];
  if (before === null) head.push("new file mode 100644");
  if (after === null) head.push("deleted file mode 100644");
  head.push(before === null ? "--- /dev/null" : `--- a/${path}`, after === null ? "+++ /dev/null" : `+++ b/${path}`);
  if (additions === 0 && deletions === 0) return { patch: "", additions, deletions };

  // hunk'lara böl
  const out: string[] = [];
  const changeIdx: number[] = [];
  ops.forEach((o, i) => {
    if (o.t !== "=") changeIdx.push(i);
  });
  let i = 0;
  let aLine = 1;
  let bLine = 1;
  const aAt: number[] = [];
  const bAt: number[] = [];
  for (const o of ops) {
    aAt.push(aLine);
    bAt.push(bLine);
    if (o.t !== "+") aLine++;
    if (o.t !== "-") bLine++;
  }
  while (i < changeIdx.length) {
    let start = Math.max(0, (changeIdx[i] as number) - context);
    let end = Math.min(ops.length, (changeIdx[i] as number) + context + 1);
    let j = i;
    while (j + 1 < changeIdx.length && (changeIdx[j + 1] as number) - context <= end) {
      j++;
      end = Math.min(ops.length, (changeIdx[j] as number) + context + 1);
    }
    start = Math.max(0, start);
    const slice = ops.slice(start, end);
    const aCount = slice.filter((o) => o.t !== "+").length;
    const bCount = slice.filter((o) => o.t !== "-").length;
    const aStart = aCount === 0 ? (aAt[start] as number) - 1 : (aAt[start] as number);
    const bStart = bCount === 0 ? (bAt[start] as number) - 1 : (bAt[start] as number);
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`);
    for (const o of slice) {
      const noEol = o.line.endsWith("\u0000");
      out.push(`${o.t === "=" ? " " : o.t}${noEol ? o.line.slice(0, -1) : o.line}`);
      if (noEol) out.push("\\ No newline at end of file");
    }
    i = j + 1;
  }
  return { patch: `${head.join("\n")}\n${out.join("\n")}\n`, additions, deletions };
}
