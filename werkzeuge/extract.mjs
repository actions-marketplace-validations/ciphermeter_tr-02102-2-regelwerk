// Extrahiert den Text des TR-PDFs zeilenweise (nach y-Position gruppiert, Spalten mit " | " getrennt).
// Aufruf: node werkzeuge/extract.mjs BSI-TR-02102-2.pdf tr.txt
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import fs from 'node:fs';
const [,, inp, out] = process.argv;
const doc = await getDocument({ data: new Uint8Array(fs.readFileSync(inp)) }).promise;
let s = '';
for (let p = 1; p <= doc.numPages; p++) {
  const page = await doc.getPage(p);
  const tc = await page.getTextContent();
  // group by y
  const lines = new Map();
  for (const it of tc.items) {
    if (!it.str) continue;
    const y = Math.round(it.transform[5]);
    let key = [...lines.keys()].find(k => Math.abs(k - y) <= 2) ?? y;
    if (!lines.has(key)) lines.set(key, []);
    lines.get(key).push({ x: it.transform[4], s: it.str });
  }
  const ys = [...lines.keys()].sort((a, b) => b - a);
  s += `\n===== SEITE ${p} =====\n`;
  for (const y of ys) {
    const l = lines.get(y).sort((a, b) => a.x - b.x);
    s += l.map(o => o.s).join(' | ').replace(/\s+\|\s+\|/g,' |') + '\n';
  }
}
fs.writeFileSync(out, s);
console.log('pages', doc.numPages);
