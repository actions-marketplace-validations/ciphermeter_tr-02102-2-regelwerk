// Zweitprüfung: liest Tabellenzeilen unabhängig aus dem extrahierten Text und vergleicht sie mit dem JSON.
// Aufruf: node werkzeuge/pruefe.mjs tr.txt tr-02102-2-2026-01.json
import fs from 'node:fs';
const [, , txtPath, jsonPath] = process.argv;
const lines = fs.readFileSync(txtPath, 'utf8').split('\n');
const j = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
const rowRe = /^(\S+) \| (\S+) \| \[(RFC \d+)\] \| (\d{4}\+?)$/;
const tables = {}; let cur = null, page = 0;
for (const l of lines) {
  const pm = l.match(/^===== SEITE (\d+)/); if (pm) { page = +pm[1]; continue; }
  const tm = l.match(/^Tabelle (\d+):/); if (tm) { cur = +tm[1]; tables[cur] = []; continue; }
  if (cur == null || l.trim() === "") continue;
  const m = l.match(rowRe);
  if (m) { tables[cur].push({ name: m[1], iana: m[2], referenz: m[3].replace(' ', ''), bis: m[4], seite: page }); continue; }
  if (/^(Cipher-Suite|Diffie-Hellman-Gruppe|Signaturverfahren|Hashfunktion|PSK-Modus|TLS-Version) \|/.test(l) || /^3 Empfehlungen$/.test(l) || /Bundesamt für Sicherheit/.test(l) || /^\d \|\s*$/.test(l)) continue; // Kopfzeilen, Seitenumbruch, Fußnotenmarker
  if (/^\d \|  ?$/.test(l) || /^Bei Cipher-Suiten, die den Betriebsmodus CCM|^Cipher-Suiten verwenden SHA-256|^Perfect Forward Secrecy|^Kenntnis der|^kann\. Bei|^Perfect Forward Secrecy grund/.test(l)) continue; // Fußnoten S. 7
  if (tables[cur].length) cur = null; // Tabelle zu Ende
}
const cmp = (nr, arr) => {
  const t = tables[nr] || []; const errs = [];
  if (t.length !== arr.length) errs.push(`Anzahl Text ${t.length} != JSON ${arr.length}`);
  t.forEach((r, i) => {
    const e = arr[i]; if (!e) return;
    const bis = e.bis + (e.bis_verlaengerbar ? '+' : '');
    for (const [k, a, b] of [['name', r.name, e.name], ['iana', r.iana, String(e.iana)], ['referenz', r.referenz, e.referenz], ['bis', r.bis, bis], ['seite', r.seite, e.fundstelle?.seite]])
      if (String(a) !== String(b)) errs.push(`Zeile ${i + 1} ${k}: Text ${a} / JSON ${b}`);
  });
  const seiten = [...new Set(t.map(r => r.seite))].join('+');
  console.log(`Tabelle ${nr}: Text ${t.length}, JSON ${arr.length}, Seiten ${seiten} -> ${errs.length ? 'FEHLER\n  ' + errs.join('\n  ') : 'OK'}`);
  return errs.length;
};
const s = j.tls12_suiten;
let f = 0;
f += cmp(3, s.filter(x => x.fundstelle.tabelle === 3));
f += cmp(4, s.filter(x => x.fundstelle.tabelle === 4));
f += cmp(5, s.filter(x => x.fundstelle.tabelle === 5));
f += cmp(6, j.gruppen_tls12);
f += cmp(7, j.signaturen_tls12.filter(x => x.art === 'signaturverfahren'));
f += cmp(8, j.signaturen_tls12.filter(x => x.art === 'hashfunktion'));
f += cmp(9, j.tls13_psk_modi);
f += cmp(10, j.gruppen_tls13);
f += cmp(11, j.signaturen_tls13);
f += cmp(12, j.signaturen_tls13_cert);
f += cmp(13, j.tls13_suiten);
// Tabelle 2 (Versionen) und 14 (Schlüssellängen) haben ein anderes Format
const t2 = lines.filter(l => /^TLS 1\.[23] \| \[RFC \d+\] \| \d{4}\+?$/.test(l));
console.log('Tabelle 2 (Text):', t2.join(' ; '));
const t14 = lines.filter(l => /^(ECDSA|DSA|RSA|ECDH|DH) \| \d+ Bit/.test(l));
console.log('Tabelle 14 (Text):', t14.join(' ; '));
// Kontrolle CBC => encrypt_then_mac, DHE => 2029
for (const x of s) {
  if (x.name.includes('_CBC_') !== (x.bedingung === 'encrypt_then_mac')) { console.log('Bedingung falsch:', x.name); f++; }
  if (x.name.startsWith('TLS_DHE_') && x.bis !== 2029) { console.log('DHE-Frist falsch:', x.name); f++; }
}
console.log(f ? `${f} Abweichung(en)` : 'Alle Tabellen stimmen überein.');
