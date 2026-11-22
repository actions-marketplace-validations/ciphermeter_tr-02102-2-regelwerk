// SPDX-License-Identifier: Apache-2.0
// TLS-Prüfung eines Ziels gegen BSI TR-02102-2 (Fassung 2026-01), nur über normale TLS-Handshakes (keine Angriffstests).
// Aufruf lokal:  node action/run.js <host> [port] [--fail-on none|warn|fail] [--sni name] [--regelwerk datei.json]
// In der Action: Werte kommen über die Umgebung (TR_HOST, TR_PORT, TR_FAIL_ON, TR_SNI), siehe action.yml.
// Schreibt eine Markdown-Zusammenfassung nach $GITHUB_STEP_SUMMARY und result/findings nach $GITHUB_OUTPUT (falls gesetzt).
// Ergebnis: fail = mindestens eine Abweichung von der TR (mit Fundstelle in der TR) oder keine Messung möglich
//           warn = keine solche Abweichung, aber ein Zertifikatsbefund ohne TR-Vorgabe (Name, Gültigkeit, Vertrauen),
//                  eine Frist endet im laufenden Jahr oder die Messung ist eingeschränkt
//           pass = sonst
// findings = Abweichungen von der TR + Zertifikatsbefunde ohne TR-Vorgabe + Fristen im laufenden Jahr.
// Exit: 0 Schwelle nicht erreicht · 1 Schwelle (fail-on) erreicht · 2 Aufruf- oder interner Fehler
'use strict';
const fs = require('fs');
const path = require('path');
const { messen } = require('./lib/messung');
const { laden, messstatus } = require('./lib/rohdaten');
const { bewerten } = require('./lib/bewertung');
const { zielNormalisieren } = require('./lib/ziel');

const HYBRID = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'MLKEM768', 'MLKEM1024'];
const ML_KEM_TEXT = 'nicht messbar (OpenSSL < 3.5; runs-on: ubuntu-26.04 verwenden)';
const MESSUNG = { vollstaendig: 'vollständig', eingeschraenkt: 'eingeschränkt', nicht_erfolgreich: 'nicht erfolgreich' };

function fehler(text) { console.error(`Fehler: ${text}`); process.exit(2); }

// „3.0.13+quic“, „OpenSSL 3.5.5 30 Sep 2025“ → [3, 0, 13]; unlesbar → null
function versionLesen(s) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || ''));
  return m ? m.slice(1).map(Number) : null;
}
const mindestens = (v, ziel) => !!v && (v[0] - ziel[0] || v[1] - ziel[1] || v[2] - ziel[2]) >= 0;

// Hybridgruppen: Bei OpenSSL < 3.5 kann das Prüfsystem sie nicht senden – also keine Aussage, nie „nicht angeboten“
function mlkemEinordnen(roh, opensslNode) {
  if (mindestens(versionLesen(opensslNode), [3, 5, 0])) return false;
  if (roh.gruppen_tls13 && roh.gruppen_tls13.status === 'geprueft')
    for (const e of roh.gruppen_tls13.eintraege) if (HYBRID.includes(e.name)) {
      e.status = 'nicht_pruefbar'; e.art = 'lokal'; e.grund = ML_KEM_TEXT;
    }
  const ms = messstatus(roh);
  roh.messstatus = ms.status; roh.nicht_pruefbar = ms.gruende.length;
  return true;
}

function argumente(argv, env) {
  const a = argv.slice(2), opt = n => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };
  const frei = a.filter((x, i) => !x.startsWith('--') && !(i > 0 && a[i - 1].startsWith('--')));
  return {
    host: frei[0] || env.TR_HOST,
    port: frei[1] || env.TR_PORT || undefined,
    failOn: (opt('--fail-on') || env.TR_FAIL_ON || 'fail').trim().toLowerCase(),
    sni: opt('--sni') || env.TR_SNI || undefined,
    regelwerk: opt('--regelwerk') || env.TR_REGELWERK || path.join(__dirname, '..', 'tr-02102-2-2026-01.json')
  };
}

const zelle = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
function tabelle(zeilen) {
  if (!zeilen.length) return '_keine_\n';
  return '| Bereich | Merkmal | Befund | Fundstelle |\n|---|---|---|---|\n'
    + zeilen.map(z => `| ${zelle(z.bereich)} | ${zelle(z.merkmal)} | ${zelle(z.text)} | ${zelle(z.fundstelle)} |`).join('\n') + '\n';
}

// Zeilen der Bewertung nach Folge: Abweichungen mit Fundstelle in der TR getrennt von Zertifikatsbefunden ohne TR-Vorgabe
// (Name, Gültigkeit, Vertrauenskette: Fundstelle „keine Vorgabe in TR-02102-2“)
const OHNE_TR = /^keine Vorgabe in TR-02102-2/;
function einteilen(bew) {
  const l = s => bew ? bew.zeilen.filter(z => z.stufe === s) : [];
  return { tr: l('abw').filter(z => !OHNE_TR.test(z.fundstelle || '')), zert: l('abw').filter(z => OHNE_TR.test(z.fundstelle || '')),
    frist: l('frist'), np: l('np'), hinweis: [...l('info'), ...l('na')], ok: l('ok') };
}

function zusammenfassung({ ziel, roh, bew, ergebnis, findings, mlkem, tr, failOn }) {
  const g = einteilen(bew);
  const t = [];
  t.push('## TLS-Prüfung gegen BSI TR-02102-2', '');
  t.push(`Ziel: \`${ziel.host}:${ziel.port}\` · Zeitpunkt (UTC): ${roh.zeitpunkt} · Ergebnis: **${ergebnis.toUpperCase()}** (fail-on: ${failOn})`, '');
  t.push(`Regelwerk: TR-02102-2 Fassung ${tr.quelle.version} · Messung: ${MESSUNG[bew ? bew.gesamt : roh.messstatus]} · `
    + `Abweichungen von der TR: ${g.tr.length} · Zertifikat (ohne TR-Vorgabe): ${g.zert.length} · Fristen im laufenden Jahr: ${g.frist.length} · nicht prüfbar: ${g.np.length} · Befunde gesamt: ${findings}`, '');
  t.push(`Prüfsystem: Node.js ${roh.werkzeug.node}, OpenSSL der Node-Laufzeit ${roh.werkzeug.openssl_node}, openssl-Programm: ${roh.werkzeug.openssl_cli || 'nicht gefunden'}`, '');
  if (mlkem) t.push(`> Hybridgruppen mit ML-KEM (${HYBRID.slice(0, 3).join(', ')}): ${ML_KEM_TEXT}.`, '');
  if (!bew) {
    t.push(`Kein Handshake gelungen – keine Bewertung möglich.${roh.abbruch ? ` Grund: ${zelle(roh.abbruch)}` : ''}`, '');
    return t.join('\n') + '\n';
  }
  t.push('### Abweichungen von der TR', '', tabelle(g.tr));
  t.push('### Zertifikat: Befunde ohne Vorgabe der TR (Name, Gültigkeit, Vertrauenskette)', '', tabelle(g.zert));
  t.push('### Fristen, die im laufenden Jahr enden', '', tabelle(g.frist));
  t.push(`<details><summary>Nicht prüfbar (${g.np.length})</summary>`, '', tabelle(g.np), '</details>', '');
  t.push(`<details><summary>Hinweise und nicht in der TR aufgeführte Verfahren (${g.hinweis.length})</summary>`, '', tabelle(g.hinweis), '</details>', '');
  t.push(`Entspricht: ${g.ok.length} Merkmale.`, '');
  t.push('Geprüft wurde nur mit normalen TLS-Handshakes (höchstens 4 je Sekunde), ohne Schwachstellen- oder Angriffstests. '
    + 'Maßgeblich ist allein die TR des BSI; diese Prüfung ist kein Dokument des BSI.', '');
  return t.join('\n') + '\n';
}

async function main() {
  const a = argumente(process.argv, process.env);
  if (!a.host) fehler('host fehlt. Aufruf: node action/run.js <host> [port] [--fail-on none|warn|fail] [--sni name]');
  if (!['none', 'warn', 'fail'].includes(a.failOn)) fehler(`fail-on muss none, warn oder fail sein (nicht „${a.failOn}“)`);
  const ziel = zielNormalisieren(a.host, { port: a.port, lokal: true });
  if (!ziel.ok) fehler(`Ziel ungültig: ${ziel.fehler}`);
  let tr;
  try { tr = JSON.parse(fs.readFileSync(a.regelwerk, 'utf8')); } catch (e) { fehler(`Regelwerk ${a.regelwerk} nicht lesbar (${e.message})`); }

  // Nur für Tests: andere OpenSSL-Version der Laufzeit vortäuschen (prüft die Einordnung der Hybridgruppen)
  const opensslNode = process.env.TR_TEST_OPENSSL_NODE || process.versions.openssl;
  console.error(`Prüfe ${ziel.host}:${ziel.port} (Node.js ${process.version}, OpenSSL ${opensslNode}) …`);
  const roh = await messen({ host: ziel.host, port: ziel.port, sni: a.sni, sperrliste: [] });
  if (process.env.TR_TEST_OPENSSL_NODE) roh.werkzeug.openssl_node = `${opensslNode} (vorgetäuscht, Test)`;
  const mlkem = mlkemEinordnen(roh, opensslNode);

  let bew = null;
  if (roh.messstatus !== 'nicht_erfolgreich') bew = bewerten(laden(roh), tr);
  const g = einteilen(bew);
  const findings = g.tr.length + g.zert.length + g.frist.length;
  const ergebnis = !bew || bew.gesamt === 'nicht_erfolgreich' || g.tr.length ? 'fail'
    : g.zert.length || g.frist.length || bew.gesamt !== 'vollstaendig' ? 'warn' : 'pass';

  const md = zusammenfassung({ ziel, roh, bew, ergebnis, findings, mlkem, tr, failOn: a.failOn });
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
  else process.stdout.write(md);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `result=${ergebnis}\nfindings=${findings}\n`);

  console.error(`Ergebnis: ${ergebnis} · Befunde: ${findings} (TR ${g.tr.length}, Zertifikat ohne TR-Vorgabe ${g.zert.length}, Fristen ${g.frist.length}, nicht prüfbar ${g.np.length}) · Messung: ${MESSUNG[bew ? bew.gesamt : roh.messstatus]}`);
  const rang = { pass: 0, warn: 1, fail: 2 }, schwelle = { none: 99, warn: 1, fail: 2 }[a.failOn];
  process.exitCode = rang[ergebnis] >= schwelle ? 1 : 0;
}

if (require.main === module) main().catch(e => fehler(e.stack || e.message));
module.exports = { versionLesen, mindestens, mlkemEinordnen, ML_KEM_TEXT, HYBRID };
