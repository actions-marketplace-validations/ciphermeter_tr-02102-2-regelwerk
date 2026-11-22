// SPDX-License-Identifier: Apache-2.0
// Rohdaten des Prüfkerns: Prüfung vor der Bewertung, Umwandlung des Altformats (Prüfkern 0.1) und Messstatus.
// Format 2 (Prüfkern ab 0.2) hält für jedes geprüfte Merkmal einen von drei Zuständen fest:
//   angeboten       – nachgewiesen angeboten (Handshake gelungen)
//   abgelehnt       – nachgewiesen abgelehnt (eindeutiger TLS-Alarm oder andere Version)
//   nicht_pruefbar  – keine Aussage möglich (Zeitüberschreitung, DNS, Netz, lokale Werkzeuggrenze, unklarer Fehler)
// mit Grund und Messverfahren. Fehlende Werte gelten nie als „nicht angeboten“.
// Format 3 (Prüfkern ab 0.4) ergänzt die Zertifikatsdiagnose: Namen je Kettenelement (san_dns, san_ip, cn),
// selbst_signiert, zertifikat.geliefert (vom Server gesendete Kette in Lieferreihenfolge) und zertifikat.pruefsystem
// (Node/OpenSSL und Vertrauensspeicher). Format 2 und das Altformat werden beim Laden ausdrücklich nach Format 3 überführt
// (ausFormat2): Namen aus den Textfeldern san/subject, soweit eindeutig lesbar; der gelieferte Ketteninhalt bleibt unbekannt.
'use strict';
const { sanLesen, cnLesen } = require('./zertifikat');

const FORMAT = 'ciphermeter-rohdaten/3';
const FORMAT_2 = 'ciphermeter-rohdaten/2';
const VERSIONEN = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const BLOECKE = ['tls12_suiten', 'tls13_suiten', 'gruppen_tls13', 'gruppen_tls12', 'signaturen_tls13'];
const MERKMALE = ['extended_master_secret', 'sichere_renegotiation', 'kompression', 'encrypt_then_mac_bei_cbc'];
const STATUS = new Set(['angeboten', 'abgelehnt', 'nicht_pruefbar']);
const BLOCKSTATUS = new Set(['geprueft', 'nicht_anwendbar', 'nicht_pruefbar']);
const WERTE = new Set(['ja', 'nein', 'nicht_anwendbar', 'nicht_pruefbar']);
// Zu welcher Protokollversion ein Block gehört; „nicht anwendbar“ ist nur zulässig, wenn diese Version nachweislich abgelehnt wird.
const BLOCK_VERSION = { tls12_suiten: 'TLSv1.2', gruppen_tls12: 'TLSv1.2', tls13_suiten: 'TLSv1.3', gruppen_tls13: 'TLSv1.3', signaturen_tls13: 'TLSv1.3' };
// Blöcke, für die ein gelungener Handshake der Version mindestens einen angebotenen Wert belegt (Gruppen TLS 1.2 nicht: DHE/RSA ohne ECDHE möglich)
const MUSS_ANGEBOTEN = ['tls12_suiten', 'tls13_suiten', 'gruppen_tls13', 'signaturen_tls13'];
const ALT = 'Altformat (Prüfkern 0.1): Fehlergrund nicht erfasst – „nein“ kann Ablehnung oder Messfehler bedeuten';

class RohdatenFehler extends Error {
  constructor(fehler) { super('Rohdaten ungültig:\n- ' + fehler.join('\n- ')); this.name = 'RohdatenFehler'; this.fehler = fehler; }
}

const istObj = o => o && typeof o === 'object' && !Array.isArray(o);
const istDatum = s => typeof s === 'string' && !Number.isNaN(Date.parse(s));

// Altformat → Format 2 (nur was die Altdaten wirklich belegen)
function ausAltformat(r) {
  const n = { format: FORMAT_2, altformat: true, ziel: r.ziel, zeitpunkt: r.zeitpunkt, werkzeug: r.werkzeug || {}, handshakes: r.handshakes };
  n.verfahren = { hinweis: 'Altformat: Verfahren je Merkmal nicht erfasst' };
  n.versionen = {};
  for (const v of VERSIONEN) {
    const w = istObj(r.versionen) ? r.versionen[v] : undefined;
    n.versionen[v] = w === 'ja' ? { status: 'angeboten', verfahren: 'Handshake (Altformat)' }
      : { status: 'nicht_pruefbar', grund: w === 'nein' ? ALT : 'Wert fehlt in den Rohdaten' };
  }
  const block = (liste, version, abbild) => {
    const vs = n.versionen[version].status;
    if (!Array.isArray(liste)) return { status: 'nicht_pruefbar', grund: 'Wert fehlt in den Rohdaten', eintraege: [] };
    return { status: vs === 'angeboten' ? 'geprueft' : 'nicht_pruefbar', nur_positive: true,
      grund: 'Altformat: nur angebotene Werte erfasst; nicht aufgeführte Werte sind nicht als abgelehnt belegt',
      eintraege: liste.map(abbild) };
  };
  n.tls12_suiten = block(r.tls12_suiten, 'TLSv1.2', s => istObj(s) ? { name: s.iana, iana_code: s.iana_code, openssl: s.openssl, status: 'angeboten', schluesselaustausch: s.schluesselaustausch || null } : { name: s });
  n.tls13_suiten = block(r.tls13_suiten, 'TLSv1.3', s => ({ name: s, status: 'angeboten' }));
  n.gruppen_tls13 = block(r.gruppen_tls13, 'TLSv1.3', s => ({ name: s, status: 'angeboten' }));
  n.gruppen_tls12 = block(r.gruppen_tls12, 'TLSv1.2', s => ({ name: s, status: 'angeboten' }));
  n.signaturen_tls13 = block(r.signaturen_tls13, 'TLSv1.3', s => ({ name: s, status: 'angeboten' }));
  const sh = r.standard_handshake || {};
  n.standard_handshake = sh.protokoll ? { status: 'ok', protokoll: sh.protokoll, suite: sh.suite || null, gruppe: sh.gruppe || null }
    : { status: 'nicht_pruefbar', grund: 'kein erfolgreicher Standard-Handshake erfasst' };
  const z = r.zertifikat || {};
  n.zertifikat = Array.isArray(z.kette) && z.kette.length ? { status: 'ok', kette: z.kette, vertrauenswuerdig: z.vertrauenswuerdig === true, fehler: z.fehler || null }
    : { status: 'nicht_pruefbar', grund: 'keine Zertifikatskette erfasst', kette: [] };
  const m = r.tls12_merkmale;
  if (n.versionen['TLSv1.2'].status !== 'angeboten') n.tls12_merkmale = { status: 'nicht_pruefbar', grund: 'TLS 1.2 im Altformat nicht als angeboten belegt' };
  else if (!istObj(m)) n.tls12_merkmale = { status: 'nicht_pruefbar', grund: 'Wert fehlt in den Rohdaten' };
  else {
    const jn = (w, beleg) => w === 'ja' ? { wert: 'ja', verfahren: beleg } : w === 'nein' ? { wert: 'nein', verfahren: beleg }
      : { wert: 'nicht_pruefbar', grund: w === undefined ? 'Wert fehlt in den Rohdaten' : `Messung ergab „${w}“` };
    const sc = 'openssl s_client (Altformat)';
    n.tls12_merkmale = { status: 'geprueft', extended_master_secret: jn(m.extended_master_secret, sc), sichere_renegotiation: jn(m.sichere_renegotiation, sc),
      // Das Altverfahren bot selbst keine Kompression an; „Compression: NONE“ belegt daher nicht, dass der Server sie ablehnt.
      kompression: m.kompression === 'ja' ? { wert: 'ja', verfahren: sc }
        : { wert: 'nicht_pruefbar', grund: 'Altformat: Prüfsystem hat keine Kompression angeboten; Ablehnung nicht belegt' },
      encrypt_then_mac_bei_cbc: m.encrypt_then_mac_bei_cbc === 'keine CBC-Suite angeboten' ? { wert: 'nicht_anwendbar', grund: 'keine CBC-Suite angeboten' } : jn(m.encrypt_then_mac_bei_cbc, sc + ' -tlsextdebug') };
  }
  return n;
}

// Format 2 → Format 3 (Eingabe bleibt unverändert). Nur was die Daten belegen: fehlt das Feld san, bleiben die Namen
// unbekannt; ein mehrdeutiger Common Name bleibt null. Ob ein Fehlercode in Format 2 auch eine Namensabweichung enthält,
// wertet bewertung.js aus (ERR_TLS_CERT_ALTNAME_INVALID).
function ausFormat2(r) {
  const n = { ...r, format: FORMAT, migriert_von: r.altformat ? `Altformat (Prüfkern 0.1) über ${FORMAT_2}` : FORMAT_2 };
  if (!istObj(r.zertifikat)) return n;
  const z = n.zertifikat = { ...r.zertifikat };
  if (Array.isArray(z.kette)) z.kette = z.kette.map(k => {
    if (!istObj(k) || 'san_dns' in k) return k;
    const e = { ...k };
    if (k.san !== undefined) { const s = sanLesen(k.san); e.san_dns = s ? (s.ungueltig ? null : s.dns) : []; e.san_ip = s ? (s.ungueltig ? null : s.ip) : []; }
    if (typeof k.subject === 'string') e.cn = cnLesen(k.subject, /(?<!\\), /);
    return e;
  });
  z.geliefert = { status: 'nicht_pruefbar', art: 'methode', grund: 'Rohdatenformat 2 enthält den vom Server gelieferten Ketteninhalt nicht' };
  if (z.status === 'ok' && !z.pruefsystem) {
    const w = istObj(r.werkzeug) ? r.werkzeug : {};
    z.pruefsystem = { node: w.node || null, openssl: w.openssl_node || null, vertrauensspeicher: 'Zertifikatsspeicher von Node.js (Einzelheiten in Rohdatenformat 2 nicht erfasst)',
      namenspruefung: 'in Format 2 nicht getrennt erfasst' };
  }
  return n;
}

function pruefen(r) {
  const f = [];
  if (!istObj(r)) throw new RohdatenFehler(['Rohdaten sind kein JSON-Objekt']);
  if (!istObj(r.ziel)) f.push('ziel fehlt');
  else {
    if (typeof r.ziel.host !== 'string' || !/^[A-Za-z0-9.:_-]{1,253}$/.test(r.ziel.host)) f.push('ziel.host fehlt oder ist ungültig');
    if (!Number.isInteger(r.ziel.port) || r.ziel.port < 1 || r.ziel.port > 65535) f.push('ziel.port fehlt oder ist ungültig');
    if (r.ziel.sni != null && (typeof r.ziel.sni !== 'string' || !/^[A-Za-z0-9.-]{1,253}$/.test(r.ziel.sni))) f.push('ziel.sni ist ungültig');
  }
  if (!istDatum(r.zeitpunkt)) f.push('zeitpunkt fehlt oder ist kein Datum');
  if (!istObj(r.versionen)) f.push('versionen fehlt');
  else for (const v of VERSIONEN) {
    const e = r.versionen[v];
    if (!istObj(e) || !STATUS.has(e.status)) f.push(`versionen.${v}: Zustand fehlt oder ist ungültig`);
    else if (e.status === 'nicht_pruefbar' && !e.grund) f.push(`versionen.${v}: „nicht prüfbar“ ohne Grund`);
  }
  for (const b of BLOECKE) {
    const blk = r[b];
    if (!istObj(blk) || !BLOCKSTATUS.has(blk.status) || !Array.isArray(blk.eintraege)) { f.push(`${b}: Block fehlt oder ist ungültig`); continue; }
    if (blk.status !== 'geprueft' && !blk.grund) f.push(`${b}: „${blk.status === 'nicht_anwendbar' ? 'nicht anwendbar' : 'nicht prüfbar'}“ ohne Grund`);
    blk.eintraege.forEach((e, i) => {
      if (!istObj(e) || typeof e.name !== 'string' || !e.name) f.push(`${b}[${i}]: Name fehlt`);
      else if (!STATUS.has(e.status)) f.push(`${b}[${i}] ${e.name}: Zustand fehlt oder ist ungültig`);
      else if (e.status === 'nicht_pruefbar' && !e.grund) f.push(`${b}[${i}] ${e.name}: „nicht prüfbar“ ohne Grund`);
    });
  }
  if (!istObj(r.zertifikat) || !Array.isArray(r.zertifikat.kette)) f.push('zertifikat fehlt oder ist ungültig');
  else r.zertifikat.kette.forEach((k, i) => {
    if (!istObj(k)) f.push(`zertifikat.kette[${i}] ist kein Objekt`);
    // Zeitangaben nur auf Typ prüfen; ungültige Kalenderdaten bewertet bewertung.js ausdrücklich als „nicht prüfbar“
    else {
      for (const feld of ['gueltigAb', 'gueltigBis']) if (k[feld] != null && typeof k[feld] !== 'string') f.push(`zertifikat.kette[${i}].${feld} ist kein Text`);
      for (const feld of ['san_dns', 'san_ip']) if (k[feld] != null && (!Array.isArray(k[feld]) || k[feld].some(x => typeof x !== 'string'))) f.push(`zertifikat.kette[${i}].${feld} ist keine Namensliste`);
    }
  });
  const gl = istObj(r.zertifikat) ? r.zertifikat.geliefert : undefined;
  if (gl !== undefined && (!istObj(gl) || !['geprueft', 'nicht_pruefbar'].includes(gl.status) || (gl.status === 'geprueft' ? !Array.isArray(gl.zertifikate) || gl.zertifikate.some(x => !istObj(x)) : !gl.grund)))
    f.push('zertifikat.geliefert ist ungültig');
  if (r.tls12_merkmale != null) {
    const m = r.tls12_merkmale;
    if (!istObj(m) || !BLOCKSTATUS.has(m.status)) f.push('tls12_merkmale ist ungültig');
    else if (m.status === 'geprueft') for (const k of MERKMALE) if (!istObj(m[k]) || !WERTE.has(m[k].wert)) f.push(`tls12_merkmale.${k}: Wert fehlt oder ist ungültig`);
  }
  if (f.length) throw new RohdatenFehler(f);
  // Widersprüche
  const st = v => r.versionen[v].status;
  const angeboten = b => r[b].eintraege.some(e => e.status === 'angeboten');
  for (const [v, bl] of [['TLSv1.2', ['tls12_suiten', 'gruppen_tls12']], ['TLSv1.3', ['tls13_suiten', 'gruppen_tls13', 'signaturen_tls13']]])
    if (st(v) === 'abgelehnt') for (const b of bl) if (angeboten(b)) f.push(`Widerspruch: ${v} abgelehnt, aber ${b} enthält angebotene Werte`);
  const sh = r.standard_handshake;
  if (sh && sh.status === 'ok' && VERSIONEN.includes(sh.protokoll) && st(sh.protokoll) === 'abgelehnt') f.push(`Widerspruch: Standard-Handshake mit ${sh.protokoll}, Version aber als abgelehnt erfasst`);
  if (r.tls12_merkmale && r.tls12_merkmale.status === 'geprueft' && st('TLSv1.2') === 'abgelehnt') f.push('Widerspruch: TLS-1.2-Merkmale gemessen, TLS 1.2 aber abgelehnt');
  // „Nicht anwendbar“ nur mit nachvollziehbarer Voraussetzung: Version nachweislich nicht angeboten bzw. keine CBC-Suite angeboten
  const vText = v => st(v) === 'angeboten' ? 'angeboten' : 'nicht nachweislich abgelehnt';
  for (const [b, v] of Object.entries(BLOCK_VERSION)) if (r[b].status === 'nicht_anwendbar' && st(v) !== 'abgelehnt') f.push(`Widerspruch: ${b} „nicht anwendbar“, ${v} ist aber ${vText(v)}`);
  if (r.tls12_merkmale && r.tls12_merkmale.status === 'nicht_anwendbar' && st('TLSv1.2') !== 'abgelehnt') f.push(`Widerspruch: tls12_merkmale „nicht anwendbar“, TLSv1.2 ist aber ${vText('TLSv1.2')}`);
  const etm = r.tls12_merkmale && r.tls12_merkmale.status === 'geprueft' ? r.tls12_merkmale.encrypt_then_mac_bei_cbc : null;
  if (etm && etm.wert === 'nicht_anwendbar' && r.tls12_suiten.eintraege.some(e => e.status === 'angeboten' && /_CBC_/.test(e.name)))
    f.push('Widerspruch: Encrypt-then-MAC „nicht anwendbar“, es wird aber eine CBC-Suite angeboten');
  if (f.length) throw new RohdatenFehler(f);
}

// Messstatus nur aus der Messung: nicht_erfolgreich (kein einziger Handshake gelungen), eingeschraenkt, vollstaendig.
// „Grenzen“ sind dauerhafte, im Bericht ausgewiesene Grenzen des Verfahrens (art: 'methode', PSK/SRP ohne Zugangsdaten);
// sie machen die Messung nicht unvollständig. Alles andere, was nicht prüfbar war, macht sie „eingeschränkt“.
//
// Vollständigkeit: Ist eine Version angeboten, muss jeder zugehörige Block wirklich gemessen sein. Leere Listen, Listen ohne
// angebotenen Wert (wo ein Handshake einen belegt), fehlende Pflichtkandidaten und ein fehlender Merkmalsblock bei TLS 1.2
// machen die Messung „eingeschränkt“ und stehen als „luecken“ im Ergebnis (die Bewertung zeigt sie als „nicht prüfbar“).
// Pflichtkandidaten: pflichtkandidaten(tr); ohne Angabe wird nur die Struktur geprüft.
function messstatus(r, { pflicht } = {}) {
  const gruende = [], grenzen = [], luecken = [];
  const luecke = (block, merkmal, grund) => { luecken.push({ block, merkmal, grund }); gruende.push({ wo: `${block}: ${merkmal}`, grund }); };
  const np = (wo, grund) => gruende.push({ wo, grund });
  let erfolg = false;
  for (const v of VERSIONEN) { const e = r.versionen[v]; if (e.status === 'angeboten') erfolg = true; if (e.status === 'nicht_pruefbar') np(`Version ${v}`, e.grund); }
  for (const b of BLOECKE) {
    const blk = r[b];
    if (blk.status === 'nicht_pruefbar') np(b, blk.grund || 'nicht prüfbar');
    else if (blk.nur_positive && blk.status === 'geprueft') np(b, blk.grund);
    for (const e of blk.eintraege) { if (e.status === 'angeboten') erfolg = true;
      if (e.status === 'nicht_pruefbar') (e.art === 'methode' ? grenzen.push({ wo: `${b}: ${e.name}`, grund: e.grund }) : np(`${b}: ${e.name}`, e.grund)); }
    for (const n of blk.ausserhalb_pruefumfang || []) grenzen.push({ wo: `${b}: ${n}`, grund: 'ohne Zugangsdaten (PSK/SRP) nicht messbar; außerhalb des Prüfumfangs' });
  }
  if (r.standard_handshake && r.standard_handshake.status === 'ok') erfolg = true;
  if (!r.zertifikat || r.zertifikat.status !== 'ok' || !r.zertifikat.kette.length) np('Zertifikat', (r.zertifikat && r.zertifikat.grund) || 'keine Zertifikatskette');
  const m = r.tls12_merkmale;
  if (m && m.status === 'nicht_pruefbar') np('TLS-1.2-Merkmale', m.grund);
  if (m && m.status === 'geprueft') for (const k of MERKMALE) if (m[k].wert === 'nicht_pruefbar') np(`Merkmal ${k}`, m[k].grund);
  const vName = { 'TLSv1.2': 'TLS 1.2', 'TLSv1.3': 'TLS 1.3' };
  for (const [b, v] of Object.entries(BLOCK_VERSION)) {
    const blk = r[b];
    if (r.versionen[v].status !== 'angeboten' || blk.status !== 'geprueft' || blk.nur_positive) continue;
    if (!blk.eintraege.length) { luecke(b, 'gesamter Bereich', `Liste leer, obwohl ${vName[v]} angeboten wird`); continue; }
    if (MUSS_ANGEBOTEN.includes(b) && !blk.eintraege.some(e => e.status === 'angeboten' || e.status === 'nicht_pruefbar'))
      luecke(b, 'gesamter Bereich', `kein Wert als angeboten gemessen, obwohl ${vName[v]} angeboten wird; Messung unvollständig oder widersprüchlich`);
    const gemessen = new Set(blk.eintraege.map(e => e.name.toLowerCase()));
    for (const n of (pflicht && pflicht[b]) || []) if (!gemessen.has(n.toLowerCase())) luecke(b, n, 'Pflichtkandidat wurde nicht gemessen (fehlt in den Rohdaten)');
  }
  if (r.versionen['TLSv1.2'].status === 'angeboten' && !m) luecke('tls12_merkmale', 'gesamter Bereich', 'Merkmalsblock fehlt, obwohl TLS 1.2 angeboten wird');
  const status = !erfolg ? 'nicht_erfolgreich' : gruende.length ? 'eingeschraenkt' : 'vollstaendig';
  return { status, gruende, grenzen, luecken };
}

// Pflichtkandidaten je Block aus dem Regelwerk: alle Tabellenwerte, die das Prüfsystem aushandeln kann, plus die
// hybriden Post-Quanten-Gruppen. FFDHE-Gruppen bei TLS 1.2 sind eine Verfahrensgrenze (gemessen wird über ECDHE; DH-Längen
// über die DHE-Suiten) und deshalb keine Pflicht. TLS-1.2-Suiten prüft bewertung.js gesondert gegen die Tabellen 3–5.
function pflichtkandidaten(tr) {
  const namen = l => (l || []).map(e => e.name);
  return { tls13_suiten: namen(tr.tls13_suiten),
    gruppen_tls13: [...new Set(namen(tr.gruppen_tls13).concat('X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'))],
    gruppen_tls12: namen(tr.gruppen_tls12).filter(n => !/^ffdhe/i.test(n)),
    signaturen_tls13: namen(tr.signaturen_tls13) };
}

// Einlesen: JSON-Text oder Objekt → geprüfte Rohdaten im Format 2 (wirft RohdatenFehler)
function laden(eingabe) {
  let r = eingabe;
  if (typeof eingabe === 'string') { try { r = JSON.parse(eingabe); } catch (e) { throw new RohdatenFehler([`kein gültiges JSON (${e.message})`]); } }
  if (!istObj(r)) throw new RohdatenFehler(['Rohdaten sind kein JSON-Objekt']);
  if (r.format === undefined) {
    const vorab = [];
    if (!istObj(r.ziel)) vorab.push('ziel fehlt');
    if (!istObj(r.versionen)) vorab.push('versionen fehlt');
    if (vorab.length) throw new RohdatenFehler(vorab);
    r = ausFormat2(ausAltformat(r));
  } else if (r.format === FORMAT_2) r = ausFormat2(r);
  else if (r.format !== FORMAT) throw new RohdatenFehler([`unbekanntes Format ${JSON.stringify(r.format)}`]);
  pruefen(r);
  return r;
}

module.exports = { FORMAT, FORMAT_2, ausFormat2, VERSIONEN, BLOECKE, BLOCK_VERSION, MERKMALE, RohdatenFehler, laden, pruefen, messstatus, pflichtkandidaten, ausAltformat };
