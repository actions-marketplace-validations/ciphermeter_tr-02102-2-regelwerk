// SPDX-License-Identifier: Apache-2.0
// Bewertet geprüfte Rohdaten (rohdaten.laden) gegen das Regelwerk TR-02102-2. Ergebnis ist eine Struktur ohne HTML.
// Stufen: ok (entspricht) · frist (Frist endet im laufenden Jahr) · abw (Abweichung: von der TR ausdrücklich nicht
// empfohlen, abgelaufen oder Bedingung nachweislich nicht erfüllt) · na (in keiner Tabelle aufgeführt – kein Urteil über
// die Sicherheit) · info (Einordnung) · np (nicht prüfbar – keine Aussage).
// Grundsatz: Positive und negative Bewertungen nur bei belegtem Messwert und eindeutiger Zuordnung zum Regelwerk.
'use strict';
const { messstatus, pflichtkandidaten, VERSIONEN } = require('./rohdaten');
const { kennung, beleg } = require('./befund');
const { namePruefen } = require('./zertifikat');

const STUFEN = ['abw', 'frist', 'np', 'na', 'info', 'ok'];
const vName = { TLSv1: 'TLS 1.0', 'TLSv1.1': 'TLS 1.1', 'TLSv1.2': 'TLS 1.2', 'TLSv1.3': 'TLS 1.3' };
const fs_ = f => !f ? '' : `Abschn. ${f.abschnitt}${f.tabelle ? `, Tab. ${f.tabelle}` : ''}${f.seite ? `, S. ${f.seite}` : ''}`;
const bisText = e => `bis ${e.bis}${e.bis_verlaengerbar ? '+' : ''}`;
const gross = s => s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
const KURVEN_BITS = { prime256v1: 256, secp256r1: 256, secp384r1: 384, secp521r1: 521, brainpoolP256r1: 256, brainpoolP384r1: 384, brainpoolP512r1: 512 };
const KURVE_TLS13 = { prime256v1: 'secp256r1', secp256r1: 'secp256r1', secp384r1: 'secp384r1', secp521r1: 'secp521r1',
  brainpoolP256r1: 'brainpoolP256r1tls13', brainpoolP384r1: 'brainpoolP384r1tls13', brainpoolP512r1: 'brainpoolP512r1tls13' };
// Betriebliche Vorwarnschwellen vor Zertifikatsablauf: Produktentscheidung von Ciphermeter, keine Vorgabe der TR-02102-2.
// Unter VORWARNUNG_TAGE gilt das Zertifikat im Bericht als „bald ablaufend“; die Fristenübersicht nennt beide Schwellen.
const VORWARNUNG_TAGE = 21;
const VORWARNSCHWELLEN = [30, 21];
// Statische (EC)DH-Suiten (Tabelle 4) und PSK-Suiten (Tabelle 5) kann das Prüfsystem nicht aushandeln: Grenze des Verfahrens
const NICHT_MESSBAR_TR = /^TLS_(ECDH|DH)_(ECDSA|RSA|DSS)_|_PSK_/;

function bewerten(roh, tr, { stichtag } = {}) {
  const tag = stichtag ? new Date(stichtag) : new Date(roh.zeitpunkt);
  if (Number.isNaN(tag.getTime())) throw new Error('Stichtag ungültig');
  const jahr = tag.getUTCFullYear();
  const stufeAusTabelle = e => !e ? 'na' : e.bis < jahr ? 'abw' : e.bis === jahr ? 'frist' : 'ok';
  const zeilen = [];
  const add = (bereich, merkmal, stufe, text, fundstelle = '', schluessel = null, extra = {}) =>
    zeilen.push({ bereich, merkmal, stufe, text, fundstelle, schluessel: schluessel || `${bereich}:${merkmal}`, ...extra });
  const npText = e => `Nicht prüfbar: ${e.grund || 'kein Messwert'}.`;
  const ctx = { roh, tr, jahr, tag, add, npText, stufeAusTabelle, zeilen };
  for (const teil of [versionen, suiten13, suiten12, gruppen, signaturen13, zertifikat, merkmale12]) teil(ctx);

  // Grenzen und Status; Lücken der Messung (leere Listen, fehlende Pflichtkandidaten, fehlender Merkmalsblock) als „nicht prüfbar“
  const ms = messstatus(roh, { pflicht: pflichtkandidaten(tr) });
  const BEREICH = { tls12_suiten: 'Cipher-Suiten TLS 1.2', tls13_suiten: 'Cipher-Suiten TLS 1.3', gruppen_tls13: 'Gruppen TLS 1.3', gruppen_tls12: 'Gruppen TLS 1.2',
    signaturen_tls13: 'Signaturverfahren TLS 1.3', tls12_merkmale: 'Erweiterungen TLS 1.2' };
  for (const l of ms.luecken) add(BEREICH[l.block] || l.block, l.merkmal, 'np', `Nicht prüfbar: ${l.grund}.`, '', `luecke:${l.block}:${l.merkmal}`, { luecke: true });
  const grenzen = [...ms.grenzen];
  if (roh.tls12_suiten.status === 'geprueft' && !roh.tls12_suiten.nur_positive) {
    const geprueft = new Set(roh.tls12_suiten.eintraege.map(e => e.name).concat(roh.tls12_suiten.ausserhalb_pruefumfang || []));
    for (const s of tr.tls12_suiten.filter(t => !geprueft.has(t.name))) {
      if (NICHT_MESSBAR_TR.test(s.name)) grenzen.push({ wo: `Cipher-Suiten TLS 1.2: ${s.name}`, grund: /_PSK_/.test(s.name) ? 'PSK-Suite, ohne Zugangsdaten nicht messbar' : 'statische (EC)DH-Suite, vom Prüfsystem (OpenSSL) nicht unterstützt' });
      else add('Cipher-Suiten TLS 1.2', s.name, 'np', 'Nicht prüfbar: lokale Werkzeuggrenze, die Suite fehlt in der Kandidatenliste des Prüfsystems.', fs_(s.fundstelle), `tls12_suite:${s.name}`);
    }
  }
  // Stabile Kennung (aus Regel + Merkmal) und Messbeleg je Zeile
  for (const z of zeilen) { z.kennung = kennung(z.schluessel); z.beleg = beleg(roh, z); }
  const zaehl = Object.fromEntries(STUFEN.map(s => [s, 0])); zeilen.forEach(z => zaehl[z.stufe]++);
  const npZeilen = zeilen.filter(z => z.stufe === 'np' && !z.grenze);
  const gesamt = ms.status === 'nicht_erfolgreich' ? 'nicht_erfolgreich' : npZeilen.length || ms.status === 'eingeschraenkt' ? 'eingeschraenkt' : 'vollstaendig';
  // Gelieferter Ketteninhalt ist Diagnose, keine Bewertung: unbekannt → Grenze, macht die Messung nicht unvollständig
  const zd = ctx.zertDiagnose;
  if (zd && !zd.geliefert.bekannt) grenzen.push({ wo: 'Zertifikat: gelieferter Ketteninhalt', grund: `Gelieferter Ketteninhalt unbekannt (${zd.geliefert.grund})` });
  return { gesamt, messstatus: ms.status, stichtag: tag.toISOString(), jahr, zeilen, zaehl, zertifikat: zertifikatDiagnose(roh, zd),
    aufmerksamkeit: zeilen.filter(z => z.stufe === 'abw' || z.stufe === 'frist'),
    hinweise: zeilen.filter(z => z.stufe === 'na' || z.stufe === 'info'),
    nichtPruefbar: npZeilen,
    pruefgrenzen: zeilen.filter(z => z.stufe === 'np' && z.grenze),
    // Grenzen je Merkmal nur einmal: Methodengrenzen stehen sowohl im Messstatus als auch als Zeile
    grenzen: einmal(grenzen.concat(zeilen.filter(z => z.grenze).map(z => ({ wo: `${z.bereich}: ${z.merkmal}`, grund: z.text.replace(/^Nicht prüfbar: /, '').replace(/.$/, '') })))) };
}

const einmal = gs => { const da = new Set(), k = g => `${g.grund}|${g.wo.split(': ').pop()}`; return gs.filter(g => !da.has(k(g)) && da.add(k(g))); };

// Blöcke: Rückgabe false, wenn nichts einzeln zu bewerten ist
function blockKopf({ roh, add, npText }, b, bereich) {
  const blk = roh[b];
  if (blk.status === 'nicht_pruefbar') { add(bereich, 'gesamter Bereich', 'np', npText(blk), '', `${b}:block`); return false; }
  if (blk.status === 'nicht_anwendbar') return false;
  if (blk.nur_positive) add(bereich, 'nicht angebotene Werte', 'np', 'Altformat: Es wurden nur angebotene Werte erfasst; ob weitere Werte abgelehnt werden, ist nicht belegt.', '', `${b}:alt`);
  return true;
}
const npZeile = ({ add, npText }, bereich, praefix, e) => add(bereich, e.name, 'np', npText(e), '', `${praefix}:${e.name}`, e.art === 'methode' ? { grenze: true } : {});

function versionen({ roh, tr, add, npText, stufeAusTabelle }) {
  for (const k of VERSIONEN) {
    const m = roh.versionen[k], e = tr.versionen.find(v => v.name === vName[k]);
    const sk = `version:${k}`;
    if (m.status === 'nicht_pruefbar') { add('Protokollversionen', vName[k], 'np', npText(m), fs_(e.fundstelle), sk); continue; }
    if (m.status === 'angeboten') {
      if (e.status === 'nicht_empfohlen') add('Protokollversionen', vName[k], 'abw', 'Wird angeboten, ist aber nicht empfohlen.', fs_(e.fundstelle), sk, { regel: 'version_alt' });
      else add('Protokollversionen', vName[k], stufeAusTabelle(e), `Wird angeboten; empfohlen ${bisText(e)}.${e.hinweis ? ' ' + gross(e.hinweis) + '.' : ''}`, fs_(e.fundstelle), sk);
    } else if (e.status === 'empfohlen') {
      if (k === 'TLSv1.3') add('Protokollversionen', vName[k], 'abw', 'Wird nachweislich nicht angeboten. TLS 1.3 ist die bevorzugte Version.', fs_(e.fundstelle), sk, { regel: 'tls13_fehlt' });
      else add('Protokollversionen', vName[k], 'info', 'Wird nachweislich nicht angeboten. Das ist zulässig, solange TLS 1.3 angeboten wird.', fs_(e.fundstelle), sk);
    } else add('Protokollversionen', vName[k], 'ok', `Wird nachweislich nicht angeboten (${m.grund}).`, fs_(e.fundstelle), sk);
  }
}

function suiten13(ctx) {
  const { roh, tr, add, stufeAusTabelle } = ctx;
  if (!blockKopf(ctx, 'tls13_suiten', 'Cipher-Suiten TLS 1.3')) return;
  for (const s of roh.tls13_suiten.eintraege) {
    if (s.status === 'nicht_pruefbar') { npZeile(ctx, 'Cipher-Suiten TLS 1.3', 'tls13_suite', s); continue; }
    if (s.status !== 'angeboten') continue;
    const e = tr.tls13_suiten.find(t => t.name === s.name);
    if (e) add('Cipher-Suiten TLS 1.3', s.name, stufeAusTabelle(e), `Wird angeboten; empfohlen ${bisText(e)}.`, fs_(e.fundstelle), `tls13_suite:${s.name}`);
    else add('Cipher-Suiten TLS 1.3', s.name, 'na', s.name.includes('CHACHA20')
      ? 'Nicht in Tabelle 13. ChaCha20-Poly1305 gilt in der Fachwelt nicht als unsicher (RFC 8439); die TR führt es nur nicht auf.'
      : 'Nicht in Tabelle 13.', 'Abschn. 3.4.4, Tab. 13', `tls13_suite:${s.name}`, { regel: 'streng_tabellen' });
  }
}

function suiten12(ctx) {
  const { roh, tr, add, stufeAusTabelle } = ctx;
  if (!blockKopf(ctx, 'tls12_suiten', 'Cipher-Suiten TLS 1.2')) return;
  const m12 = roh.tls12_merkmale;
  const etm = m12 && m12.status === 'geprueft' ? m12.encrypt_then_mac_bei_cbc : null;
  for (const s of roh.tls12_suiten.eintraege) {
    if (s.status === 'nicht_pruefbar') { npZeile(ctx, 'Cipher-Suiten TLS 1.2', 'tls12_suite', s); continue; }
    if (s.status !== 'angeboten') continue;
    const e = tr.tls12_suiten.find(t => t.name === s.name);
    const sk = `tls12_suite:${s.name}`;
    if (e) {
      let st = stufeAusTabelle(e), regel = st === 'abw' || st === 'frist' ? 'tls12_suiten' : null, fund = fs_(e.fundstelle);
      let txt = `Wird angeboten; empfohlen ${bisText(e)}${e.pfs === false ? ', ohne Forward Secrecy (nur wenn Suiten aus Tabelle 3 nicht möglich sind)' : ''}.`;
      if (e.bedingung === 'encrypt_then_mac') {
        if (etm && etm.wert === 'ja') txt += ' CBC-Suite: Encrypt-then-MAC wird ausgehandelt, Bedingung erfüllt.';
        else if (etm && etm.wert === 'nein') { st = 'abw'; regel = 'tls12_suiten'; txt += ' CBC-Suite: Server wählt Encrypt-then-MAC nicht, obwohl angeboten; Bedingung nicht erfüllt.'; }
        else { st = 'np'; txt += ` CBC-Suite: Ob Encrypt-then-MAC ausgehandelt wird, ist nicht prüfbar (${etm ? etm.grund || etm.wert : 'kein Messwert'}).`; }
      }
      const dh = s.schluesselaustausch;
      if (dh && dh.type === 'DH' && dh.size && dh.size < 3000) { st = 'abw'; regel = 'tls12_suiten'; txt += ` Ausgehandelte DH-Parameter: ${dh.size} Bit, Mindestlänge laut Tabelle 14: 3000 Bit.`; fund += '; Abschn. 3.6.1, Tab. 14'; }
      add('Cipher-Suiten TLS 1.2', s.name, st, txt, fund, sk, regel ? { regel } : {});
    } else {
      let txt = 'In den Tabellen 3–5 nicht aufgeführt.', st = 'na', regel = 'tls12_suiten', fund = 'Abschn. 3.3.1, Tab. 3–5';
      if (/CHACHA20/.test(s.name)) { txt += ' ChaCha20-Poly1305 ist kein bekannter Sicherheitsmangel; die TR führt es nur nicht auf.'; regel = 'streng_tabellen'; }
      else if (/_SHA$/.test(s.name)) { st = 'abw'; txt = 'Nutzt HMAC-SHA-1; laut TR seit Fassung 2020-01 abgekündigt. In den Tabellen 3–5 nicht aufgeführt.'; fund += '; Tab. 1 (Änderungshistorie)'; }
      else if (/^TLS_RSA_/.test(s.name)) { txt += ' RSA-Schlüsseltransport ohne Forward Secrecy; Forward Secrecy wird grundsätzlich empfohlen.'; fund += '; Abschn. 3.3.1.1, S. 7 Fn. 2'; }
      add('Cipher-Suiten TLS 1.2', s.name, st, txt, fund, sk, { regel });
    }
  }
}

function gruppen(ctx) {
  const { roh, tr, add, stufeAusTabelle } = ctx;
  const pqcWeb = (tr.pqc || []).find(p => p.status === 'tr_konform_einsetzbar_tls13_laut_webseite') || { gruppen: [] };
  const dhMin = ((tr.schluessellaengen.schluesseleinigung || []).find(x => x.algorithmus === 'DH') || {}).min_bit || 3000;
  const ffdheBits = n => { const m = /^ffdhe(\d+)$/i.exec(n); return m ? Number(m[1]) : null; };
  const B13 = 'Gruppen TLS 1.3', B12 = 'Gruppen TLS 1.2';
  if (blockKopf(ctx, 'gruppen_tls13', B13)) for (const g of roh.gruppen_tls13.eintraege) {
    if (g.status === 'nicht_pruefbar') { npZeile(ctx, B13, 'gruppe13', g); continue; }
    if (g.status !== 'angeboten') continue;
    const e = tr.gruppen_tls13.find(t => t.name.toLowerCase() === g.name.toLowerCase());
    const sk = `gruppe13:${g.name}`;
    if (e) add(B13, g.name, stufeAusTabelle(e), `Wird angeboten; empfohlen ${bisText(e)}, allein (nicht hybrid) nur bis Ende 2031.`, fs_(e.fundstelle), sk);
    else if (pqcWeb.gruppen.includes(g.name)) add(B13, g.name, 'info', g.name === 'X25519MLKEM768'
      ? 'Hybride Post-Quanten-Gruppe. Nicht in Tabelle 10; laut BSI-Webseite (abgerufen 2026-10-26) zusätzlich einsetzbar.'
      : 'Hybride Post-Quanten-Gruppe. Nicht in Tabelle 10; laut BSI-Webseite ab sofort TR-konform einsetzbar und für die nächste Fassung angekündigt.', 'BSI-Webseite TR-02102, Hinweis zu TLS 1.3', sk);
    else if (ffdheBits(g.name) && ffdheBits(g.name) < dhMin) add(B13, g.name, 'abw', `Nicht in Tabelle 10; ${ffdheBits(g.name)} Bit liegt unter der Mindestlänge von ${dhMin} Bit für DH.`, 'Abschn. 3.4.2, Tab. 10; Abschn. 3.6.1, Tab. 14', sk, { regel: 'gruppen_tr' });
    else if (/^MLKEM/i.test(g.name)) add(B13, g.name, 'na', 'Reines ML-KEM ohne klassischen Anteil; weder in der TR noch auf der BSI-Webseite für TLS genannt (die TR spricht von hybrider Nutzung).', 'Abschn. 3.1.3', sk, { regel: 'streng_tabellen' });
    else add(B13, g.name, 'na', g.name.toLowerCase() === 'x25519'
      ? 'Nicht in Tabelle 10 (die TR nennt X25519 nur als Teil von X25519MLKEM768). X25519 gilt nicht als unsicher. Abschalten nur mit Folgenabschätzung: Clients, die ausschließlich X25519 anbieten, sind selten, aber möglich.'
      : 'Nicht in Tabelle 10.', 'Abschn. 3.4.2, Tab. 10', sk, { regel: 'streng_tabellen' });
  }
  if (blockKopf(ctx, 'gruppen_tls12', B12)) for (const g of roh.gruppen_tls12.eintraege) {
    if (g.status === 'nicht_pruefbar') { npZeile(ctx, B12, 'gruppe12', g); continue; }
    if (g.status !== 'angeboten') continue;
    const e = tr.gruppen_tls12.find(t => t.name.toLowerCase() === g.name.toLowerCase());
    if (e) add(B12, g.name, stufeAusTabelle(e), `Wird angeboten; empfohlen ${bisText(e)}.`, fs_(e.fundstelle), `gruppe12:${g.name}`);
    else add(B12, g.name, 'na', 'Nicht in Tabelle 6. Kein bekannter Sicherheitsmangel.', 'Abschn. 3.3.2, Tab. 6', `gruppe12:${g.name}`, { regel: 'streng_tabellen' });
  }
  // Post-Quanten-Vorbereitung: „wird nicht angeboten“ nur bei nachgewiesener Ablehnung
  if (roh.versionen['TLSv1.3'].status === 'angeboten' && roh.gruppen_tls13.status === 'geprueft' && !roh.gruppen_tls13.nur_positive) {
    const fehlend = ['SecP256r1MLKEM768', 'SecP384r1MLKEM1024'].map(n => roh.gruppen_tls13.eintraege.find(e => e.name === n)).filter(e => e && e.status === 'abgelehnt').map(e => e.name);
    if (fehlend.length) add('Post-Quanten-Vorbereitung', fehlend.join(', '), 'info', 'Wird nachweislich nicht angeboten. Diese Hybridgruppen will das BSI in der nächsten Fassung empfehlen; ab 2032 gelten klassische Gruppen nur noch im Hybrideinsatz.', 'Abschn. 3.1.3 und 3.4.2; BSI-Webseite', 'pqc:fehlend', { regel: 'pqc_hybrid' });
  }
}

function signaturen13(ctx) {
  const { roh, tr, add, stufeAusTabelle } = ctx;
  if (!blockKopf(ctx, 'signaturen_tls13', 'Signaturverfahren TLS 1.3')) return;
  for (const a of roh.signaturen_tls13.eintraege) {
    if (a.status === 'nicht_pruefbar') { npZeile(ctx, 'Signaturverfahren TLS 1.3', 'sig13', a); continue; }
    if (a.status !== 'angeboten') continue;
    const e = tr.signaturen_tls13.find(t => t.name === a.name);
    add('Signaturverfahren TLS 1.3', a.name, e ? stufeAusTabelle(e) : 'na', e ? `Wird verwendet; empfohlen ${bisText(e)}.` : 'Nicht in Tabelle 11.', e ? fs_(e.fundstelle) : 'Abschn. 3.4.3, Tab. 11', `sig13:${a.name}`, e ? {} : { regel: 'streng_tabellen' });
  }
}

function zertifikat(ctx) {
  const { roh, tr, tag, add, npText, stufeAusTabelle } = ctx;
  const kette = roh.zertifikat.status === 'ok' ? roh.zertifikat.kette : [];
  const z = kette[0];
  const sl = tr.schluessellaengen, B = 'Zertifikat', F = 'keine Vorgabe in TR-02102-2';
  if (!z) return add(B, 'Serverzertifikat', 'np', npText(roh.zertifikat), '', 'zert:fehlt');
  // Schlüssel gegen Tabelle 14
  const minRsa = (sl.signatur.find(x => x.algorithmus === 'RSA') || {}).min_bit, minEc = (sl.signatur.find(x => x.algorithmus === 'ECDSA') || {}).min_bit;
  const fsl = fs_(sl.fundstelle);
  if (z.schluessel === 'rsa' || z.schluessel === 'rsa-pss') {
    if (!Number.isInteger(z.bits)) add(B, 'Schlüssel', 'np', 'Nicht prüfbar: Schlüssellänge fehlt in den Rohdaten.', fsl, 'zert:schluessel');
    else add(B, 'Schlüssel', z.bits >= minRsa ? 'ok' : 'abw', `RSA ${z.bits} Bit; Mindestlänge laut Tabelle 14: RSA ${minRsa} Bit.`, fsl, 'zert:schluessel', z.bits >= minRsa ? {} : { regel: 'zert_schluessel' });
  } else if (z.schluessel === 'ec') {
    const bits = KURVEN_BITS[z.kurve];
    if (!bits) add(B, 'Schlüssel', 'np', `Nicht prüfbar: Kurve ${z.kurve ? `„${z.kurve}“ nicht zuordenbar` : 'fehlt in den Rohdaten'}.`, fsl, 'zert:schluessel');
    else add(B, 'Schlüssel', bits >= minEc ? 'ok' : 'abw', `ECDSA ${z.kurve} (${bits} Bit); Mindestlänge laut Tabelle 14: ECDSA ${minEc} Bit.`, fsl, 'zert:schluessel', bits >= minEc ? {} : { regel: 'zert_schluessel' });
  } else if (z.schluessel) add(B, 'Schlüssel', 'na', `Schlüsselart ${z.schluessel}; nicht in Tabelle 14.`, fsl, 'zert:schluessel');
  else add(B, 'Schlüssel', 'np', 'Nicht prüfbar: Schlüsselart fehlt in den Rohdaten.', fsl, 'zert:schluessel');
  // Signatur gegen Tabelle 12 (signature_algorithms_cert)
  const sig = signaturZuordnen(z, kette, tr);
  add(B, 'Signatur', sig.stufe === 'tabelle' ? stufeAusTabelle(sig.eintrag) : sig.stufe, sig.text, sig.fundstelle, 'zert:signatur', sig.regel ? { regel: sig.regel } : {});
  // Gültigkeit am Stichtag (getrennt von der Vertrauenskette)
  const g = gueltigkeit(z, tag);
  add(B, 'Gültigkeit', g.stufe, g.text, F, 'zert:gueltigkeit', { gueltigkeit: g.zustand, ...(g.stufe === 'abw' || g.stufe === 'frist' ? { regel: 'zert_gueltigkeit' } : {}) });
  // Namenspassung (RFC 6125), unabhängig vom Vertrauen
  const name = roh.ziel.sni || roh.ziel.host;
  const n = namePruefen(name, z);
  const namenText = l => l.length ? `${l.slice(0, 6).join(', ')}${l.length > 6 ? ` und ${l.length - 6} weitere` : ''}` : 'keine';
  if (n.zustand === 'passt') add(B, 'Namenspassung', 'ok', `„${name}“ steht im Zertifikat (${n.ueber === 'san_ip' ? 'SAN, IP-Adresse' : 'SAN'}: ${n.treffer}).`, `${F}; RFC 6125`, 'zert:name');
  else if (n.zustand === 'nur_cn') add(B, 'Namenspassung', 'abw', `„${name}“ steht nur im Common Name; das Zertifikat hat keinen DNS-Namen im Subject Alternative Name. Viele aktuelle Clients, darunter Browser, werten den Common Name nicht mehr aus.`, `${F}; RFC 6125`, 'zert:name', { regel: 'zert_name' });
  else if (n.zustand === 'passt_nicht') add(B, 'Namenspassung', 'abw', `„${name}“ steht nicht im Zertifikat (enthaltene Namen: ${namenText(n.namen)}).`, `${F}; RFC 6125`, 'zert:name', { regel: 'zert_name' });
  else add(B, 'Namenspassung', 'np', `Nicht prüfbar: ${n.grund}.`, `${F}; RFC 6125`, 'zert:name');
  // Vertrauen aus Sicht des Prüfsystems; aus einem Fehlercode wird keine unbelegte Ursache abgeleitet
  const gl = ketteAuswerten(roh.zertifikat.geliefert);
  const v = vertrauen(roh.zertifikat, gl);
  add(B, 'Vertrauenskette', v.stufe, v.text + (v.ursachen.length ? ` Mögliche Ursachen (vom Prüfsystem nicht unterschieden): ${v.ursachen.join('; ')}.` : ''), F, 'zert:kette', v.stufe === 'abw' ? { regel: 'zert_kette' } : {});
  ctx.zertDiagnose = { gepruefter_name: name, namenspassung: { zustand: n.zustand, ueber: n.ueber || null, namen: n.namen || null },
    gueltigkeit: { zustand: g.zustand, rest_tage: g.rest == null ? null : g.rest }, geliefert: gl, vertrauen: { zustand: v.zustand, code: roh.zertifikat.fehler || null, text: v.text, ursachen: v.ursachen } };
}

// Zertifikat im Überblick (für Bericht und Export): Serverzertifikat, Namenspassung, Gültigkeit, gelieferte Kette,
// Vertrauen aus Sicht des Prüfsystems und die vom Prüfsystem gebildete Kette. null, wenn kein Zertifikat vorliegt.
function zertifikatDiagnose(roh, zd) {
  const zert = roh.zertifikat, z = zert.status === 'ok' ? zert.kette[0] : null;
  if (!z || !zd) return { status: 'nicht_pruefbar', grund: zert.grund || 'keine Zertifikatskette' };
  const namen = Array.isArray(z.san_dns) && Array.isArray(z.san_ip) ? [...z.san_dns, ...z.san_ip] : null;
  return { status: 'ok', gepruefter_name: zd.gepruefter_name,
    blatt: { inhaber: z.subject || null, aussteller: z.issuer || null, namen, cn: z.cn === undefined ? null : z.cn,
      gueltig_ab: z.gueltigAb || null, gueltig_bis: z.gueltigBis || null, rest_tage: zd.gueltigkeit.rest_tage, fingerabdruck_sha256: z.fingerprint256 || null,
      schluessel: z.schluessel ? `${z.schluessel === 'ec' ? `ECDSA ${z.kurve || '?'}` : z.schluessel.toUpperCase()}${z.bits ? ` ${z.bits} Bit` : ''}` : null },
    namenspassung: zd.namenspassung, gueltigkeit: zd.gueltigkeit, geliefert: zd.geliefert,
    vertrauen: { ...zd.vertrauen, pruefsystem: zert.pruefsystem || null },
    kette_pruefsystem: zert.kette.map((k, i) => ({ nr: i + 1, inhaber: k.subject || null, aussteller: k.issuer || null, gueltig_bis: k.gueltigBis || null,
      selbst_signiert: typeof k.selbst_signiert === 'boolean' ? k.selbst_signiert : null })) };
}

// Ergebnis der Kettenprüfung des Prüfsystems → { zustand, stufe, text, ursachen[] }. Nur der Fehlercode und die gelieferten
// Zertifikate zählen als Beleg; mögliche Ursachen werden ausdrücklich als Möglichkeiten genannt.
const KETTE_NICHT_GEBILDET = ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT'];
function vertrauen(zert, gl) {
  const code = zert.fehler || null;
  if (typeof zert.vertrauenswuerdig !== 'boolean') return { zustand: 'unbekannt', stufe: 'np', text: 'Nicht prüfbar: kein Ergebnis der Kettenprüfung.', ursachen: [] };
  if (zert.vertrauenswuerdig) return { zustand: 'vertrauenswuerdig', stufe: 'ok', text: 'Das Prüfsystem bildet die Kette bis zu einer vertrauenswürdigen Wurzel.', ursachen: [] };
  // Format 2: Node.js meldet ERR_TLS_CERT_ALTNAME_INVALID nur, wenn die Kettenprüfung von OpenSSL bestanden ist
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') return { zustand: 'vertrauenswuerdig', stufe: 'ok', text: 'Das Prüfsystem hat die Kette bestätigt; der Fehlercode ERR_TLS_CERT_ALTNAME_INVALID betrifft nur den Namen (siehe „Namenspassung“).', ursachen: [] };
  const nurBlatt = gl.bekannt && gl.anzahl === 1 && !gl.blatt_selbst_signiert ? ' Beobachtet: Der Server liefert nur das Serverzertifikat.' : '';
  if (KETTE_NICHT_GEBILDET.includes(code)) return { zustand: 'nicht_vertrauenswuerdig', stufe: 'abw', text: `Die Kette konnte vom Prüfsystem nicht bis zu einer vertrauenswürdigen Wurzel gebildet werden (${code}).${nurBlatt}`,
    ursachen: ['ein Zwischenzertifikat wird nicht mitgeliefert', 'die Wurzel steht nicht im Vertrauensspeicher des Prüfsystems (z. B. private oder unternehmenseigene CA)', 'ein falsches oder veraltetes Zwischenzertifikat wird geliefert'] };
  if (code === 'DEPTH_ZERO_SELF_SIGNED_CERT') return { zustand: 'nicht_vertrauenswuerdig', stufe: 'abw', text: 'Das Serverzertifikat ist selbst signiert und steht nicht im Vertrauensspeicher des Prüfsystems (DEPTH_ZERO_SELF_SIGNED_CERT).', ursachen: [] };
  if (code === 'SELF_SIGNED_CERT_IN_CHAIN') return { zustand: 'nicht_vertrauenswuerdig', stufe: 'abw', text: 'Die Kette endet in einem selbst signierten Zertifikat, das nicht im Vertrauensspeicher des Prüfsystems steht (SELF_SIGNED_CERT_IN_CHAIN).',
    ursachen: ['private oder unternehmenseigene CA', 'Wurzel ist dem Prüfsystem nicht bekannt'] };
  if (code === 'CERT_HAS_EXPIRED' || code === 'CERT_NOT_YET_VALID') return { zustand: 'nicht_vertrauenswuerdig', stufe: 'abw',
    text: `Das Prüfsystem lehnt die Kette wegen des Gültigkeitszeitraums eines Zertifikats ab (${code}; siehe „Gültigkeit“). Ob die Kette sonst vertrauenswürdig wäre, belegt die Messung nicht.`, ursachen: [] };
  return { zustand: 'nicht_vertrauenswuerdig', stufe: 'abw', text: `Das Prüfsystem bestätigt die Kette nicht (${code || 'ohne Fehlercode'}). Eine Ursache leitet der Bericht daraus nicht ab.`, ursachen: [] };
}

// Vom Server gelieferte Kette (Format 3) → Befunde, die die gelieferten Zertifikate belegen
function ketteAuswerten(gl) {
  if (!gl || gl.status !== 'geprueft') return { bekannt: false, grund: gl ? gl.grund : 'nicht erfasst' };
  const zs = gl.zertifikate;
  let i = 0; while (i + 1 < zs.length && zs[i + 1].stellt_vorgaenger_aus === true) i++;
  const falsch = zs.map((z, k) => k > 0 && z.stellt_vorgaenger_aus !== true ? k + 1 : null).filter(Boolean);
  const letzter = zs[i];
  return { bekannt: true, verfahren: gl.verfahren || null, anzahl: zs.length,
    zertifikate: zs.map((z, k) => ({ nr: k + 1, inhaber: z.subject, aussteller: z.issuer, selbst_signiert: z.selbst_signiert === true, fingerabdruck_sha256: z.fingerprint256 || null })),
    reihenfolge_ordnungsgemaess: falsch.length === 0, nicht_anschliessend: falsch,
    blatt_selbst_signiert: zs[0].selbst_signiert === true, wurzel_mitgeliefert: zs.slice(1).some(z => z.selbst_signiert === true),
    aussteller_nicht_geliefert: letzter.selbst_signiert === true ? null : letzter.issuer, letzter_im_pfad: i + 1 };
}

// Strenges Lesen eines Zeitpunkts (ISO 8601, UTC): kein stilles Korrigieren (2026-02-30 wird nicht zum 2. März)
function zeitpunktLesen(s) {
  if (s == null || s === '') return { fehlt: true };
  const m = typeof s === 'string' && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?Z$/.exec(s);
  if (!m) return { ungueltig: true };
  const d = new Date(s), [, j, mo, t, h, mi, se] = m.map(Number);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() !== j || d.getUTCMonth() + 1 !== mo || d.getUTCDate() !== t || d.getUTCHours() !== h || d.getUTCMinutes() !== mi || d.getUTCSeconds() !== se) return { ungueltig: true };
  return { datum: d };
}

// Gültigkeit am Stichtag. Zustände: noch_nicht_gueltig · gueltig · bald_ablaufend (< 21 Tage) · abgelaufen · widerspruechlich ·
// nicht_pruefbar. notBefore und notAfter zählen beide noch zum Gültigkeitszeitraum (RFC 5280 Abschn. 4.1.2.5).
function gueltigkeit(z, tag) {
  const ab = zeitpunktLesen(z.gueltigAb), bis = zeitpunktLesen(z.gueltigBis);
  const np = grund => ({ zustand: 'nicht_pruefbar', stufe: 'np', text: `Nicht prüfbar: ${grund}.` });
  const lesbar = (w, wort) => w.fehlt ? `${wort} fehlt in den Rohdaten` : `${wort} ist kein gültiges Kalenderdatum`;
  if (!ab.datum && !bis.datum) return np(`${lesbar(ab, 'Gültigkeitsbeginn')}, ${lesbar(bis, 'Ablaufdatum')}`);
  if (!ab.datum) return np(lesbar(ab, 'Gültigkeitsbeginn'));
  if (!bis.datum) return np(lesbar(bis, 'Ablaufdatum'));
  const t = d => d.toISOString().slice(0, 10);
  if (ab.datum > bis.datum) return { zustand: 'widerspruechlich', stufe: 'abw', text: `Widersprüchlicher Zeitraum: Gültigkeitsbeginn ${t(ab.datum)} liegt nach dem Ablauf ${t(bis.datum)}; das Zertifikat ist zu keinem Zeitpunkt gültig.` };
  if (tag < ab.datum) return { zustand: 'noch_nicht_gueltig', stufe: 'abw', rest: Math.floor((bis.datum - tag) / 864e5), text: `Am Prüftag noch nicht gültig (gültig ab ${z.gueltigAb.slice(0, 16).replace('T', ' ')} UTC bis ${t(bis.datum)}).` };
  if (tag > bis.datum) return { zustand: 'abgelaufen', stufe: 'abw', rest: Math.floor((bis.datum - tag) / 864e5), text: `Am Prüftag abgelaufen (gültig bis ${z.gueltigBis.slice(0, 16).replace('T', ' ')} UTC).` };
  const rest = Math.floor((bis.datum - tag) / 864e5), lz = Math.round((bis.datum - ab.datum) / 864e5);
  const text = `Gültig vom ${t(ab.datum)} bis ${t(bis.datum)} (am Prüftag ${rest ? `noch ${rest} ${rest === 1 ? 'Tag' : 'Tage'}` : 'letzter Gültigkeitstag'}, Laufzeit ${lz} Tage).`;
  return rest < VORWARNUNG_TAGE ? { zustand: 'bald_ablaufend', stufe: 'frist', rest, text } : { zustand: 'gueltig', stufe: 'ok', rest, text };
}

function merkmale12({ roh, tr, add, npText }) {
  const m12 = roh.tls12_merkmale, B = 'Erweiterungen TLS 1.2';
  if (!m12) return;
  if (m12.status === 'nicht_pruefbar') return add(B, 'gesamter Bereich', 'np', npText(m12), '', 'merkmal:block');
  if (m12.status !== 'geprueft') return;
  const b = id => fs_((tr.bedingungen.find(x => x.id === id) || {}).fundstelle);
  const merk = (name, w, id, sk, okText, neinText, regel, umgekehrt = false) => {
    if (w.wert === 'nicht_pruefbar') return add(B, name, 'np', npText(w), b(id), sk);
    if (w.wert === 'nicht_anwendbar') return; // z. B. Encrypt-then-MAC ohne CBC-Suite: nichts zu bewerten
    const gut = umgekehrt ? w.wert === 'nein' : w.wert === 'ja';
    add(B, name, gut ? 'ok' : 'abw', gut ? okText : neinText, b(id), sk, gut ? {} : { regel });
  };
  merk('Extended Master Secret', m12.extended_master_secret, 'extended_master_secret', 'merkmal:ems', 'Wird ausgehandelt.', 'Server wählt die Erweiterung nicht, obwohl angeboten.', 'ems');
  merk('Sichere Renegotiation (RFC 5746)', m12.sichere_renegotiation, 'renegotiation', 'merkmal:reneg', 'Wird unterstützt. Ob der Server vom Client angestoßene Renegotiation ablehnt, prüft diese Version nicht.', 'Server bestätigt renegotiation_info nicht, obwohl angeboten.', 'renegotiation');
  merk('Kompression', m12.kompression, 'kompression', 'merkmal:kompression', 'Server wählt keine Kompression, obwohl angeboten.', 'Server wählt Kompression (DEFLATE).', 'kompression', true);
  merk('Encrypt-then-MAC bei CBC', m12.encrypt_then_mac_bei_cbc, 'encrypt_then_mac', 'merkmal:etm', 'Wird bei CBC-Suiten ausgehandelt.', 'Server wählt Encrypt-then-MAC bei CBC-Suiten nicht, obwohl angeboten.', 'tls12_suiten');
}

// Zertifikatssignatur → Eintrag in Tabelle 12. Ergebnis { stufe ('tabelle'|'abw'|'na'|'np'), eintrag?, text, fundstelle, regel? }
// Der TLS-Name des Verfahrens hängt am Schlüssel des Ausstellers (Kurve bzw. rsae/pss); ohne Aussteller keine Zuordnung.
function signaturZuordnen(z, kette, tr) {
  const t12 = tr.signaturen_tls13_cert, fund = 'Abschn. 3.4.3, Tab. 12';
  if (!z.signatur && !z.signatur_oid) return { stufe: 'np', text: 'Nicht prüfbar: Signaturverfahren fehlt in den Rohdaten.', fundstelle: fund };
  const name = z.signatur || `OID ${z.signatur_oid}`;
  const aussteller = z.subject && z.subject === z.issuer ? z : kette.slice(1).find(k => k.subject && k.subject === z.issuer);
  const hash = (z.signatur_hash || (/(SHA\d+)/i.exec(name) || [])[1] || '').toLowerCase();
  let ziel, zusatz = '';
  if (/^(sha\d+|md5)WithRSAEncryption$/i.test(name)) {
    ziel = `rsa_pkcs1_${hash}`;
    if (!t12.find(e => e.name === ziel)) return { stufe: 'abw', regel: 'zert_signatur', fundstelle: `${fund}; Tab. 8`,
      text: `${name}: RSA PKCS #1 v1.5 mit ${hash.toUpperCase()}. ${hash.toUpperCase()} steht in keiner Tabelle; rsa_pkcs1_* ist in Tabelle 12 nur bis 2025 empfohlen.` };
  } else if (name === 'RSASSA-PSS') {
    if (!aussteller || !aussteller.schluessel || !hash) return { stufe: 'np', fundstelle: fund, text: `${name}: Nicht prüfbar, Ausstellerschlüssel oder Hashverfahren fehlt; rsae oder pss nicht eindeutig.` };
    ziel = `rsa_pss_${aussteller.schluessel === 'rsa-pss' ? 'pss' : 'rsae'}_${hash}`;
  } else if (/^ecdsa-with-SHA\d+$/i.test(name)) {
    if (!aussteller || !aussteller.kurve) return { stufe: 'np', fundstelle: fund, text: `${name}: Nicht prüfbar, die Kurve des Ausstellerschlüssels steht nicht in der gelieferten Kette; Zuordnung zu Tabelle 12 nicht eindeutig.` };
    const kurve = KURVE_TLS13[aussteller.kurve];
    if (!kurve) return { stufe: 'np', fundstelle: fund, text: `${name}: Ausstellerkurve „${aussteller.kurve}“ nicht zuordenbar.` };
    ziel = `ecdsa_${kurve}_${hash}`; zusatz = ` mit Ausstellerschlüssel ${aussteller.kurve}`;
  } else if (/^(Ed25519|Ed448)$/i.test(name)) return { stufe: 'na', fundstelle: fund, text: `${name}: nicht in Tabelle 12.` };
  else return { stufe: 'np', fundstelle: fund, text: `${name}: Nicht prüfbar, Verfahren nicht eindeutig einem Tabelleneintrag zuordenbar.` };
  const e = t12.find(x => x.name === ziel);
  if (!e) return { stufe: 'na', fundstelle: fund, text: `${name}${zusatz} entspricht ${ziel}; nicht in Tabelle 12.` };
  return { stufe: 'tabelle', eintrag: e, fundstelle: fs_(e.fundstelle), regel: 'zert_signatur',
    text: `${name}${zusatz} entspricht ${ziel}; empfohlen ${bisText(e)}.` };
}

module.exports = { bewerten, signaturZuordnen, gueltigkeit, zeitpunktLesen, ketteAuswerten, vertrauen, STUFEN, VORWARNUNG_TAGE, VORWARNSCHWELLEN };
