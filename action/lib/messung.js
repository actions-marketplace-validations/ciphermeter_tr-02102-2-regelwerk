// SPDX-License-Identifier: Apache-2.0
// Messung der TLS-Konfiguration eines Ziels, nur über normale Handshakes (keine Angriffstests).
// Sperrliste (Opt-out der Hostbetreiber, lib/schutz.js) wird vor der Namensauflösung und vor jedem Handshake geprüft;
// ein gesperrtes Ziel wird nicht kontaktiert (Fehler mit code 'GESPERRT').
// Grenzen: ein Ziel je Lauf, höchstens 4 Handshakes pro Sekunde (Pause 250 ms), Zeitlimit 6 s je Versuch,
// ein Wiederholungsversuch bei Netzfehlern, Abbruch nach 4 aufeinanderfolgenden Netzfehlern.
// Jedes Ergebnis: angeboten | abgelehnt | nicht_pruefbar, mit Grund und Messverfahren (siehe rohdaten.js).
'use strict';
const tls = require('tls');
const dns = require('dns');
const net = require('net');
const { execFile } = require('child_process');
const { einordnen, istNetzartig } = require('./fehler');
const { kette, geliefert, pruefsystem } = require('./zertifikat');
const hallo = require('./hallo');
const { FORMAT, VERSIONEN, messstatus } = require('./rohdaten');
const schutz = require('./schutz');

const PRUEFKERN = '0.4.0';
const KANDIDATEN = {
  tls13_suiten: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_CCM_SHA256', 'TLS_AES_128_CCM_8_SHA256'],
  gruppen_tls13: ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448', 'brainpoolP256r1tls13', 'brainpoolP384r1tls13', 'brainpoolP512r1tls13',
    'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'ffdhe6144', 'ffdhe8192', 'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'MLKEM768', 'MLKEM1024'],
  gruppen_tls12: ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'],
  signaturen_tls13: ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_brainpoolP256r1tls13_sha256',
    'ecdsa_brainpoolP384r1tls13_sha384', 'ecdsa_brainpoolP512r1tls13_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512',
    'rsa_pss_pss_sha256', 'rsa_pss_pss_sha384', 'rsa_pss_pss_sha512', 'ed25519', 'ed448', 'mldsa44', 'mldsa65', 'mldsa87']
};
// Suiten, die ohne Zugangsdaten nicht sinnvoll messbar sind (PSK, SRP) – Grenze des Prüfumfangs
const OHNE_ZUGANGSDATEN = /PSK|SRP/;

const schlaf = ms => new Promise(r => setTimeout(r, ms));
const normGruppe = n => String(n || '').toLowerCase().replace('prime256v1', 'secp256r1');

function befehl(prog, args, zeitlimitMs) {
  return new Promise(res => execFile(prog, args, { timeout: zeitlimitMs, windowsHide: true, maxBuffer: 1 << 22 }, (e, out, err) =>
    res(e ? { ok: false, fehler: e.killed ? { zeitueberschreitung: zeitlimitMs } : e, text: String(out || '') + String(err || '') } : { ok: true, text: String(out) })));
}

async function opensslSuiten(prog, zeitlimitMs) {
  const r = await befehl(prog, ['ciphers', '-V', '-stdname', '-tls1_2', 'ALL:COMPLEMENTOFALL:@SECLEVEL=0'], zeitlimitMs);
  if (!r.ok) return { ok: false, fehler: r.fehler };
  const liste = r.text.split('\n').map(z => z.trim().match(/^(0x\S+,0x\S+)\s+-\s+(\S+)\s+-\s+(\S+)\s+(\S+)/)).filter(Boolean)
    .map(m => ({ iana_code: m[1], name: m[2], openssl: m[3], version: m[4] })).filter(s => s.version !== 'TLSv1.3');
  return liste.length ? { ok: true, liste } : { ok: false, fehler: { lokal: 'openssl ciphers lieferte keine Liste' } };
}

async function messen(opt) {
  const { host, port = 443, zeitlimitMs = 6000, pauseMs = 250, opensslBefehl = 'openssl', uhr = () => new Date() } = opt;
  const kand = { ...KANDIDATEN, ...(opt.kandidaten || {}) };
  if (typeof host !== 'string' || !/^[A-Za-z0-9.:-]{1,253}$/.test(host)) throw new Error('host fehlt oder ist ungültig');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port ist ungültig');
  const istIp = net.isIP(host) !== 0;
  const sni = opt.sni || (istIp || host === 'localhost' ? undefined : host);
  const lookup = opt.lookup || dns.lookup;
  const sperrliste = opt.sperrliste || schutz.sperrlisteLaden(opt.sperrlistePfad);
  const sperre = (...namen) => { const e = schutz.gesperrt(sperrliste, ...namen); if (e) { const f = new Error(`Ziel steht auf der Sperrliste (Eintrag ${e}); keine Verbindung aufgebaut`); f.code = 'GESPERRT'; throw f; } };
  sperre(host, sni);

  const roh = { format: FORMAT, ziel: { host, port, sni: sni || null, adresse: null }, zeitpunkt: uhr().toISOString(),
    werkzeug: { pruefkern: PRUEFKERN, node: process.version, openssl_node: process.versions.openssl, openssl_cli: null },
    verfahren: { zeitlimit_ms: zeitlimitMs, pause_ms: pauseMs, wiederholung_bei_netzfehler: 1, abbruch_nach_netzfehlern: 4,
      beschreibung: 'Node.js tls.connect (OpenSSL der Laufzeit), je Merkmal ein Handshake mit genau einem angebotenen Wert; TLS-1.2-Merkmale über eigenen ClientHello' } };
  let handshakes = 0, erfolgreich = 0, netzFolge = 0, abbruch = null;
  const v = await befehl(opensslBefehl, ['version'], 10000);
  roh.werkzeug.openssl_cli = v.ok ? v.text.trim() : null;

  // 1. Namensauflösung (einmal; alle Verbindungen gehen an dieselbe Adresse)
  if (istIp) roh.ziel.adresse = host;
  else {
    const a = await new Promise(res => lookup(host, { all: false }, (e, adr) => res(e ? { e } : { adr })));
    if (a.e) abbruch = einordnen(a.e).grund;
    else roh.ziel.adresse = a.adr;
  }
  if (roh.ziel.adresse) sperre(roh.ziel.adresse);

  // Ein Versuch mit genau einem angebotenen Wert; ein Wiederholungsversuch bei Netzfehlern
  function einmal(tlsOpt, mitZert) {
    return new Promise(res => {
      try { sperre(host, sni, roh.ziel.adresse); } catch (e) { return res({ ok: false, gesperrt: e }); }
      try { tls.createSecureContext(tlsOpt); } catch (e) { return res({ ok: false, e: einordnen({ code: e.code, lokal: `das Prüfsystem (OpenSSL ${process.versions.openssl}) kann dieses Angebot nicht senden` }) }); }
      handshakes++;
      let fertig = false; const ende = r => { if (!fertig) { fertig = true; res(r); } };
      let s;
      try {
        s = tls.connect({ host: roh.ziel.adresse, port, servername: sni, rejectUnauthorized: false, ...tlsOpt }, () => {
          const r = { ok: true, protokoll: s.getProtocol(), suite: s.getCipher(), gruppe: s.getEphemeralKeyInfo() || null };
          if (mitZert) { try { r.kette = kette(s.getPeerCertificate(true)); } catch (e) { r.ketteFehler = e.message; } r.autorisiert = s.authorized; r.autorisierungsfehler = s.authorizationError || null; }
          erfolgreich++; s.end(); ende(r);
        });
      } catch (e) { return ende({ ok: false, e: einordnen({ code: e.code, message: e.message, lokal: e.message }) }); }
      s.setTimeout(zeitlimitMs, () => { s.destroy(); ende({ ok: false, e: einordnen({ zeitueberschreitung: zeitlimitMs }) }); });
      s.on('error', e => ende({ ok: false, e: einordnen(e) }));
    });
  }
  async function versuch(tlsOpt, mitZert = false) {
    if (abbruch) return { ok: false, e: { status: 'nicht_pruefbar', art: 'abbruch', grund: `nicht durchgeführt: ${abbruch}` } };
    let r = await einmal(tlsOpt, mitZert); if (r.gesperrt) throw r.gesperrt; await schlaf(pauseMs);
    if (!r.ok && istNetzartig(r.e)) { r = await einmal(tlsOpt, mitZert); await schlaf(pauseMs); }
    if (!r.ok && istNetzartig(r.e)) { if (++netzFolge >= 4) abbruch = `Abbruch nach wiederholten Netzfehlern (zuletzt: ${r.e.grund})`; }
    else netzFolge = 0;
    return r;
  }
  const ergebnis = (r, verfahren, extra = {}) => r.ok ? { status: 'angeboten', verfahren, ...extra }
    : { status: r.e.status, grund: r.e.grund, ...(r.e.status === 'nicht_pruefbar' ? { art: r.e.art } : {}), verfahren };

  // 2. Standard-Handshake mit Zertifikat (zugleich Erreichbarkeit). Vertrauen nur aus der Kettenprüfung von OpenSSL:
  //    checkServerIdentity bleibt hier leer, der Namensabgleich geschieht getrennt in der Bewertung (lib/zertifikat.js).
  //    opt.ca: ausdrücklich konfigurierte Zertifizierungsstelle statt des Vertrauensspeichers (nur Tests)
  const z = await versuch({ checkServerIdentity: () => undefined, ...(opt.ca ? { ca: opt.ca } : {}) }, true);
  roh.standard_handshake = z.ok ? { status: 'ok', protokoll: z.protokoll, suite: z.suite, gruppe: z.gruppe } : { status: 'nicht_pruefbar', grund: z.e.grund };
  if (z.ok && z.kette && z.kette.length) roh.zertifikat = { status: 'ok', kette: z.kette, vertrauenswuerdig: !!z.autorisiert, fehler: z.autorisierungsfehler,
    verfahren: 'Standard-Handshake; Kette wie vom Prüfsystem gebildet (kann eine Wurzel aus dem Vertrauensspeicher enthalten); Vertrauen nur aus der Kettenprüfung, Namensabgleich getrennt',
    pruefsystem: pruefsystem(opt.ca) };
  else roh.zertifikat = { status: 'nicht_pruefbar', kette: [], grund: z.ok ? (z.ketteFehler || 'Server lieferte keine Zertifikatskette') : z.e.grund };
  roh.zertifikat.geliefert = { status: 'nicht_pruefbar', grund: 'nicht gemessen' }; // wird in Schritt 9 ersetzt
  if (!z.ok && istNetzartig(z.e) && !abbruch) abbruch = `Ziel nicht erreichbar (${z.e.grund})`;

  // 3. Protokollversionen
  roh.versionen = {};
  for (const ver of VERSIONEN) {
    const r = await versuch({ minVersion: ver, maxVersion: ver, ciphers: 'ALL:@SECLEVEL=0' });
    roh.versionen[ver] = ergebnis(r, `Handshake nur mit ${ver}`);
  }
  const vs = ver => roh.versionen[ver].status;
  const nichtAnwendbar = ver => vs(ver) === 'abgelehnt' ? { status: 'nicht_anwendbar', grund: `${ver} wird nicht angeboten`, eintraege: [] }
    : { status: 'nicht_pruefbar', grund: `${ver} nicht prüfbar (${roh.versionen[ver].grund})`, eintraege: [] };
  const v12 = { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }, v13 = { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' };

  // 4. Cipher-Suiten TLS 1.2 (Kandidaten aus der OpenSSL-Liste; PSK/SRP außerhalb des Prüfumfangs)
  if (vs('TLSv1.2') !== 'angeboten') roh.tls12_suiten = nichtAnwendbar('TLSv1.2');
  else {
    const l = opt.suitenListe ? { ok: true, liste: opt.suitenListe } : await opensslSuiten(opensslBefehl, 10000);
    if (!l.ok) roh.tls12_suiten = { status: 'nicht_pruefbar', grund: `Kandidatenliste nicht verfügbar: ${einordnen({ ...l.fehler, lokal: l.fehler.lokal || l.fehler.message || 'openssl ciphers' }).grund}`, eintraege: [] };
    else {
      roh.tls12_suiten = { status: 'geprueft', ausserhalb_pruefumfang: l.liste.filter(s => OHNE_ZUGANGSDATEN.test(s.name)).map(s => s.name), eintraege: [] };
      for (const s of l.liste.filter(s => !OHNE_ZUGANGSDATEN.test(s.name))) {
        const r = await versuch({ ...v12, ciphers: s.openssl + ':@SECLEVEL=0' });
        roh.tls12_suiten.eintraege.push({ name: s.name, iana_code: s.iana_code, openssl: s.openssl,
          ...ergebnis(r, `TLS 1.2, nur Suite ${s.openssl}`, r.ok ? { schluesselaustausch: r.gruppe } : {}) });
      }
    }
  }

  // 5. Cipher-Suiten TLS 1.3
  if (vs('TLSv1.3') !== 'angeboten') roh.tls13_suiten = nichtAnwendbar('TLSv1.3');
  else {
    roh.tls13_suiten = { status: 'geprueft', eintraege: [] };
    for (const s of kand.tls13_suiten) roh.tls13_suiten.eintraege.push({ name: s, ...ergebnis(await versuch({ ...v13, ciphers: s + ':ALL:@SECLEVEL=0' }), `TLS 1.3, nur Suite ${s}`) });
  }

  // 6. Gruppen TLS 1.3: genau eine Gruppe in supported_groups und key_share
  if (vs('TLSv1.3') !== 'angeboten') roh.gruppen_tls13 = nichtAnwendbar('TLSv1.3');
  else {
    roh.gruppen_tls13 = { status: 'geprueft', eintraege: [] };
    for (const g of kand.gruppen_tls13) roh.gruppen_tls13.eintraege.push({ name: g, ...ergebnis(await versuch({ ...v13, ecdhCurve: g }), `TLS 1.3, nur Gruppe ${g}`) });
  }

  // 7. Gruppen TLS 1.2 (ECDHE). Bei ECDSA-Zertifikat verlangt TLS 1.2 die Zertifikatskurve in supported_groups:
  //    erst die Gruppe allein, nach Ablehnung zusätzlich die Zertifikatskurve; nur die ausgehandelte Gruppe zählt.
  if (vs('TLSv1.2') !== 'angeboten') roh.gruppen_tls12 = nichtAnwendbar('TLSv1.2');
  else {
    roh.gruppen_tls12 = { status: 'geprueft', eintraege: [] };
    const blatt = roh.zertifikat.kette[0];
    const zertKurve = blatt && blatt.schluessel === 'ec' ? normGruppe(blatt.kurve) : null;
    for (const g of kand.gruppen_tls12) {
      const opt12 = { ...v12, ciphers: 'ECDHE:@SECLEVEL=0' };
      let r = await versuch({ ...opt12, ecdhCurve: g }); let verfahren = `TLS 1.2 ECDHE, nur Gruppe ${g}`;
      if (!r.ok && r.e.status === 'abgelehnt' && zertKurve && zertKurve !== normGruppe(g)) {
        const rueck = { secp256r1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' }[zertKurve];
        if (rueck) { r = await versuch({ ...opt12, ecdhCurve: `${g}:${rueck}` }); verfahren += ` und ergänzend ${g} + Zertifikatskurve ${zertKurve}`; }
      }
      let e;
      if (r.ok) e = normGruppe(r.gruppe && r.gruppe.name) === normGruppe(g) ? { status: 'angeboten', verfahren }
        : { status: 'nicht_pruefbar', art: 'methode', verfahren, grund: `Server wählte ${r.gruppe ? r.gruppe.name : 'keine ECDHE-Gruppe'}, obwohl ${g} zuerst angeboten war. Mit diesem Zertifikat müssen TLS-1.2-Clients die Zertifikatskurve mitanbieten; ob ${g} unterstützt wird, lässt sich so nicht entscheiden` };
      else e = { status: r.e.status, grund: r.e.grund, ...(r.e.status === 'nicht_pruefbar' ? { art: r.e.art } : {}), verfahren };
      roh.gruppen_tls12.eintraege.push({ name: g, ...e });
    }
  }

  // 8. Signaturverfahren TLS 1.3
  if (vs('TLSv1.3') !== 'angeboten') roh.signaturen_tls13 = nichtAnwendbar('TLSv1.3');
  else {
    roh.signaturen_tls13 = { status: 'geprueft', eintraege: [] };
    for (const a of kand.signaturen_tls13) roh.signaturen_tls13.eintraege.push({ name: a, ...ergebnis(await versuch({ ...v13, sigalgs: a }), `TLS 1.3, nur signature_algorithms ${a}`) });
  }

  // 9. TLS-1.2-Merkmale über eigenen ClientHello mit den angebotenen Suiten; derselbe Handshake liefert die vom Server
  //    gesendete Zertifikatskette (Certificate-Nachricht, bei TLS 1.2 unverschlüsselt) – kein zusätzlicher Verbindungsaufbau
  const geliefertAus = r => {
    const np = grund => ({ status: 'nicht_pruefbar', grund });
    if (!r.ok) return np(r.e.grund);
    if (!r.zertifikate) return np(r.zertifikatGrund || (r.zertifikate === null ? 'Server sandte keine Certificate-Nachricht' : 'Certificate-Nachricht nicht gelesen'));
    let g; try { g = geliefert(r.zertifikate); } catch (e) { return np(`gelieferte Zertifikate unlesbar (${e.message})`); }
    const blatt = roh.zertifikat.kette[0];
    if (!g.length) return np('Certificate-Nachricht ohne Zertifikat');
    if (!blatt || g[0].fingerprint256 !== blatt.fingerprint256) return np('Über TLS 1.2 lieferte der Server ein anderes Serverzertifikat als im Standard-Handshake (z. B. getrennte RSA- und ECDSA-Zertifikate); gelieferte Kette nicht zuordenbar');
    return { status: 'geprueft', verfahren: 'eigener TLS-1.2-ClientHello; Certificate-Nachricht des Servers, Reihenfolge wie gesendet', zertifikate: g };
  };
  if (vs('TLSv1.2') !== 'angeboten') roh.zertifikat.geliefert = vs('TLSv1.2') === 'abgelehnt' ? { status: 'nicht_pruefbar', art: 'methode',
    grund: 'Server bietet TLS 1.2 nicht an; bei TLS 1.3 ist die Zertifikatsnachricht verschlüsselt und wird von diesem Prüfsystem nicht ausgelesen' }
    : { status: 'nicht_pruefbar', grund: `TLS 1.2 nicht prüfbar (${roh.versionen['TLSv1.2'].grund})` };
  if (vs('TLSv1.2') !== 'angeboten') roh.tls12_merkmale = vs('TLSv1.2') === 'abgelehnt' ? { status: 'nicht_anwendbar', grund: 'TLS 1.2 wird nicht angeboten' }
    : { status: 'nicht_pruefbar', grund: `TLS 1.2 nicht prüfbar (${roh.versionen['TLSv1.2'].grund})` };
  else {
    const angeboten = roh.tls12_suiten.eintraege.filter(s => s.status === 'angeboten' && /^0x/.test(s.iana_code || ''));
    const codes = l => l.map(s => parseInt(s.iana_code.replace(/0x|,/g, ''), 16));
    const np = grund => ({ wert: 'nicht_pruefbar', grund });
    const hello = async suiten => {
      if (abbruch) return { ok: false, e: { status: 'nicht_pruefbar', grund: `nicht durchgeführt: ${abbruch}` } };
      sperre(host, sni, roh.ziel.adresse);
      handshakes++;
      const r = await hallo.versuch({ adresse: roh.ziel.adresse, port, sni, suiten, zeitlimitMs }); await schlaf(pauseMs);
      if (r.ok) { erfolgreich++; return r; }
      return { ok: false, e: einordnen(r.fehler) };
    };
    const verf = 'eigener TLS-1.2-ClientHello, bietet DEFLATE-Kompression, extended_master_secret, encrypt_then_mac und renegotiation_info an; ausgewertet: ServerHello';
    if (!angeboten.length) { roh.tls12_merkmale = { status: 'nicht_pruefbar', grund: 'keine angebotene TLS-1.2-Suite bekannt' }; roh.zertifikat.geliefert = { status: 'nicht_pruefbar', grund: 'keine angebotene TLS-1.2-Suite bekannt' }; }
    else {
      const r = await hello(codes(angeboten));
      roh.zertifikat.geliefert = geliefertAus(r);
      const m = { status: 'geprueft' };
      if (r.ok && r.serverHello.version === 0x0303) {
        const sh = r.serverHello, hat = t => sh.erweiterungen.includes(t);
        m.extended_master_secret = { wert: hat(hallo.ERW.extended_master_secret) ? 'ja' : 'nein', verfahren: verf };
        m.sichere_renegotiation = { wert: hat(hallo.ERW.renegotiation_info) ? 'ja' : 'nein', verfahren: verf };
        m.kompression = sh.kompression === 0 ? { wert: 'nein', verfahren: verf } : sh.kompression === 1 ? { wert: 'ja', verfahren: verf }
          : np(`unbekannte Kompressionsmethode ${sh.kompression}`);
      } else {
        const grund = r.ok ? `ServerHello mit unerwarteter Version 0x${r.serverHello.version.toString(16)}` : r.e.grund;
        m.extended_master_secret = np(grund); m.sichere_renegotiation = np(grund); m.kompression = np(grund);
      }
      const cbc = angeboten.filter(s => /_CBC_/.test(s.name));
      if (!cbc.length) m.encrypt_then_mac_bei_cbc = { wert: 'nicht_anwendbar', grund: 'keine CBC-Suite angeboten' };
      else {
        const r2 = await hello(codes(cbc));
        if (r2.ok && r2.serverHello.version === 0x0303 && codes(cbc).includes(r2.serverHello.suite))
          m.encrypt_then_mac_bei_cbc = { wert: r2.serverHello.erweiterungen.includes(hallo.ERW.encrypt_then_mac) ? 'ja' : 'nein', verfahren: verf + ' (nur CBC-Suiten)' };
        else m.encrypt_then_mac_bei_cbc = np(r2.ok ? 'Server wählte keine der angebotenen CBC-Suiten' : r2.e.grund);
      }
      roh.tls12_merkmale = m;
    }
  }

  roh.handshakes = handshakes;
  roh.erfolgreiche_handshakes = erfolgreich;
  if (abbruch) roh.abbruch = abbruch;
  const ms = messstatus(roh);
  roh.messstatus = ms.status;
  roh.nicht_pruefbar = ms.gruende.length;
  return roh;
}

module.exports = { messen, KANDIDATEN, PRUEFKERN };
