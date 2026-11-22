// SPDX-License-Identifier: Apache-2.0
// TLS-1.2-Merkmale über einen eigenen ClientHello (RFC 5246, Abschn. 7.4.1.2), der die Merkmale ausdrücklich anbietet:
// Kompression DEFLATE (RFC 3749), Extended Master Secret (RFC 7627), Encrypt-then-MAC (RFC 7366) und
// renegotiation_info (RFC 5746). Ausgewertet werden der ServerHello und die folgende Certificate-Nachricht (bei TLS 1.2
// unverschlüsselt: gelieferte Kette in Lieferreihenfolge); danach wird die Verbindung geschlossen.
// So belegt die Antwort, was der Server wählt, obwohl das Merkmal angeboten war.
'use strict';
const net = require('net');
const crypto = require('crypto');

const u16 = n => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const u24 = n => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const mitLaenge16 = b => Buffer.concat([u16(b.length), b]);
const erw = (typ, daten = Buffer.alloc(0)) => Buffer.concat([u16(typ), mitLaenge16(daten)]);
const ERW = { server_name: 0x0000, supported_groups: 0x000a, ec_point_formats: 0x000b, signature_algorithms: 0x000d,
  encrypt_then_mac: 0x0016, extended_master_secret: 0x0017, renegotiation_info: 0xff01 };
const GRUPPEN = [0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x001a, 0x001b, 0x001c, 0x0100, 0x0101, 0x0102];
const SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c,
  0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0402, 0x0502, 0x0602];

function clientHello({ suiten, sni, kompression = true }) {
  const codes = Buffer.concat(suiten.map(c => u16(c)));
  const ext = [];
  if (sni) { const n = Buffer.from(sni, 'ascii'); ext.push(erw(ERW.server_name, mitLaenge16(Buffer.concat([Buffer.from([0]), mitLaenge16(n)])))); }
  ext.push(erw(ERW.supported_groups, mitLaenge16(Buffer.concat(GRUPPEN.map(u16)))));
  ext.push(erw(ERW.ec_point_formats, Buffer.from([1, 0])));
  ext.push(erw(ERW.signature_algorithms, mitLaenge16(Buffer.concat(SIGALGS.map(u16)))));
  ext.push(erw(ERW.encrypt_then_mac), erw(ERW.extended_master_secret), erw(ERW.renegotiation_info, Buffer.from([0])));
  const komp = kompression ? Buffer.from([2, 1, 0]) : Buffer.from([1, 0]);
  const body = Buffer.concat([u16(0x0303), crypto.randomBytes(32), Buffer.from([0]), mitLaenge16(codes), komp, mitLaenge16(Buffer.concat(ext))]);
  const hs = Buffer.concat([Buffer.from([1]), u24(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), mitLaenge16(hs)]);
}

const ALARME = { 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 47: 'illegal_parameter', 50: 'decode_error',
  70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback', 112: 'unrecognized_name' };

// Handshake-Nachrichten (Typ, Inhalt) aus dem zusammengesetzten Handshake-Strom, nur vollständige
function nachrichten(hs) {
  const out = []; let q = 0;
  while (q + 4 <= hs.length) { const l = (hs[q + 1] << 16) | (hs[q + 2] << 8) | hs[q + 3]; if (q + 4 + l > hs.length) break; out.push({ typ: hs[q], inhalt: hs.subarray(q + 4, q + 4 + l) }); q += 4 + l; }
  return out;
}
// Certificate-Nachricht (RFC 5246, Abschn. 7.4.2): Liste der DER-Zertifikate in Lieferreihenfolge
function zertifikateLesen(b) {
  const gesamt = (b[0] << 16) | (b[1] << 8) | b[2], liste = []; let p = 3;
  if (3 + gesamt > b.length) throw new Error('Certificate-Nachricht zu kurz');
  while (p < 3 + gesamt) { const l = (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]; if (p + 3 + l > 3 + gesamt) throw new Error('Zertifikatslänge über Nachrichtenende'); liste.push(Buffer.from(b.subarray(p + 3, p + 3 + l))); p += 3 + l; }
  return liste;
}

// Zerlegt die Antwort; liefert { fertig, serverHello, zertifikate? } oder { fertig, alarm } oder { fertig:false, serverHello? }.
// Bei TLS 1.2 folgt dem ServerHello die Certificate-Nachricht im Klartext: Sie wird mitgelesen (gelieferte Kette, Reihenfolge
// wie vom Server gesendet). zertifikate: Liste der DER-Zertifikate · null (keine Certificate-Nachricht) · fehlt (nicht gelesen).
function auswerten(puffer) {
  let p = 0; let hs = Buffer.alloc(0); let sh = null;
  while (p + 5 <= puffer.length) {
    const typ = puffer[p], len = puffer.readUInt16BE(p + 3);
    if (p + 5 + len > puffer.length) break;
    const frag = puffer.subarray(p + 5, p + 5 + len); p += 5 + len;
    if (typ === 0x15 && frag.length >= 2) return sh ? { fertig: true, serverHello: sh, zertifikate: null } : { fertig: true, alarm: { stufe: frag[0], code: frag[1], name: ALARME[frag[1]] || String(frag[1]) } };
    if (typ !== 0x16) return sh ? { fertig: true, serverHello: sh } : { fertig: true, fehler: `unerwarteter Datensatztyp ${typ}` };
    hs = Buffer.concat([hs, frag]);
    if (hs.length >= 1 && hs[0] !== 2) return { fertig: true, fehler: `erste Handshake-Nachricht ist kein ServerHello (Typ ${hs[0]})` };
    const n = nachrichten(hs);
    if (!n.length) continue;
    sh = serverHelloLesen(n[0].inhalt);
    if (sh.version !== 0x0303) return { fertig: true, serverHello: sh };
    if (n.length >= 2) return { fertig: true, serverHello: sh, zertifikate: n[1].typ === 11 ? zertifikateLesen(n[1].inhalt) : null };
  }
  return { fertig: false, serverHello: sh };
}

function serverHelloLesen(b) {
  let p = 0; const version = b.readUInt16BE(p); p += 2 + 32;
  const sidLen = b[p]; p += 1 + sidLen;
  const suite = b.readUInt16BE(p); p += 2;
  const kompression = b[p]; p += 1;
  const erweiterungen = [];
  if (p + 2 <= b.length) { const ende = p + 2 + b.readUInt16BE(p); p += 2;
    while (p + 4 <= ende) { const t = b.readUInt16BE(p), l = b.readUInt16BE(p + 2); erweiterungen.push(t); p += 4 + l; } }
  return { version, suite, kompression, erweiterungen };
}

// Ein Versuch: { ok, serverHello } | { ok:false, fehler } – fehler wie bei fehler.einordnen (code/zeitueberschreitung/alarm)
function versuch({ adresse, port, sni, suiten, zeitlimitMs = 6000, kompression = true }) {
  return new Promise(res => {
    let puffer = Buffer.alloc(0), erledigt = false, sh = null;
    const ende = r => { if (erledigt) return; erledigt = true; s.destroy(); res(r); };
    // Endet die Verbindung nach dem ServerHello, aber vor der Certificate-Nachricht, zählt der ServerHello (Kette unbekannt)
    const nurSh = () => ({ ok: true, serverHello: sh, zertifikatGrund: 'Certificate-Nachricht nicht vollständig empfangen' });
    const s = net.connect({ host: adresse, port }, () => s.write(clientHello({ suiten, sni, kompression })));
    s.setTimeout(zeitlimitMs, () => ende(sh ? nurSh() : { ok: false, fehler: { zeitueberschreitung: zeitlimitMs } }));
    s.on('data', d => {
      puffer = Buffer.concat([puffer, d]);
      let r; try { r = auswerten(puffer); } catch (e) { return ende(sh ? { ...nurSh(), zertifikatGrund: `Certificate-Nachricht unlesbar (${e.message})` } : { ok: false, fehler: { code: 'ANTWORT_UNLESBAR', message: e.message } }); }
      if (r.serverHello) sh = r.serverHello;
      if (!r.fertig) { if (sh && puffer.length > 1 << 18) ende(nurSh()); return; }
      if (r.serverHello) return ende({ ok: true, serverHello: r.serverHello, ...(r.zertifikate !== undefined ? { zertifikate: r.zertifikate } : {}) });
      if (r.alarm) {
        const name = r.alarm.name.toUpperCase();
        return ende({ ok: false, fehler: { code: `ERR_SSL_TLSV1_ALERT_${name}`, message: `TLS-Alarm ${r.alarm.name}` } });
      }
      ende({ ok: false, fehler: { code: 'ANTWORT_UNERWARTET', message: r.fehler } });
    });
    s.on('error', e => ende(sh ? nurSh() : { ok: false, fehler: e }));
    s.on('close', () => ende(sh ? nurSh() : { ok: false, fehler: { code: 'ECONNRESET', message: 'Verbindung vor dem ServerHello beendet' } }));
  });
}

module.exports = { versuch, clientHello, auswerten, ERW };
