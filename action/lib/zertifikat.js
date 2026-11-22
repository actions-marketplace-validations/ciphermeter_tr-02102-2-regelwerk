// SPDX-License-Identifier: Apache-2.0
// Liest die Zertifikatskette aus einem TLS-Handshake. Das Signaturverfahren wird direkt aus dem DER-Zertifikat gelesen
// (Feld signatureAlgorithm, RFC 5280 Abschn. 4.1.1.2), weil nicht jede Node-Version es über X509Certificate anbietet.
'use strict';
const crypto = require('crypto');

const SIGNATUR_OID = {
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44', '2.16.840.1.101.3.4.3.18': 'ML-DSA-65', '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
  '1.2.840.10040.4.3': 'dsa-with-SHA1', '2.16.840.1.101.3.4.3.2': 'dsa-with-SHA256'
};
const HASH_OID = { '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.4': 'sha224', '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };

function tlv(buf, off) {
  if (off + 2 > buf.length) throw new Error('DER zu kurz');
  const tag = buf[off]; let len = buf[off + 1]; let p = off + 2;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 4) throw new Error('DER-Länge ungültig'); len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[p + i]; p += n; }
  if (p + len > buf.length) throw new Error('DER-Länge über Pufferende');
  return { tag, start: p, end: p + len };
}
function kinder(buf, t) { const out = []; let p = t.start; while (p < t.end) { const k = tlv(buf, p); out.push(k); p = k.end; } return out; }
function oid(buf, t) {
  const b = buf.subarray(t.start, t.end); const teile = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { teile.push(v); v = 0; } }
  return teile.join('.');
}

// Liefert { signatur, signatur_oid, signatur_hash } oder wirft bei kaputtem DER
function signaturverfahren(der) {
  const zert = tlv(der, 0); const [, algId] = kinder(der, zert);
  if (!algId || algId.tag !== 0x30) throw new Error('signatureAlgorithm fehlt');
  const [o, param] = kinder(der, algId);
  const id = oid(der, o);
  const r = { signatur: SIGNATUR_OID[id] || null, signatur_oid: id, signatur_hash: null };
  const m = /with-?(SHA\d+|sha\d+|MD5|md5)/i.exec(r.signatur || '') || /^(sha\d+|md5)With/i.exec(r.signatur || '');
  if (m) r.signatur_hash = m[1].toLowerCase();
  if (id === '1.2.840.113549.1.1.10') { // RSASSA-PSS-params: [0] hashAlgorithm, Standard SHA-1 (RFC 4055)
    r.signatur_hash = 'sha1';
    if (param && param.tag === 0x30) for (const k of kinder(der, param)) if (k.tag === 0xa0) {
      const alg = tlv(der, k.start); const [ho] = kinder(der, alg); r.signatur_hash = HASH_OID[oid(der, ho)] || oid(der, ho);
    }
  }
  return r;
}

// Subject Alternative Name im Textformat von Node.js („DNS:a, DNS:b, IP Address:1.2.3.4“; Sonderzeichen in Anführungszeichen)
// → { dns, ip }. null bei fehlender Erweiterung; Einträge, die sich nicht eindeutig lesen lassen, machen das Ergebnis ungültig.
function sanLesen(text) {
  if (text == null) return null;
  const dns = [], ip = [];
  const re = /([A-Za-z][A-Za-z ]*):("(?:[^"\\]|\\.)*"|[^,]*)(?:, |$)/gy;
  let m, rest = String(text);
  while (rest.length && (m = re.exec(rest))) {
    let w = m[2]; if (w.startsWith('"')) { try { w = JSON.parse(w); } catch { return { ungueltig: true }; } }
    if (m[1] === 'DNS') dns.push(w); else if (m[1] === 'IP Address') ip.push(w);
    if (re.lastIndex >= rest.length) break;
  }
  if (re.lastIndex < rest.length && re.lastIndex !== 0) return { ungueltig: true };
  return { dns, ip };
}
// Common Name aus dem Subject (Zeilen „CN=…“ von Node.js, Kommas im Wert als „\,“); mehrdeutig → null
function cnLesen(subject, trenner = /\n/) {
  if (typeof subject !== 'string') return null;
  const cn = subject.split(trenner).map(s => s.trim()).filter(s => s.startsWith('CN=')).map(s => s.slice(3).replace(/\\(.)/g, '$1'));
  return cn.length === 1 ? cn[0] : null;
}

// Selbst signiert: Aussteller = Inhaber und Signatur mit dem eigenen Schlüssel prüfbar
function selbstSigniert(x) { try { return x.checkIssued(x) && x.verify(x.publicKey); } catch { return false; } }

function eintrag(raw, jetzt) {
  const x = new crypto.X509Certificate(raw);
  const d = (x.publicKey && x.publicKey.asymmetricKeyDetails) || {};
  let sig;
  try { sig = signaturverfahren(raw); } catch (e) { sig = { signatur: null, signatur_oid: null, signatur_hash: null, signatur_fehler: e.message }; }
  // Unlesbare Zeitangaben bleiben leer (null) statt NaN oder Ausnahme; die Bewertung meldet sie als „nicht prüfbar“
  const zeit = t => t instanceof Date && !Number.isNaN(t.getTime()) ? t : null;
  const ab = zeit(x.validFromDate || new Date(x.validFrom)), bis = zeit(x.validToDate || new Date(x.validTo));
  const san = sanLesen(x.subjectAltName);
  return { subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), san: x.subjectAltName || null,
    // Format 3: Namen einzeln (null = unbekannt, [] = keine)
    san_dns: san ? (san.ungueltig ? null : san.dns) : [], san_ip: san ? (san.ungueltig ? null : san.ip) : [], cn: cnLesen(x.subject),
    gueltigAb: ab ? ab.toISOString() : null, gueltigBis: bis ? bis.toISOString() : null,
    laufzeitTage: ab && bis ? Math.round((bis - ab) / 864e5) : null, restTage: bis ? Math.floor((bis - jetzt) / 864e5) : null,
    schluessel: x.publicKey ? x.publicKey.asymmetricKeyType : null, bits: d.modulusLength || null, kurve: d.namedCurve || null,
    ...sig, fingerprint256: x.fingerprint256, ca: x.ca, selbst_signiert: selbstSigniert(x) };
}

// Vom Server gelieferte Zertifikate (DER, in Lieferreihenfolge) → Liste mit Inhaber, Aussteller, Fingerabdruck und der
// Angabe, ob Zertifikat i das Zertifikat i−1 ausgestellt hat (Name und Signatur geprüft). Nur was die Daten belegen.
function geliefert(ders) {
  const xs = ders.map(d => new crypto.X509Certificate(d));
  return xs.map((x, i) => {
    const e = { subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), fingerprint256: x.fingerprint256, ca: x.ca,
      selbst_signiert: selbstSigniert(x), gueltigBis: x.validToDate ? x.validToDate.toISOString() : new Date(x.validTo).toISOString() };
    if (i > 0) { let ok = false; try { ok = xs[i - 1].checkIssued(x) && xs[i - 1].verify(x.publicKey); } catch { ok = false; } e.stellt_vorgaenger_aus = ok; }
    return e;
  });
}

// Hostnamenabgleich nach RFC 6125 (unabhängig vom Vertrauensstatus). Wildcard nur als ganzes Label ganz links und nur für
// genau ein Label („*.example.de“ passt auf „a.example.de“, nicht auf „example.de“ oder „a.b.example.de“); keine Teil-Wildcards
// („w*.example.de“) und kein „*.tld“. Der Common Name zählt nur, wenn das Zertifikat keinen DNS-Namen im SAN hat.
const normName = n => String(n).toLowerCase().replace(/\.$/, '');
function musterPasst(muster, name) {
  const m = normName(muster), n = normName(name);
  if (!m.includes('*')) return m === n;
  const ml = m.split('.'), nl = n.split('.');
  if (ml[0] !== '*' || ml.slice(1).some(l => l.includes('*') || !l) || ml.length < 3) return false;
  return nl.length === ml.length && nl[0].length > 0 && nl.slice(1).join('.') === ml.slice(1).join('.');
}
const ipNorm = a => { const t = String(a).toLowerCase(); return require('net').isIPv6(t) ? t.replace(/(^|:)0+(?=[0-9a-f])/g, '$1') : t; };

// z: Kettenelement (Format 3: san_dns, san_ip, cn). Ergebnis { zustand: passt|nur_cn|passt_nicht|unbekannt, ueber, namen, grund }
function namePruefen(name, z) {
  if (!name) return { zustand: 'unbekannt', grund: 'kein Name zum Abgleich' };
  if (!z || !Array.isArray(z.san_dns) || !Array.isArray(z.san_ip)) return { zustand: 'unbekannt', grund: 'Namen des Zertifikats fehlen in den Rohdaten' };
  const namen = [...z.san_dns, ...z.san_ip];
  if (require('net').isIP(name)) {
    const t = z.san_ip.find(a => ipNorm(a) === ipNorm(name));
    return t ? { zustand: 'passt', ueber: 'san_ip', treffer: t, namen } : { zustand: 'passt_nicht', namen };
  }
  if (z.san_dns.length) {
    const t = z.san_dns.find(m => musterPasst(m, name));
    return t ? { zustand: 'passt', ueber: 'san_dns', treffer: t, namen } : { zustand: 'passt_nicht', namen };
  }
  if (z.cn === undefined) return { zustand: 'unbekannt', grund: 'Common Name fehlt in den Rohdaten', namen };
  if (z.cn && musterPasst(z.cn, name)) return { zustand: 'nur_cn', ueber: 'cn', treffer: z.cn, namen: [z.cn] };
  return { zustand: 'passt_nicht', namen: z.cn ? [z.cn] : namen };
}

// Vertrauensspeicher, gegen den das Prüfsystem die Kette prüft (für Bericht und Rohdaten)
function pruefsystem(ca) {
  const tls = require('tls');
  const opts = `${process.env.NODE_OPTIONS || ''} ${process.execArgv.join(' ')}`;
  let speicher;
  if (ca) speicher = 'ausdrücklich konfigurierte Zertifizierungsstelle (Parameter ca, nur für Tests)';
  else {
    speicher = `eingebaute Wurzelzertifikate von Node.js (Mozilla-Liste, ${tls.rootCertificates.length} Einträge)`;
    if (/--use-openssl-ca/.test(opts)) speicher = 'Zertifikatsspeicher von OpenSSL (--use-openssl-ca)';
    if (/--use-system-ca/.test(opts)) speicher += ' und Zertifikatsspeicher des Betriebssystems (--use-system-ca)';
    if (process.env.NODE_EXTRA_CA_CERTS) speicher += ' und zusätzliche Zertifikate aus NODE_EXTRA_CA_CERTS';
  }
  return { node: process.version, openssl: process.versions.openssl, vertrauensspeicher: speicher, namenspruefung: 'getrennt (lib/zertifikat.js, RFC 6125)' };
}

// peer: Ergebnis von tlsSocket.getPeerCertificate(true)
function kette(peer, jetzt = Date.now()) {
  const out = []; const gesehen = new Set(); let c = peer;
  while (c && c.raw && !gesehen.has(c.fingerprint256)) {
    gesehen.add(c.fingerprint256);
    out.push(eintrag(c.raw, jetzt));
    if (!c.issuerCertificate || c.issuerCertificate === c) break;
    c = c.issuerCertificate;
  }
  return out;
}

module.exports = { kette, signaturverfahren, SIGNATUR_OID, sanLesen, cnLesen, geliefert, namePruefen, musterPasst, pruefsystem };
