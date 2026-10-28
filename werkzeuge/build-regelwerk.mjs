// Erzeugt tr-02102-2-2026-01.json aus manuell gegen den PDF-Text geprüften Tabellen.
// Aufruf: node werkzeuge/build-regelwerk.mjs tr-02102-2-2026-01.json
import fs from 'node:fs';
const F = (abschnitt, tabelle, seite) => ({ abschnitt, tabelle, seite });
const rows = (spec, fund, extra = () => ({})) => spec.trim().split('\n').map(l => {
  const [name, iana, ref, bis] = l.trim().split(/\s+/);
  return { name, iana, referenz: ref, bis: parseInt(bis), bis_verlaengerbar: bis.endsWith('+'), ...extra(name), fundstelle: fund(name) };
});
const cond12 = n => ({
  pfs: !(/^TLS_(ECDH|DH)_/.test(n) || n.startsWith('TLS_RSA_PSK')),
  bedingung: n.includes('_CBC_') ? 'encrypt_then_mac' : null,
});
const t3 = rows(`
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC0,0x23 RFC5289 2031
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC0,0x24 RFC5289 2031
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC0,0x2B RFC5289 2031
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC0,0x2C RFC5289 2031
TLS_ECDHE_ECDSA_WITH_AES_128_CCM 0xC0,0xAC RFC7251 2031
TLS_ECDHE_ECDSA_WITH_AES_256_CCM 0xC0,0xAD RFC7251 2031
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xC0,0x27 RFC5289 2031
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 0xC0,0x28 RFC5289 2031
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC0,0x2F RFC5289 2031
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xC0,0x30 RFC5289 2031
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 0x00,0x40 RFC5246 2029
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 0x00,0x6A RFC5246 2029
TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 0x00,0xA2 RFC5288 2029
TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 0x00,0xA3 RFC5288 2029
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x00,0x67 RFC5246 2029
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x00,0x6B RFC5246 2029
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x00,0x9E RFC5288 2029
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 0x00,0x9F RFC5288 2029
TLS_DHE_RSA_WITH_AES_128_CCM 0xC0,0x9E RFC6655 2029
TLS_DHE_RSA_WITH_AES_256_CCM 0xC0,0x9F RFC6655 2029`,
  n => F('3.3.1.1', 3, (n.startsWith('TLS_ECDHE') || n === 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256') ? 7 : 8),
  n => ({ kategorie: 'pfs', ...cond12(n) }));
const t4 = rows(`
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 0xC0,0x25 RFC5289 2026
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 0xC0,0x26 RFC5289 2026
TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 0xC0,0x2D RFC5289 2026
TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 0xC0,0x2E RFC5289 2026
TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 0xC0,0x29 RFC5289 2026
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 0xC0,0x2A RFC5289 2026
TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 0xC0,0x31 RFC5289 2026
TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 0xC0,0x32 RFC5289 2026
TLS_DH_DSS_WITH_AES_128_CBC_SHA256 0x00,0x3E RFC5246 2026
TLS_DH_DSS_WITH_AES_256_CBC_SHA256 0x00,0x68 RFC5246 2026
TLS_DH_DSS_WITH_AES_128_GCM_SHA256 0x00,0xA4 RFC5288 2026
TLS_DH_DSS_WITH_AES_256_GCM_SHA384 0x00,0xA5 RFC5288 2026
TLS_DH_RSA_WITH_AES_128_CBC_SHA256 0x00,0x3F RFC5246 2026
TLS_DH_RSA_WITH_AES_256_CBC_SHA256 0x00,0x69 RFC5246 2026
TLS_DH_RSA_WITH_AES_128_GCM_SHA256 0x00,0xA0 RFC5288 2026
TLS_DH_RSA_WITH_AES_256_GCM_SHA384 0x00,0xA1 RFC5288 2026`,
  () => F('3.3.1.2', 4, 8), n => ({ kategorie: 'ohne_pfs_nur_falls_pfs_unmoeglich', ...cond12(n) }));
const t5 = rows(`
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 0xC0,0x37 RFC5489 2031
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 0xC0,0x38 RFC5489 2031
TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 0xD0,0x01 RFC8442 2031
TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 0xD0,0x02 RFC8442 2031
TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 0xD0,0x05 RFC8442 2031
TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 0x00,0xB2 RFC5487 2029
TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 0x00,0xB3 RFC5487 2029
TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 0x00,0xAA RFC5487 2029
TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 0x00,0xAB RFC5487 2029
TLS_DHE_PSK_WITH_AES_128_CCM 0xC0,0xA6 RFC6655 2029
TLS_DHE_PSK_WITH_AES_256_CCM 0xC0,0xA7 RFC6655 2029
TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 0x00,0xB6 RFC5487 2026
TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 0x00,0xB7 RFC5487 2026
TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 0x00,0xAC RFC5487 2026
TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 0x00,0xAD RFC5487 2026`,
  () => F('3.3.1.3', 5, 9), n => ({ kategorie: 'psk', ...cond12(n) }));
const g12 = rows(`
secp256r1 23 RFC8422 2031
secp384r1 24 RFC8422 2031
secp521r1 25 RFC8422 2031
brainpoolP256r1 26 RFC7027 2031
brainpoolP384r1 27 RFC7027 2031
brainpoolP512r1 28 RFC7027 2031
ffdhe3072 257 RFC7919 2029
ffdhe4096 258 RFC7919 2029`,
  n => F('3.3.2', 6, ['secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1'].includes(n) ? 9 : 10),
  n => ({ typ: n.startsWith('ffdhe') ? 'ffdhe' : 'ecdhe' }));
const g13 = rows(`
secp256r1 23 RFC8422 2031
secp384r1 24 RFC8422 2031
secp521r1 25 RFC8422 2031
brainpoolP256r1tls13 31 RFC8734 2031
brainpoolP384r1tls13 32 RFC8734 2031
brainpoolP512r1tls13 33 RFC8734 2031
ffdhe3072 257 RFC7919 2031
ffdhe4096 258 RFC7919 2031`,
  () => F('3.4.2', 10, 13),
  n => ({ typ: n.startsWith('ffdhe') ? 'ffdhe' : 'ecdhe', hinweis: 'alleinige (nicht hybride) Nutzung nur bis Ende 2031' }));
const s12 = rows(`
rsa 1 RFC5246 2025
dsa 2 RFC5246 2029
ecdsa 3 RFC5246 2031`, () => F('3.3.3', 7, 10), n => ({
  art: 'signaturverfahren',
  grund: n === 'rsa' ? 'PKCS #1 v1.5 Padding; Frist Ende 2025 abgelaufen' : n === 'dsa' ? 'geringe Verbreitung, in FIPS 186-5 abgekündigt' : null }));
const h12 = rows(`
sha256 4 RFC5246 2031
sha384 5 RFC5246 2031
sha512 6 RFC5246 2031`, () => F('3.3.3', 8, 10), () => ({ art: 'hashfunktion' }));
const sig13 = `
rsa_pss_rsae_sha256 0x0804 RFC8446 2032+
rsa_pss_rsae_sha384 0x0805 RFC8446 2032+
rsa_pss_rsae_sha512 0x0806 RFC8446 2032+
rsa_pss_pss_sha256 0x0809 RFC8446 2032+
rsa_pss_pss_sha384 0x080A RFC8446 2032+
rsa_pss_pss_sha512 0x080B RFC8446 2032+
ecdsa_secp256r1_sha256 0x0403 RFC8446 2032+
ecdsa_secp384r1_sha384 0x0503 RFC8446 2032+
ecdsa_secp521r1_sha512 0x0603 RFC8446 2032+
ecdsa_brainpoolP256r1tls13_sha256 0x081A RFC8734 2032+
ecdsa_brainpoolP384r1tls13_sha384 0x081B RFC8734 2032+
ecdsa_brainpoolP512r1tls13_sha512 0x081C RFC8734 2032+`;
const s13 = rows(sig13, () => F('3.4.3', 11, 13), () => ({ erweiterung: 'signature_algorithms' }));
const s13c = rows(`
rsa_pkcs1_sha256 0x0401 RFC8446 2025
rsa_pkcs1_sha384 0x0501 RFC8446 2025
rsa_pkcs1_sha512 0x0601 RFC8446 2025` + sig13, () => F('3.4.3', 12, 14), () => ({ erweiterung: 'signature_algorithms_cert' }));
const t13 = rows(`
TLS_AES_128_GCM_SHA256 0x13,0x01 RFC8446 2032+
TLS_AES_256_GCM_SHA384 0x13,0x02 RFC8446 2032+
TLS_AES_128_CCM_SHA256 0x13,0x04 RFC8446 2032+`, () => F('3.4.4', 13, 14));
const psk13 = rows(`
psk_ke 0 RFC8446 2026
psk_dhe_ke 1 RFC8446 2032+`, () => F('3.4.1', 9, 12),
  n => ({ pfs: n === 'psk_dhe_ke', hinweis: n === 'psk_ke' ? 'ohne PFS; nur in Sonderfällen mit Expertenrat' : null }));

const WEB = 'https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html';
const out = {
  quelle: {
    titel: 'BSI TR-02102-2 Kryptographische Verfahren: Empfehlungen und Schlüssellängen, Teil 2 – Verwendung von Transport Layer Security (TLS)',
    herausgeber: 'Bundesamt für Sicherheit in der Informationstechnik (BSI)',
    version: '2026-01',
    datum: '2026-01-27',
    versionsbeleg: 'Änderungshistorie (Tabelle 1, S. 2) und BSI-Webseite ("Version: 2026-01"); das Titelblatt (S. 1) nennt weder Version noch Datum',
    url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.pdf?__blob=publicationFile',
    seiten: 19,
    abgerufen: '2026-10-26',
    webseite: WEB
  },
  hinweis: 'Nur Fakten (Verfahrensnamen, Parameter, Fristen) mit Fundstelle, kein TR-Text. Nicht vom BSI geprüft oder anerkannt.',
  lesehinweise: {
    bis: 'Jahreszahl = empfohlen bis Ende dieses Jahres (Abschnitt 3.1.1, S. 6).',
    bis_verlaengerbar: 'true = Jahreszahl in der TR mit "+" markiert; Frist wird evtl. in einer künftigen Fassung verlängert (Abschnitt 3.1.1, S. 6).',
    stichtag: 'Fristen mit bis < aktuelles Jahr sind abgelaufen (bis 2025 seit 2026-01-01). Fristen bis 2026 enden am 2026-12-31.',
    iana: 'Alle IANA-Nummern in den Tabellen stammen aus der TR selbst (Spalte "IANA-Nr."). Nur die Nummern der PQC-Hybridgruppen in "pqc" sind ergänzt.',
    fundstelle_seite: 'Seitenzahlen = gedruckte Seitenzahl = PDF-Seite (19 Seiten).',
    sicherheitsniveau: '120 Bit (Abschnitt 3.1.2, S. 6)',
    nicht_aufgefuehrt: 'Nicht aufgeführte Verfahren gelten laut TR nicht automatisch als unsicher, sie sind nur nicht empfohlen (Kapitel 1, S. 4).'
  },
  versionen: [
    { name: 'TLS 1.3', status: 'empfohlen', bis: 2032, bis_verlaengerbar: true, bevorzugt: true, referenz: 'RFC8446', fundstelle: F('3.2', 2, 6) },
    { name: 'TLS 1.2', status: 'empfohlen', bis: 2031, bis_verlaengerbar: false, hinweis: 'endet 2031, weil für TLS 1.2 keine PQC-Schlüsseleinigung erwartet wird', referenz: 'RFC5246', fundstelle: F('3.2', 2, 6) },
    { name: 'TLS 1.1', status: 'nicht_empfohlen', fundstelle: F('3.2', null, 6) },
    { name: 'TLS 1.0', status: 'nicht_empfohlen', fundstelle: F('3.2', null, 6) },
    { name: 'SSL 3.0', status: 'nicht_empfohlen', fundstelle: F('3.2', null, 6) },
    { name: 'SSL 2.0', status: 'nicht_empfohlen', fundstelle: F('3.2', null, 6) }
  ],
  tls12_suiten: [...t3, ...t4, ...t5],
  tls12_suiten_hinweise: [
    { id: 'tls12_gesamt_max_2031', text_kurz: 'Alle TLS-1.2-Suiten, -Gruppen und -Signaturverfahren höchstens bis Ende 2031.', fundstelle: F('3.3', null, 7) },
    { id: 'pfs_bevorzugt', text_kurz: 'Suiten ohne PFS (Tabelle 4) nur, wenn Suiten aus Tabelle 3 nicht möglich sind.', fundstelle: F('3.3.1.2', 4, 8) },
    { id: 'dhe_bis_2029', text_kurz: 'TLS_DHE_*-Suiten nur bis 2029 (erwartete IETF-Abkündigung).', fundstelle: F('3.3.1.1 / 3.3.1.3', '3, 5', '8, 9') },
    { id: 'psk_plain_nicht', text_kurz: 'Reine TLS_PSK_*-Suiten (ohne ephemere Schlüssel/Zufallswerte) nicht empfohlen.', fundstelle: F('3.3.1.3', null, 9) },
    { id: 'rsa_psk_ohne_pfs', text_kurz: 'TLS_RSA_PSK_* ohne PFS, übrige PSK-Suiten aus Tabelle 5 mit PFS.', fundstelle: F('3.3.1.3', 5, 9) },
    { id: 'ccm_prf', text_kurz: 'CCM-Suiten ohne Hash im Namen nutzen SHA-256 für die PRF.', fundstelle: F('3.3.1', null, '7 (Fußnote 1)') }
  ],
  tls13_suiten: t13,
  tls13_psk_modi: psk13,
  gruppen_tls12: g12,
  gruppen_tls13: g13,
  signaturen_tls12: [...s12, ...h12],
  signaturen_tls12_hinweis: 'In TLS 1.2 wird ein Signaturverfahren (Tabelle 7) mit einer Hashfunktion (Tabelle 8) kombiniert. RSA-PSS in TLS 1.2 (nach RFC 8446, Abschnitte 1.3 und 4.2.3) folgt den Tabellen 11 und 12. Fundstelle 3.3.3, S. 10.',
  signaturen_tls13: s13,
  signaturen_tls13_cert: s13c,
  schluessellaengen: {
    fundstelle: F('3.6.1', 14, 15),
    signatur: [
      { algorithmus: 'ECDSA', min_bit: 250, ab: null, bis: 2032, bis_verlaengerbar: true },
      { algorithmus: 'DSA', min_bit: 3000, ab: 2023, bis: 2029, bis_verlaengerbar: false },
      { algorithmus: 'RSA', min_bit: 3000, ab: 2023, bis: 2032, bis_verlaengerbar: true }
    ],
    schluesseleinigung: [
      { algorithmus: 'ECDH', min_bit: 250, ab: null, bis: 2032, bis_verlaengerbar: true },
      { algorithmus: 'DH', min_bit: 3000, ab: 2023, bis: 2032, bis_verlaengerbar: true }
    ],
    hinweise: [
      'Feld "ab" = Spalte "Verwendung spätestens ab": Jahr, ab dem die Mindestlänge spätestens gilt.',
      'Gilt für Signaturschlüssel (Zertifikate und Schlüsseleinigung) sowie statische und ephemere (EC)DH-Schlüssel.',
      '(EC)DH allein nur bis Ende 2031; ab 2032 gelten die (EC)DH-Längen nur im hybriden Einsatz mit PQC.',
      'Für PFS ausschließlich ephemere Schlüssel; diese nach Verbindungsende sicher löschen (3.6.1, 4.2).',
      'Ableitung (nicht TR-Wortlaut): RSA-2048 und ffdhe2048 liegen unter 3000 Bit und erfüllen die Mindestlänge nicht.'
    ],
    kurven: {
      fundstelle: F('3.6.2', null, 16),
      bevorzugt: ['brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'],
      alternativ: ['secp256r1', 'secp384r1', 'secp521r1'],
      regel: 'Nur named curves über Fp (p prim); NIST-Kurven, falls Brainpool nicht verfügbar.'
    },
    zertifikate: {
      fundstelle: F('3.5 / 3.6', null, 15),
      regeln: [
        'Domainparameter und Schlüssellängen der Zertifikats-Signaturschlüssel richten sich nach TR-02102-1 (siehe Tabelle 14).',
        'Für X.509-Zertifikate und Pfadvalidierung verweist die TR auf TR-02103; für Bundesprojekte auf TR-03116-4.',
        'Im Web ist in der Regel mindestens die Server-Authentisierung nötig.',
        'Zertifikatssignaturen (signature_algorithms_cert): rsa_pkcs1_* nur bis 2025 (abgelaufen), RSA-PSS und ECDSA bis 2032+ (Tabelle 12).'
      ]
    }
  },
  bedingungen: [
    { id: 'encrypt_then_mac', gilt_fuer: 'TLS 1.2, CBC-Suiten', text_kurz: 'CBC-Suiten nur zusammen mit der Erweiterung Encrypt-then-MAC (RFC 7366); EtM generell empfohlen.', fundstelle: F('3.3.4.5 und Hinweise unter Tabellen 3, 4, 5', '3, 4, 5', '8, 9, 11') },
    { id: 'lucky13', gilt_fuer: 'TLS 1.2, CBC', text_kurz: 'Abwehr durch AEAD (GCM/CCM) oder Encrypt-then-MAC.', fundstelle: F('3.3.4.4', null, 11) },
    { id: 'extended_master_secret', gilt_fuer: 'TLS 1.2', text_kurz: 'Erweiterung Extended Master Secret (RFC 7627) einsetzen.', fundstelle: F('3.3.4.7', null, 12) },
    { id: 'renegotiation', gilt_fuer: 'TLS 1.2', text_kurz: 'Renegotiation nur nach RFC 5746; vom Client angestoßene Renegotiation soll der Server ablehnen.', fundstelle: F('3.3.4.1', null, 10) },
    { id: 'truncated_hmac', gilt_fuer: 'TLS 1.2', text_kurz: 'Erweiterung truncated_hmac (RFC 6066) nicht verwenden.', fundstelle: F('3.3.4.2', null, 11) },
    { id: 'kompression', gilt_fuer: 'TLS 1.2', text_kurz: 'TLS-Kompression abschalten, sofern nicht sicher ausgeschlossen ist, dass ein Angreifer Klartext einschleust (CRIME).', fundstelle: F('3.3.4.3', null, 11) },
    { id: 'heartbeat', gilt_fuer: 'TLS 1.2 und 1.3', text_kurz: 'Heartbeat-Erweiterung (RFC 6520) nicht verwenden.', fundstelle: F('3.3.4.6 / 3.4.5.1', null, '11-12, 14') },
    { id: 'supported_groups', gilt_fuer: 'TLS 1.2', text_kurz: 'Erweiterung supported_groups für ECDHE- und DHE-Suiten nutzen.', fundstelle: F('3.3.2', null, 9) },
    { id: 'signature_algorithms', gilt_fuer: 'TLS 1.2', text_kurz: 'Erweiterung signature_algorithms nutzen.', fundstelle: F('3.3.3', null, 10) },
    { id: 'zero_rtt', gilt_fuer: 'TLS 1.3', text_kurz: '0-RTT-Daten weder senden noch annehmen (kein Replay-Schutz).', fundstelle: F('3.4.1', null, 12) },
    { id: 'session_resumption', gilt_fuer: 'TLS 1.3', text_kurz: 'Wiederaufnahme ist in TLS 1.3 ein PSK-Handshake (Session Tickets zählen als PSK): psk_dhe_ke bis 2032+, psk_ke nur bis 2026 und nur in Sonderfällen. Für TLS 1.2 (Session-ID/Tickets) trifft die TR keine eigene Aussage.', fundstelle: F('3.4.1', 9, 12) },
    { id: 'pfs', gilt_fuer: 'TLS 1.2', text_kurz: 'Für personenbezogene oder sensible Daten wird PFS grundsätzlich empfohlen.', fundstelle: F('3.3.1.1', null, '7 (Fußnote 2)') },
    { id: 'ephemere_schluessel', gilt_fuer: 'alle', text_kurz: 'Ephemere Schlüssel nur für eine Verbindung, nicht dauerhaft speichern, danach unwiderruflich löschen.', fundstelle: F('4.2', null, 17) },
    { id: 'zufall', gilt_fuer: 'alle', text_kurz: 'Zufallszahlengenerator der Klassen DRG.3, DRG.4, DRT.1, PTG.3 oder NTG.1 (AIS 20/31).', fundstelle: F('4.3', null, 17) },
    { id: 'schluesselspeicherung', gilt_fuer: 'alle', text_kurz: 'Private Schlüssel geschützt speichern (z. B. HSM, Chipkarte), Vertrauensanker manipulationssicher.', fundstelle: F('4.1', null, 17) }
  ],
  pqc: [
    { aussage: 'Alleinige klassische Schlüsseleinigung nur noch bis Ende 2031 empfohlen.', quelle: 'TR-02102-2 2026-01', fundstelle: F('3.1.3', null, 6) },
    { aussage: 'Alleinige Nutzung der Gruppen aus Tabelle 10 (TLS 1.3) nur bis Ende 2031; (EC)DH-Schlüssellängen gelten ab 2032 nur im Hybrideinsatz.', quelle: 'TR-02102-2 2026-01', fundstelle: F('3.4.2 / 3.6.1', '10, 14', '13, 15') },
    { aussage: 'Das BSI kündigt an, die Hybridgruppen SecP256r1MLKEM768 und SecP384r1MLKEM1024 (draft-ietf-tls-ecdhe-mlkem) nach Verabschiedung des RFC zu empfehlen; in den Tabellen der Fassung 2026-01 stehen sie noch nicht.', gruppen: ['SecP256r1MLKEM768', 'SecP384r1MLKEM1024'], quelle: 'TR-02102-2 2026-01', fundstelle: F('3.4.2', null, 13) },
    { aussage: 'Für TLS 1.2 erwartet das BSI keine standardisierte PQC-Schlüsseleinigung; deshalb TLS 1.2 nur bis 2031.', quelle: 'TR-02102-2 2026-01', fundstelle: F('3.2', 2, 6) },
    {
      aussage: 'Laut BSI-Webseite ist der Standard als RFC 10024 ("Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3", Proposed Standard) erschienen. SecP256r1MLKEM768 und SecP384r1MLKEM1024 werden in der nächsten TR-Fassung empfohlen und sind ab sofort TR-konform in TLS 1.3 einsetzbar. Zusätzlich kann X25519MLKEM768 eingesetzt werden.',
      gruppen: ['SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'X25519MLKEM768'],
      status: 'tr_konform_einsetzbar_tls13_laut_webseite',
      iana_gruppen_nr: { SecP256r1MLKEM768: 4587, X25519MLKEM768: 4588, SecP384r1MLKEM1024: 4589 },
      iana_hinweis: 'Nummern nicht aus TR oder Webseite, sondern aus dem IANA-Register \"TLS Supported Groups\" (tls-parameters-8), abgeglichen am 2026-10-28: Referenz jeweils RFC 10024. Hex: 0x11EB, 0x11EC, 0x11ED.',
      quelle: 'BSI-Webseite TR-02102, Abschnitt "BSI TR-02102-2", "Hinweis zu TLS 1.3", abgerufen 2026-10-26',
      url: WEB
    },
    { aussage: 'Reines ML-KEM ohne klassischen Anteil wird weder in der TR noch auf der Webseite für TLS genannt; die TR spricht ausdrücklich von hybrider Nutzung.', quelle: 'TR-02102-2 2026-01 und BSI-Webseite', fundstelle: F('3.1.3', null, 6) }
  ],
  nicht_aufgefuehrt_haeufig: [
    { name: 'X25519', art: 'gruppe', hinweis: 'Nicht in Tabellen 6/10; laut Webseite nur als Teil von X25519MLKEM768 zulässig.' },
    { name: 'X448', art: 'gruppe', hinweis: 'Nicht in Tabellen 6/10.' },
    { name: 'ffdhe2048', art: 'gruppe', hinweis: 'Nicht in Tabellen 6/10; unter 3000 Bit.' },
    { name: 'ffdhe6144', art: 'gruppe', hinweis: 'Nicht in Tabellen 6/10.' },
    { name: 'ffdhe8192', art: 'gruppe', hinweis: 'Nicht in Tabellen 6/10.' },
    { name: 'TLS_CHACHA20_POLY1305_SHA256', art: 'tls13_suite', hinweis: 'Nicht in Tabelle 13.' },
    { name: 'TLS_AES_128_CCM_8_SHA256', art: 'tls13_suite', hinweis: 'Nicht in Tabelle 13.' },
    { name: 'TLS_ECDHE_*_WITH_CHACHA20_POLY1305_SHA256', art: 'tls12_suite', hinweis: 'Nicht in Tabellen 3-5.' },
    { name: 'TLS_*_WITH_AES_*_CBC_SHA (HMAC-SHA-1)', art: 'tls12_suite', hinweis: 'Nicht in Tabellen 3-5 (HMAC-SHA-1 laut Tabelle 1 seit Fassung 2020-01 abgekündigt).' },
    { name: 'TLS_RSA_WITH_* (RSA-Schlüsseltransport)', art: 'tls12_suite', hinweis: 'Nicht in Tabellen 3-5.' },
    { name: 'ed25519 / ed448', art: 'signatur', hinweis: 'Nicht in Tabellen 11/12.' },
    { name: 'rsa_pkcs1_* in signature_algorithms (TLS 1.3)', art: 'signatur', hinweis: 'Nicht in Tabelle 11; in Tabelle 12 nur bis 2025.' },
    { name: 'SHA-1 / SHA-224 in Signaturen', art: 'signatur', hinweis: 'Nicht in Tabellen 8, 11, 12.' }
  ]
};
out.zaehlung = {
  versionen: out.versionen.length,
  tls12_suiten: { tabelle3: t3.length, tabelle4: t4.length, tabelle5: t5.length, gesamt: t3.length + t4.length + t5.length },
  tls13_suiten: t13.length, tls13_psk_modi: psk13.length, gruppen_tls12: g12.length, gruppen_tls13: g13.length,
  signaturen_tls12: { tabelle7: s12.length, tabelle8: h12.length }, signaturen_tls13: s13.length, signaturen_tls13_cert: s13c.length,
  bedingungen: out.bedingungen.length, pqc: out.pqc.length, nicht_aufgefuehrt_haeufig: out.nicht_aufgefuehrt_haeufig.length
};
fs.writeFileSync(process.argv[2], JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out.zaehlung));
