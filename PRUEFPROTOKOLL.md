# Prüfprotokoll: Regelwerk TR-02102-2 (2026-01)

Datei: `tr-02102-2-2026-01.json`. Übertragen und geprüft am 2026-10-26 von Ciphermeter, PQC-Angaben nachgeprüft am 2026-10-28. Das BSI hat diese Prüfung weder durchgeführt noch anerkannt.

## Quelle

- PDF: BSI-TR-02102-2.pdf, 19 Seiten, 812.933 Byte, abgerufen am 2026-10-26 über die `publicationFile`-URL. SHA-256 `eed80d1a38ec0d7d8908765c3a09ea6f17a7ca729bef95b0d358d5d129af3f1f`. Das PDF und der extrahierte Text sind nicht Teil dieses Repositorys.
- Version und Datum: Das **Titelblatt (S. 1) nennt weder Version noch Datum.** Es enthält nur den Titel als Text und ein Hintergrundbild, das wir gerendert und angesehen haben: Logo, keine Versionsangabe. Die Version 2026-01 vom 27.01.2026 steht in der Änderungshistorie (Tabelle 1, S. 2, letzte Zeile). Die BSI-Webseite nennt ebenfalls „Version: 2026-01“ (PDF, 794 KB; das passt zur geladenen Dateigröße).
- Text extrahiert mit pdfjs-dist (`werkzeuge/extract.mjs`). Die Zeilen sind nach y-Position gruppiert, die Spalten durch ` | ` getrennt. Die gedruckten Seitenzahlen stimmen mit den PDF-Seiten überein.

## Vorgehen

1. Der gesamte Text (Seiten 1 bis 19) wurde gelesen und die Tabellen von Hand in `werkzeuge/build-regelwerk.mjs` übertragen.
2. Zweitprüfung mit `werkzeuge/pruefe.mjs`: Das Skript liest die Tabellenzeilen unabhängig per Regex aus dem Text, auch über Seitenumbrüche, wiederholte Kopfzeilen und Fußnoten hinweg. Danach vergleicht es jede Zeile mit dem JSON nach Name, IANA-Nr., Referenz, Frist inkl. „+“ und Seite. Ergebnis: **keine Abweichung.**
3. Gegenprobe: Im ganzen Text gibt es 105 Zeilen im Tabellenformat. Das entspricht genau der Summe der Tabellen 3 bis 13 (20+16+15+8+3+3+2+8+12+15+3). Keine Tabellenzeile fehlt also im JSON.
4. Die Tabellen 2 (Versionen) und 14 (Schlüssellängen) haben ein anderes Format. Sie wurden von Hand mit den Textzeilen verglichen: stimmt überein.

## Tabellen und Einträge

| Tabelle | Inhalt | Abschnitt | Seite | Einträge | JSON-Feld |
|---|---|---|---|---|---|
| 1 | Änderungshistorie | – | 2 | (nur Versionsbeleg) | quelle |
| 2 | TLS-Versionen | 3.2 | 6 | 2 (+4 „nicht empfohlen“ aus dem Fließtext) | versionen (6) |
| 3 | TLS 1.2 mit PFS | 3.3.1.1 | 7–8 | 20 (10 ECDHE bis 2031, 10 DHE bis 2029) | tls12_suiten |
| 4 | TLS 1.2 ohne PFS | 3.3.1.2 | 8 | 16 (alle bis 2026) | tls12_suiten |
| 5 | TLS 1.2 PSK | 3.3.1.3 | 9 | 15 (5 ECDHE_PSK bis 2031, 6 DHE_PSK bis 2029, 4 RSA_PSK bis 2026) | tls12_suiten |
| 6 | Gruppen TLS 1.2 | 3.3.2 | 9–10 | 8 | gruppen_tls12 |
| 7 | Signaturverfahren TLS 1.2 | 3.3.3 | 10 | 3 | signaturen_tls12 (art=signaturverfahren) |
| 8 | Hashfunktionen TLS 1.2 | 3.3.3 | 10 | 3 | signaturen_tls12 (art=hashfunktion) |
| 9 | PSK-Modi TLS 1.3 | 3.4.1 | 12 | 2 | tls13_psk_modi |
| 10 | Gruppen TLS 1.3 | 3.4.2 | 13 | 8 | gruppen_tls13 |
| 11 | signature_algorithms TLS 1.3 | 3.4.3 | 13 | 12 | signaturen_tls13 |
| 12 | signature_algorithms_cert TLS 1.3 | 3.4.3 | 14 | 15 | signaturen_tls13_cert |
| 13 | Cipher-Suiten TLS 1.3 | 3.4.4 | 14 | 3 | tls13_suiten |
| 14 | Mindestschlüssellängen | 3.6.1 | 15 | 5 | schluessellaengen |

Weitere Felder: `bedingungen` 15, `pqc` 6, `nicht_aufgefuehrt_haeufig` 13, `tls12_suiten_hinweise` 6.

## Unsichere oder auffällige Stellen

1. **Seitenumbrüche:** Tabelle 3 läuft über S. 7/8 (11 Zeilen auf S. 7, 9 auf S. 8), Tabelle 6 über S. 9/10 (4 und 4 Zeilen). Auf der Folgeseite wird die Kopfzeile wiederholt. Fußnoten 1 und 2 stehen auf S. 7 mitten zwischen den Tabellenzeilen. Der erste automatische Abgleich hat an diesen Stellen nur 11 bzw. 4 Zeilen gezählt, weil die Leerzeile am Seitenwechsel als Tabellenende galt. Nach der Korrektur des Prüfskripts stimmen beide Tabellen (20 bzw. 8). Die Seitenangabe pro Eintrag ist zeilengenau geprüft.
2. **Frist „2032+“:** Im JSON steht sie als `bis: 2032, bis_verlaengerbar: true`. Nach Abschnitt 3.1.1 heißt das „mindestens bis Ende 2032, eventuell länger“.
3. **Abgelaufene Fristen:** `rsa` (Tabelle 7) und `rsa_pkcs1_*` (Tabelle 12) stehen in der TR mit „bis 2025“, sind also am Stichtag 2026-10-26 schon abgelaufen. Tabelle 4, TLS_RSA_PSK_* und `psk_ke` laufen Ende 2026 aus. Ein Prüfwerkzeug muss das Datum auswerten.
4. **Bedingung Encrypt-then-MAC:** Die TR schreibt sie als Hinweis unter die Tabellen 3, 4 und 5, nicht als Tabellenspalte. Sie ist jeder Suite mit `_CBC_` im Namen zugeordnet (automatisch geprüft). Das ist eine Ableitung aus dem Hinweis.
5. **Feld `pfs`:** Aus der Tabellenzugehörigkeit abgeleitet (Tabelle 4 = ohne PFS) und aus dem Hinweis zu Tabelle 5 (RSA_PSK ohne PFS). Es ist kein eigenes Feld der TR.
6. **Session Resumption:** Für TLS 1.2 (Session-ID, Session Tickets nach RFC 5077) sagt die TR nichts. Für TLS 1.3 erwähnt sie Session Tickets nur als Quelle eines PSK (3.4.1). Im JSON steht deshalb nur die Ableitung über die PSK-Modi, mit diesem Hinweis.
7. **Zertifikatsanforderungen:** Die TR-02102-2 enthält dazu kaum eigene Vorgaben. Sie verweist auf TR-02102-1, TR-02103 und TR-03116-4 und nennt Mindestlängen (Tabelle 14) und Signaturverfahren (Tabelle 12). Konkrete Vorgaben etwa zu Laufzeit, Extensions oder SAN stehen nicht in diesem Dokument und fehlen daher im JSON.
8. **Kurven 3.6.2:** Brainpool gilt als bevorzugt, secp* als Ausweichlösung. In den Tabellen 6 und 10 stehen beide gleichrangig mit derselben Frist. Beides ist getrennt erfasst.
9. **Redaktionelle Auffälligkeiten in der TR (für das Regelwerk ohne Einfluss):** Im Literaturverzeichnis fehlen Einträge zu RFC 5288, RFC 7366 und RFC 6520, die im Text zitiert werden. Der Eintrag [RFC 5489] trägt im Text die Bezeichnung „RFC 5289“. In 3.3.3 steht „[RFC5246]“ ohne Leerzeichen.
10. **Leerzeichen/Silbentrennung:** Der Parser trennt einzelne Wörter („g | enug“, „[IA | NA]“, „1.3geeignet“). Das betrifft nur Fließtext, keine Tabellenwerte.

## PQC und Webseite

- In der TR (3.1.3, 3.4.2) ist die Hybrid-Empfehlung nur angekündigt (SecP256r1MLKEM768, SecP384r1MLKEM1024). In den Tabellen steht keine PQC-Gruppe.
- Die BSI-Webseite (abgerufen 2026-10-26) ist weitergegangen. Nach ihrem „Hinweis zu TLS 1.3“ ist RFC 10024 erschienen, beide Gruppen sind ab sofort TR-konform in TLS 1.3 einsetzbar und kommen in die nächste TR-Fassung. X25519MLKEM768 ist zusätzlich einsetzbar. Das steht mit Quelle im JSON.
- **Nachgeprüft am 2026-10-28:** RFC 10024 ist beim RFC Editor veröffentlicht („Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3“). Die IANA-Gruppennummern stammen nicht aus TR oder Webseite, sondern aus dem IANA-Register „TLS Supported Groups“ (tls-parameters-8): 4587 (0x11EB) SecP256r1MLKEM768, 4588 (0x11EC) X25519MLKEM768, 4589 (0x11ED) SecP384r1MLKEM1024, alle mit Referenz RFC 10024.
- Die Webseite sagt nur „kann eingesetzt werden“ und nennt keine Frist für die PQC-Gruppen. Im JSON gibt es dafür deshalb kein `bis`.

## Nicht geklärt

- Ob X25519 allein „TR-konform“ ist: nicht in den Tabellen, also nicht empfohlen. Nach Kapitel 1 ist es damit aber nicht als unsicher bewertet. Das Regelwerk führt es unter `nicht_aufgefuehrt_haeufig`, nicht als Verstoß.
- Ob die Webseite seit dem Abruf weitere Hinweise ergänzt hat: Das ist eine Momentaufnahme vom 2026-10-26.
- Die TR-02102-1, auf die mehrfach verwiesen wird (Schlüssellängen, Zertifikate, PQC-Fristen), ist hier nicht ausgewertet.

## Reproduktion

```
cd werkzeuge && npm install && cd ..
node werkzeuge/extract.mjs BSI-TR-02102-2.pdf tr.txt
node werkzeuge/build-regelwerk.mjs neu.json && cmp neu.json tr-02102-2-2026-01.json
node werkzeuge/pruefe.mjs tr.txt tr-02102-2-2026-01.json
```

Letzter Lauf am 2026-10-28: Neuaufbau byte-gleich, Zweitprüfung „Alle Tabellen stimmen überein.“
