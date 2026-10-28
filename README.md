# BSI TR-02102-2 (Version 2026-01) als JSON

Maschinenlesbare Fassung der Tabellen aus der Technischen Richtlinie **BSI TR-02102-2 „Kryptographische Verfahren:
Empfehlungen und Schlüssellängen, Teil 2 – Verwendung von Transport Layer Security (TLS)“, Version 2026-01 vom
27.01.2026**: TLS-Versionen, Cipher-Suiten für TLS 1.2 und 1.3, Gruppen, Signaturverfahren, PSK-Modi,
Mindestschlüssellängen – jeweils mit IANA-Nummer, RFC, Frist („empfohlen bis“) und Fundstelle (Abschnitt, Tabelle, Seite).

*English summary: Machine-readable JSON of all tables in the German BSI technical guideline TR-02102-2 (TLS), version
2026-01, with IANA code points, RFC, recommended-until year and the exact source location of every entry. Not
affiliated with or endorsed by the BSI.*

> **Kein Dokument des BSI.** Diese Datei wurde vom BSI weder erstellt noch geprüft oder anerkannt. Sie enthält nur
> Fakten (Verfahrensnamen, Parameter, Fristen) mit Fundstelle, keinen Text der Richtlinie. Maßgeblich ist allein das
> [PDF des BSI](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.pdf?__blob=publicationFile).

## Inhalt

| Datei | Zweck |
|---|---|
| [`tr-02102-2-2026-01.json`](tr-02102-2-2026-01.json) | das Regelwerk |
| [`PRUEFPROTOKOLL.md`](PRUEFPROTOKOLL.md) | wie die Werte übertragen und gegengeprüft wurden, offene und auffällige Stellen |
| [`werkzeuge/`](werkzeuge/) | Textextraktion aus dem PDF und unabhängige Zweitprüfung (Node.js, pdfjs-dist) |

## Felder

| Feld | Quelle in der TR | Einträge |
|---|---|---|
| `versionen` | Tabelle 2 und Abschnitt 3.2 | 6 (TLS 1.3, 1.2 empfohlen; 1.1, 1.0, SSL 3.0, 2.0 nicht empfohlen) |
| `tls12_suiten` | Tabellen 3, 4, 5 | 51 (mit `kategorie`, `pfs`, `bedingung`) |
| `tls13_suiten` | Tabelle 13 | 3 |
| `tls13_psk_modi` | Tabelle 9 | 2 |
| `gruppen_tls12`, `gruppen_tls13` | Tabellen 6, 10 | je 8 |
| `signaturen_tls12` | Tabellen 7, 8 | 6 |
| `signaturen_tls13`, `signaturen_tls13_cert` | Tabellen 11, 12 | 12, 15 |
| `schluessellaengen` | Tabelle 14 | Signatur und Schlüsseleinigung |
| `bedingungen` | Hinweise unter den Tabellen und Abschnitt 3.3.4 | 15 (z. B. Encrypt-then-MAC für CBC-Suiten) |
| `pqc` | Abschnitte 3.1.3, 3.4.2 und BSI-Webseite (Hinweis zu TLS 1.3) | 6 |
| `nicht_aufgefuehrt_haeufig` | – | 13 häufig anzutreffende Verfahren, die in den Tabellen fehlen (z. B. X25519 allein) |

Jeder Eintrag sieht so aus:

```json
{
  "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "iana": "0xC0,0x2B",
  "referenz": "RFC5289",
  "bis": 2031,
  "bis_verlaengerbar": false,
  "kategorie": "pfs",
  "pfs": true,
  "bedingung": null,
  "fundstelle": { "abschnitt": "3.3.1.1", "tabelle": 3, "seite": 7 }
}
```

## Lesehinweise

- `bis`: empfohlen bis Ende dieses Jahres (Abschnitt 3.1.1). `bis_verlaengerbar: true` steht für die Markierung „+“
  in der TR („2032+“: mindestens bis Ende 2032, eventuell länger).
- Fristen vor dem aktuellen Jahr sind abgelaufen: `bis: 2025` gilt seit dem 01.01.2026 nicht mehr als empfohlen
  (betrifft `rsa` in Tabelle 7 und `rsa_pkcs1_*` in Tabelle 12). Ein Prüfwerkzeug muss das Datum auswerten.
- Nicht aufgeführte Verfahren gelten laut TR nicht automatisch als unsicher, sie sind nur nicht empfohlen (Kapitel 1).
- Alle IANA-Nummern stammen aus der TR selbst. Ergänzt sind nur die Nummern der PQC-Hybridgruppen in `pqc`
  (aus dem IANA-Register „TLS Supported Groups“).

## Beispiel

TLS-1.2-Suiten, die am 01.01.2027 noch empfohlen sind:

```sh
node -e "const r=require('./tr-02102-2-2026-01.json');for(const s of r.tls12_suiten)if(s.bis>=2027)console.log(s.iana,s.name,s.bedingung||'')"
```

mit `jq`:

```sh
jq -r '.tls12_suiten[] | select(.bis >= 2027) | "\(.iana) \(.name)"' tr-02102-2-2026-01.json
```

## Nachprüfen

Das PDF der TR ist nicht Teil dieses Repositorys. So lässt sich die Übertragung selbst prüfen:

```sh
cd werkzeuge && npm install && cd ..
# PDF vom BSI laden (Link oben) und als BSI-TR-02102-2.pdf ablegen
node werkzeuge/extract.mjs BSI-TR-02102-2.pdf tr.txt
node werkzeuge/pruefe.mjs tr.txt tr-02102-2-2026-01.json      # erwartet: „Alle Tabellen stimmen überein.“
node werkzeuge/build-regelwerk.mjs neu.json && cmp neu.json tr-02102-2-2026-01.json
```

Geprüft gegen das PDF mit 19 Seiten, SHA-256 `eed80d1a38ec0d7d8908765c3a09ea6f17a7ca729bef95b0d358d5d129af3f1f`,
abgerufen am 26.10.2026.

## Fehler und neue Fassungen

Fehler bitte als [Issue](https://github.com/ciphermeter/tr-02102-2-regelwerk/issues) melden, mit Tabelle und Seite.
Erscheint eine neue Fassung der TR, kommt sie als neue Datei (`tr-02102-2-<version>.json`) dazu; ältere Fassungen
bleiben unverändert.

## Wer das nutzt

[Ciphermeter](https://ciphermeter.com) gleicht mit diesem Regelwerk die TLS-Konfiguration eines Servers ab und
liefert einen Bericht je Hostname.

## Lizenz

[Apache License 2.0](LICENSE) für JSON, Prüfprotokoll und Werkzeuge. Die Technische Richtlinie selbst gehört dem BSI und
ist hier nicht enthalten.
