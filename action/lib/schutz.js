// SPDX-License-Identifier: Apache-2.0
// Sperrliste (gekürzte Fassung für die GitHub Action): Die Action prüft nur Ziele, die der Nutzer selbst angibt; eine
// Sperrliste wird nicht geführt. messung.js ruft gesperrt() vor jedem Handshake auf; mit leerer Liste greift nie ein Eintrag.
// Kontingent und Tageszähler des Prüfkerns entfallen hier.
'use strict';
const net = require('net');

const norm = s => String(s || '').trim().toLowerCase().replace(/\.$/, '');

function sperrlisteLaden() { return []; }

// Gesperrt, wenn Hostname, SNI oder aufgelöste Adresse einem Eintrag entspricht oder unter einer gesperrten Domain liegt.
function gesperrt(liste, ...namen) {
  for (const n of namen.map(norm).filter(Boolean))
    for (const e of liste) if (n === e || (!net.isIP(e) && !net.isIP(n) && n.endsWith('.' + e))) return e;
  return null;
}

module.exports = { sperrlisteLaden, gesperrt };
