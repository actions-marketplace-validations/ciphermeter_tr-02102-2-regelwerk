// SPDX-License-Identifier: Apache-2.0
// Befundkennungen, Messbelege und Erfolgskriterien.
// Kennung: deterministisch aus dem Schlüssel der Bewertungszeile (Regel + Merkmal, z. B. „version:TLSv1.1“), nie aus der
// Reihenfolge: „B-“ + die ersten 8 Hexzeichen von SHA-256(schlüssel). Gleicher Befund → gleiche Kennung in jedem Bericht.
// Messgrößen: Pfade in die Rohdaten, Teile durch „/“ getrennt (z. B. „versionen/TLSv1.1/status“,
// „tls12_suiten/eintraege/name=…/status“, „zertifikat/kette/0/bits“) oder
// „bewertung:<schlüssel>“ für die Einstufung des Prüfkerns. Ein Erfolgskriterium gilt nur bei belegtem Messwert als erfüllt;
// fehlende oder nicht prüfbare Werte ergeben „unbekannt“ (null), nie „erfüllt“.
'use strict';
const crypto = require('crypto');

const kennung = schluessel => 'B-' + crypto.createHash('sha256').update(String(schluessel)).digest('hex').slice(0, 8).toUpperCase();

const LISTEN = { tls12_suite: 'tls12_suiten', tls13_suite: 'tls13_suiten', gruppe13: 'gruppen_tls13', gruppe12: 'gruppen_tls12', sig13: 'signaturen_tls13' };
const MERKMAL = { ems: 'extended_master_secret', reneg: 'sichere_renegotiation', kompression: 'kompression', etm: 'encrypt_then_mac_bei_cbc' };

// Ort des Messbelegs in den Rohdaten (ohne .status/.wert) oder null
function belegPfad(schluessel) {
  const [art, ...rest] = String(schluessel).split(':'); const name = rest.join(':');
  if (art === 'version') return `versionen/${name}`;
  if (LISTEN[art]) return `${LISTEN[art]}/eintraege/name=${name}`;
  if (art === 'merkmal') return MERKMAL[name] ? `tls12_merkmale/${MERKMAL[name]}` : 'tls12_merkmale';
  if (art === 'luecke') return rest[0];
  if (art === 'pqc') return 'gruppen_tls13';
  if (art === 'zert') return { kette: 'zertifikat', fehlt: 'zertifikat' }[name] || 'zertifikat/kette/0';
  if (['tls12_suiten', 'tls13_suiten', 'gruppen_tls13', 'gruppen_tls12', 'signaturen_tls13'].includes(art)) return art;
  return null;
}

// Liest einen Pfad; in Listen wählt „name=…“ den Eintrag nach Namen (ohne Groß-/Kleinschreibung), eine Zahl den Index
function messwert(roh, pfad) {
  let o = roh;
  for (const teil of String(pfad).split('/')) {
    if (o == null || typeof o !== 'object') return undefined;
    if (Array.isArray(o)) {
      const n = /^name=(.*)$/.exec(teil);
      o = n ? o.find(e => e && String(e.name).toLowerCase() === n[1].toLowerCase()) : /^\d+$/.test(teil) ? o[Number(teil)] : undefined;
    } else o = Object.prototype.hasOwnProperty.call(o, teil) ? o[teil] : undefined;
  }
  return o;
}

// Messbeleg einer Bewertungszeile: Pfad, Verfahren und Grund aus den Rohdaten (soweit vorhanden)
function beleg(roh, z) {
  const pfad = belegPfad(z.schluessel);
  const w = pfad ? messwert(roh, pfad) : undefined;
  const b = { pfad };
  if (w && typeof w === 'object' && !Array.isArray(w)) {
    if (w.status) b.status = w.status; else if (w.wert) b.status = w.wert;
    if (w.verfahren) b.verfahren = w.verfahren;
    if (w.grund) b.grund = w.grund;
  }
  return b;
}

// Wert einer Messgröße: Rohdatenpfad oder bewertung:<schlüssel> (Einstufung der Zeile)
function groesseLesen(groesse, roh, bew) {
  if (groesse.startsWith('bewertung:')) { const z = bew.zeilen.find(x => x.schluessel === groesse.slice(10)); return z ? z.stufe : undefined; }
  return messwert(roh, groesse);
}

// Prüft ein Erfolgskriterium gegen eine (neue) Messung. Bedingungen sind Alternativen: eine erfüllte genügt.
// Rückgabe true (erfüllt) · false (belegt nicht erfüllt) · null (unbekannt: Wert fehlt oder nicht prüfbar)
function erfuellt(kriterium, roh, bew) {
  let unbekannt = false;
  for (const b of kriterium.bedingungen) {
    const w = groesseLesen(b.groesse, roh, bew);
    if (w == null || w === 'nicht_pruefbar' || w === 'np') { unbekannt = true; continue; }
    if (b.erwartet && b.erwartet.includes(w)) return true;
    if (b.mindestens != null && typeof w === 'number' && w >= b.mindestens) return true;
  }
  return unbekannt ? null : false;
}

module.exports = { kennung, belegPfad, messwert, beleg, groesseLesen, erfuellt };
