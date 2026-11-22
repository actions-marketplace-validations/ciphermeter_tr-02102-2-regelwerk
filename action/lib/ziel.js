// SPDX-License-Identifier: Apache-2.0
// Ziel einer Prüfung (Hostname und Port): eine gemeinsame Normalisierungsregel.
// Normalisierung: trimmen, Kleinbuchstaben, Präfix http:// oder https:// entfernen, alles ab dem ersten / ? # entfernen,
//   abschließenden Punkt entfernen, optionalen Port nach dem letzten Doppelpunkt abtrennen.
// Hostname: nur ASCII (Umlaut-Domains bitte als xn--…), 1–253 Zeichen, mindestens zwei Labels zu je 1–63 Zeichen aus a–z, 0–9, -,
//   kein Bindestrich am Rand eines Labels, Endung aus Buchstaben (2–63) oder xn--…. IP-Adressen, Benutzerangaben (@) und Leerzeichen
//   sind kein Ziel. Ausnahme nur mit { lokal: true } (eigene Testgegenstellen): localhost, 127.x.x.x, ::1.
// Port: Ganzzahl 1–65535, als Text nur Ziffern ohne führende Null; Standard 443.
'use strict';

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const HOST_RE = new RegExp(`^(?:${LABEL}\\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`);
const LOKAL_RE = /^(localhost|127(\.\d{1,3}){3}|::1)$/;

const istLokal = host => LOKAL_RE.test(String(host || '').trim().toLowerCase().replace(/\.$/, ''));

function portLesen(p) {
  if (p === undefined || p === null || p === '') return { port: 443 };
  if (typeof p === 'number') return Number.isInteger(p) && p >= 1 && p <= 65535 ? { port: p } : { fehler: 'Port muss eine ganze Zahl von 1 bis 65535 sein' };
  if (typeof p !== 'string' || !/^[1-9][0-9]{0,4}$/.test(p)) return { fehler: 'Port muss eine ganze Zahl von 1 bis 65535 sein' };
  const n = Number(p);
  return n <= 65535 ? { port: n } : { fehler: 'Port muss eine ganze Zahl von 1 bis 65535 sein' };
}

// eingabe: „www.beispiel.de“, „https://www.beispiel.de:8443/pfad“ …; opt.port: getrennt angegebener Port (Zahl oder Text)
// Rückgabe: { ok: true, host, port, lokal } oder { ok: false, fehler }
function zielNormalisieren(eingabe, opt = {}) {
  if (typeof eingabe !== 'string') return { ok: false, fehler: 'Hostname fehlt' };
  let s = eingabe.trim().toLowerCase().replace(/^https?:\/\//, '');
  s = s.replace(/[/?#].*$/, '');
  if (opt.lokal && s === '::1') return { ok: true, host: '::1', port: portLesen(opt.port).port || 443, lokal: true };
  let portText;
  const i = s.lastIndexOf(':');
  if (i >= 0) { portText = s.slice(i + 1); s = s.slice(0, i); if (portText === '') return { ok: false, fehler: 'Port fehlt nach dem Doppelpunkt' }; }
  s = s.replace(/\.$/, '');
  if (portText !== undefined && opt.port !== undefined && opt.port !== null && opt.port !== '') return { ok: false, fehler: 'Port doppelt angegeben' };
  const p = portLesen(portText !== undefined ? portText : opt.port);
  if (p.fehler) return { ok: false, fehler: p.fehler };
  if (opt.lokal && istLokal(s)) return { ok: true, host: s, port: p.port, lokal: true };
  if (s.length < 1 || s.length > 253 || !HOST_RE.test(s)) return { ok: false, fehler: 'kein gültiger Hostname (Beispiel: www.ihre-firma.de oder www.ihre-firma.de:443)' };
  return { ok: true, host: s, port: p.port, lokal: false };
}

// Schlüssel für Zähler und Vergleiche
const zielSchluessel = (host, port) => `${host}:${port}`;

module.exports = { zielNormalisieren, istLokal, zielSchluessel };
