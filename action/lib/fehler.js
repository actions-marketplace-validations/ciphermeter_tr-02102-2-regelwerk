// SPDX-License-Identifier: Apache-2.0
// Ordnet Fehler eines Verbindungsversuchs ein: Hat der Server eindeutig abgelehnt, oder war die Messung nicht möglich?
// Grundsatz: Nur ein TLS-Alarm des Servers, der Ablehnung bedeutet, oder eine Antwort mit einer anderen Protokollversion
// gilt als „nachgewiesen abgelehnt“. Zeitüberschreitung, DNS-, Netz- und lokale Fehler sind „nicht prüfbar“.
'use strict';

const ANGEBOTEN = 'angeboten', ABGELEHNT = 'abgelehnt', NICHT_PRUEFBAR = 'nicht_pruefbar';

const DNS = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'EAI_NODATA', 'EAI_NONAME', 'ENODATA', 'ESERVFAIL', 'ENOTIMP', 'EREFUSED', 'ECONNREFUSED_DNS']);
const NETZ = new Set(['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE', 'ETIMEDOUT', 'ECONNABORTED', 'EADDRNOTAVAIL', 'ENETDOWN', 'EHOSTDOWN']);
// Fehler, die der eigene Client erzeugt, bevor der Server etwas entscheiden konnte
const LOKAL = new Set(['ERR_SSL_NO_CIPHER_MATCH', 'ERR_SSL_NO_CIPHERS_AVAILABLE', 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'ERR_CRYPTO_OPERATION_FAILED',
  'ERR_INVALID_ARG_VALUE', 'ERR_INVALID_ARG_TYPE', 'ERR_SSL_UNSUPPORTED_SSL_VERSION', 'ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM', 'ERR_SSL_NO_SUITABLE_GROUPS']);
// TLS-Alarme des Servers, die Ablehnung des Angebots bedeuten (RFC 8446, Abschn. 6.2; RFC 5246, Abschn. 7.2.2)
const ABLEHNUNGS_ALARME = { HANDSHAKE_FAILURE: 'handshake_failure (40)', PROTOCOL_VERSION: 'protocol_version (70)', INSUFFICIENT_SECURITY: 'insufficient_security (71)' };

function alarmName(code) {
  const m = /^ERR_SSL_(?:SSLV3|TLSV1|SSL\/TLS)_ALERT_(.+)$/.exec(code || '');
  return m ? m[1] : null;
}

// fehler: Error-Objekt oder { code, message, zeitueberschreitung, lokal }
function einordnen(fehler) {
  if (!fehler) return { status: NICHT_PRUEFBAR, art: 'unklar', grund: 'unbekannter Fehler' };
  const code = fehler.code || '';
  const text = String(fehler.message || '').replace(/^[0-9A-F]+:error:/, '').slice(0, 160);
  if (fehler.zeitueberschreitung) return { status: NICHT_PRUEFBAR, art: 'zeit', grund: `Zeitüberschreitung nach ${fehler.zeitueberschreitung} ms ohne Antwort` };
  if (fehler.lokal) return { status: NICHT_PRUEFBAR, art: 'lokal', grund: `lokale Werkzeuggrenze: ${fehler.lokal}${code ? ` (${code})` : ''}` };
  if (DNS.has(code) || /getaddrinfo|queryA|querySrv/.test(text)) return { status: NICHT_PRUEFBAR, art: 'dns', grund: `DNS-Fehler (${code || text})` };
  if (code === 'ENOENT') return { status: NICHT_PRUEFBAR, art: 'lokal', grund: `lokale Werkzeuggrenze: Programm nicht gefunden (${text})` };
  if (LOKAL.has(code)) return { status: NICHT_PRUEFBAR, art: 'lokal', grund: `lokale Werkzeuggrenze: das Prüfsystem kann dieses Angebot nicht senden (${code})` };
  const alarm = alarmName(code);
  if (alarm && ABLEHNUNGS_ALARME[alarm]) return { status: ABGELEHNT, art: 'tls_alarm', grund: `Server lehnt mit TLS-Alarm ${ABLEHNUNGS_ALARME[alarm]} ab` };
  if (alarm) return { status: NICHT_PRUEFBAR, art: 'tls_alarm_unklar', grund: `Server sendet TLS-Alarm ${alarm.toLowerCase()}; keine eindeutige Ablehnung` };
  if (code === 'ERR_SSL_UNSUPPORTED_PROTOCOL') return { status: ABGELEHNT, art: 'andere_version', grund: 'Server antwortet mit einer anderen Protokollversion' };
  if (NETZ.has(code) || /socket disconnected|socket hang up/i.test(text))
    return { status: NICHT_PRUEFBAR, art: 'netz', grund: `Verbindung ohne TLS-Alarm beendet oder nicht möglich (${code || text})` };
  return { status: NICHT_PRUEFBAR, art: 'unklar', grund: `nicht eindeutig: ${code || text || 'unbekannter Fehler'}` };
}

const istNetzartig = e => e && ['zeit', 'dns', 'netz'].includes(e.art);

module.exports = { einordnen, istNetzartig, ANGEBOTEN, ABGELEHNT, NICHT_PRUEFBAR };
