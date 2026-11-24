/**
 * Invio sicuro: messaggio e collegamento WhatsApp con il solo codice di accesso.
 * Stessa logica di packages/client/src/send.ts (l'app non carica il pacchetto client:
 * tutto ciò che è cifratura gira nel motore della WebView). Il test del motore
 * verifica che le due copie diano gli stessi risultati.
 */

/**
 * Numero per wa.me: solo cifre con prefisso internazionale.
 * "+39 333…", "0039 333…" e i cellulari italiani senza prefisso ("333…") diventano "39333…".
 * Restituisce "" se vuoto, null se non valido.
 */
export function whatsappNumber(raw: string): string | null {
  let s = raw.replace(/[\s().-]/g, "");
  if (!s) return "";
  if (s.startsWith("+")) s = s.slice(1);
  else if (s.startsWith("00")) s = s.slice(2);
  else if (/^3\d{8,9}$/.test(s)) s = `39${s}`;
  return /^[1-9]\d{7,14}$/.test(s) ? s : null;
}

/** Messaggio con il solo codice: il collegamento all'invio resta nell'email (due canali separati). */
export function accessCodeMessage(code: string): string {
  return `Ciao, ti ho appena inviato per email un collegamento sicuro (StartCredentials). Per aprirlo usa questo codice: ${code}`;
}

/** Collegamento WhatsApp con il solo codice. */
export function whatsappCodeLink(code: string, phone: string): string {
  return `https://wa.me/${phone}?text=${encodeURIComponent(accessCodeMessage(code))}`;
}
