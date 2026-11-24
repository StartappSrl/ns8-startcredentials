/**
 * Invii sicuri: cifratura con funzioni standard del browser (WebCrypto), così il
 * destinatario esterno li apre da una semplice pagina senza librerie.
 * Formato (identico in app/public/send.js):
 *   chiave = PBKDF2-SHA256(codice, sale 16 byte, 600.000 iterazioni) → AES-256-GCM
 *   dati   = AES-GCM(JSON, iv 12 byte, AAD "sc:send:v1")
 * Il codice di accesso (16 caratteri, ~80 bit) resta al mittente e non va mai al server.
 */
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const AAD = new TextEncoder().encode("sc:send:v1");
const ITERATIONS = 600_000;

export interface SendPayload {
  v: 1;
  name: string;
  username?: string;
  password?: string;
  urls?: string[];
  notes?: string;
  totpUri?: string;
}
export interface SendEnvelope { v: 1; alg: "pbkdf2-sha256-600000/aes-256-gcm"; salt: string; iv: string; data: string }

const b64 = (u: Uint8Array) => { let s = ""; for (const x of u) s += String.fromCharCode(x); return btoa(s); };
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

/** Codice di accesso casuale, es. "K7QM-3XPA-RT9C-HWZN" (senza caratteri ambigui). */
export function newAccessCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const raw = [...bytes].map((b) => ALPHABET[b % 32]).join("");
  return raw.match(/.{4}/g)!.join("-");
}

export const normalizeAccessCode = (c: string) => c.toUpperCase().replace(/[\s-]/g, "");

async function deriveKey(code: string, salt: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  const base = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(normalizeAccessCode(code)), "PBKDF2", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt as BufferSource, iterations: ITERATIONS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, [usage]);
}

export async function encryptSend(payload: SendPayload, code: string): Promise<SendEnvelope> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(code, salt, "encrypt");
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD },
    key, new TextEncoder().encode(JSON.stringify(payload))));
  return { v: 1, alg: "pbkdf2-sha256-600000/aes-256-gcm", salt: b64(salt), iv: b64(iv), data: b64(ct) };
}

export async function decryptSend(env: SendEnvelope, code: string): Promise<SendPayload> {
  const key = await deriveKey(code, unb64(env.salt), "decrypt");
  const pt = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(env.iv) as BufferSource, additionalData: AAD }, key, unb64(env.data) as BufferSource);
  return JSON.parse(new TextDecoder().decode(pt)) as SendPayload;
}

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
