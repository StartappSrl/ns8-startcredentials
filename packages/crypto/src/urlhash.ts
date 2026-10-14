/**
 * Hash dei domini per la ricerca autofill: il server confronta hash senza
 * conoscere gli URL. La chiave deriva dalla CK, quindi gli hash di due
 * contenitori diversi non sono confrontabili tra loro.
 */
import { deriveSubkey } from "./kdf.js";
import { CryptoError, sodium, toB64, utf8, wipe } from "./sodium.js";

export function normalizeHost(input: string): string {
  let host = input.trim().toLowerCase();
  if (host.includes("://")) {
    try {
      host = new URL(host).hostname;
    } catch {
      throw new CryptoError("invalid_input", "URL non valido");
    }
  }
  host = host.replace(/\.$/, "");
  if (!host || /[\s/]/.test(host)) throw new CryptoError("invalid_input", "Nome host non valido");
  return host;
}

export function hostHash(containerKey: Uint8Array, hostOrUrl: string): string {
  const key = deriveSubkey(containerKey, 2, "scurlhsh");
  try {
    return toB64(sodium().crypto_generichash(32, utf8(`sc:host:v1:${normalizeHost(hostOrUrl)}`), key));
  } finally {
    wipe(key);
  }
}
