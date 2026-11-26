/**
 * H2 — cifratura dei metadati di cache a riposo (vedi PWA-MOBILE-SCOPING-2026-11-26.md,
 * Appendice A). Protegge la PII di metadati (es. la rubrica `/users/directory`: email e
 * nomi dei colleghi) su dispositivo condiviso/compromesso. I segreti veri restano comunque
 * avvolti; `/me` resta in chiaro perché serve al bootstrap dello sblocco offline.
 *
 * La `cacheKey` (AES-GCM 256) è derivata via WebCrypto HKDF-SHA256 dal materiale di chiave
 * che il Vault già tiene in RAM (`vault.serialize().keys`), con `info` dedicata. È
 * **non estraibile** e vive **solo in RAM** accanto al Vault: azzerata a lock/logout.
 * Non introduce un secondo passaggio Argon2id e non tocca l'SDK E2EE condiviso.
 */

const IV_BYTES = 12;
const enc = new TextEncoder();
const INFO = enc.encode("startcredentials-pwa-cache-v1");

const b64ToBytes = (s: string): Uint8Array => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const bytesToB64 = (b: Uint8Array): string => {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
};

/** Deriva la chiave di cifratura della cache dal materiale di chiave del Vault (b64). */
export async function deriveCacheKey(serializedKeysB64: string): Promise<CryptoKey> {
  const ikm = b64ToBytes(serializedKeysB64);
  try {
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: INFO },
      base,
      { name: "AES-GCM", length: 256 },
      false, // non estraibile
      ["encrypt", "decrypt"],
    );
  } finally {
    ikm.fill(0);
  }
}

/** Cifra i byte del corpo; restituisce b64 di (IV ‖ ciphertext). */
export async function sealBody(key: CryptoKey, body: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, body));
  const packed = new Uint8Array(iv.length + ct.length);
  packed.set(iv, 0);
  packed.set(ct, iv.length);
  return bytesToB64(packed);
}

/** Decifra b64 di (IV ‖ ciphertext); lancia se la chiave è errata o il dato è manomesso. */
export async function openBody(key: CryptoKey, packedB64: string): Promise<Uint8Array> {
  const packed = b64ToBytes(packedB64);
  const iv = packed.subarray(0, IV_BYTES);
  const ct = packed.subarray(IV_BYTES);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}
