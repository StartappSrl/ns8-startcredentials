/**
 * Derivazione della master key dalla master password con Argon2id.
 * I parametri sono salvati per utente, così possono crescere nel tempo.
 */
import { CryptoError, fromB64, sodium, toB64, utf8 } from "./sodium.js";

export interface KdfParams {
  algorithm: "argon2id13";
  salt: string; // base64url, 16 byte
  opsLimit: number;
  memLimitBytes: number;
}

/** Valori predefiniti: 3 passate, 256 MiB. */
export const DEFAULT_OPS_LIMIT = 3;
export const DEFAULT_MEM_LIMIT = 256 * 1024 * 1024;
/** Minimi accettati (raccomandazione OWASP per Argon2id). */
export const MIN_OPS_LIMIT = 2;
export const MIN_MEM_LIMIT = 19 * 1024 * 1024;
export const MIN_PASSWORD_LENGTH = 12;

export function newKdfParams(opsLimit = DEFAULT_OPS_LIMIT, memLimitBytes = DEFAULT_MEM_LIMIT): KdfParams {
  const s = sodium();
  return {
    algorithm: "argon2id13",
    salt: toB64(s.randombytes_buf(s.crypto_pwhash_SALTBYTES)),
    opsLimit,
    memLimitBytes,
  };
}

export function validateKdfParams(p: KdfParams): void {
  if (p.algorithm !== "argon2id13") throw new CryptoError("weak_kdf_params", "Algoritmo KDF non supportato");
  if (p.opsLimit < MIN_OPS_LIMIT || p.memLimitBytes < MIN_MEM_LIMIT) {
    throw new CryptoError("weak_kdf_params", "Parametri Argon2id sotto il minimo consentito");
  }
  if (fromB64(p.salt).length !== sodium().crypto_pwhash_SALTBYTES) {
    throw new CryptoError("weak_kdf_params", "Salt di lunghezza errata");
  }
}

/** Restituisce la master key (32 byte). La password non lascia mai il dispositivo. */
export function deriveMasterKey(password: string, params: KdfParams): Uint8Array {
  validateKdfParams(params);
  const normalized = password.normalize("NFKC");
  if ([...normalized].length < MIN_PASSWORD_LENGTH) {
    throw new CryptoError("invalid_input", `La master password deve avere almeno ${MIN_PASSWORD_LENGTH} caratteri`);
  }
  const s = sodium();
  return s.crypto_pwhash(
    32,
    utf8(normalized),
    fromB64(params.salt),
    params.opsLimit,
    params.memLimitBytes,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Sottochiavi indipendenti derivate da una chiave radice (crypto_kdf, BLAKE2b).
 * Il contesto deve essere di esattamente 8 caratteri.
 */
export function deriveSubkey(root: Uint8Array, id: number, context: string): Uint8Array {
  if (context.length !== 8) throw new CryptoError("invalid_input", "Il contesto KDF deve avere 8 caratteri");
  return sodium().crypto_kdf_derive_from_key(32, id, context, root);
}
