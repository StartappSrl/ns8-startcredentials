/**
 * Busta AEAD versionata (XChaCha20-Poly1305 IETF).
 *
 * Formato binario, poi codificato in base64url:
 *   [0]      versione formato (1)
 *   [1]      algoritmo (1 = XChaCha20-Poly1305-IETF)
 *   [2]      lunghezza id chiave (0-255)
 *   [3..]    id chiave (UTF-8)
 *   [..+24]  nonce casuale
 *   [..]     testo cifrato + tag
 *
 * I dati associati sono: intestazione binaria + contesto. Il contesto lega
 * il blob al record a cui appartiene (es. id contenitore e id elemento):
 * un blob copiato su un altro record non si decifra.
 */
import { CryptoError, fromB64, sodium, toB64, utf8 } from "./sodium.js";

export const ENVELOPE_VERSION = 1;
export const ALG_XCHACHA20POLY1305 = 1;
export const KEY_BYTES = 32;

export interface EnvelopeInfo {
  version: number;
  algorithm: number;
  keyId: string;
}

function header(keyId: string): Uint8Array {
  const id = utf8(keyId);
  if (id.length > 255) throw new CryptoError("invalid_input", "Id chiave troppo lungo");
  const h = new Uint8Array(3 + id.length);
  h[0] = ENVELOPE_VERSION;
  h[1] = ALG_XCHACHA20POLY1305;
  h[2] = id.length;
  h.set(id, 3);
  return h;
}

function associatedData(h: Uint8Array, context: string): Uint8Array {
  const ctx = utf8(context);
  const ad = new Uint8Array(h.length + ctx.length);
  ad.set(h, 0);
  ad.set(ctx, h.length);
  return ad;
}

function checkKey(key: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new CryptoError("invalid_input", `La chiave deve essere di ${KEY_BYTES} byte`);
  }
}

export function seal(key: Uint8Array, plaintext: Uint8Array, context: string, keyId: string): string {
  checkKey(key);
  const s = sodium();
  const h = header(keyId);
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, associatedData(h, context), null, nonce, key);
  const out = new Uint8Array(h.length + nonce.length + ct.length);
  out.set(h, 0);
  out.set(nonce, h.length);
  out.set(ct, h.length + nonce.length);
  return toB64(out);
}

export function inspect(envelope: string): EnvelopeInfo & { headerLength: number } {
  const raw = fromB64(envelope);
  if (raw.length < 3) throw new CryptoError("invalid_envelope", "Busta troppo corta");
  const version = raw[0]!;
  const algorithm = raw[1]!;
  const idLen = raw[2]!;
  if (version !== ENVELOPE_VERSION || algorithm !== ALG_XCHACHA20POLY1305) {
    throw new CryptoError("unsupported_version", `Versione ${version}/algoritmo ${algorithm} non supportati`);
  }
  if (raw.length < 3 + idLen + 24 + 16) throw new CryptoError("invalid_envelope", "Busta troncata");
  const keyId = new TextDecoder().decode(raw.subarray(3, 3 + idLen));
  return { version, algorithm, keyId, headerLength: 3 + idLen };
}

export function open(key: Uint8Array, envelope: string, context: string): Uint8Array {
  checkKey(key);
  const s = sodium();
  const info = inspect(envelope);
  const raw = fromB64(envelope);
  const h = raw.subarray(0, info.headerLength);
  const nonce = raw.subarray(info.headerLength, info.headerLength + 24);
  const ct = raw.subarray(info.headerLength + 24);
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, associatedData(h, context), nonce, key);
  } catch {
    throw new CryptoError("decryption_failed", "Decifratura non riuscita: chiave o contesto errati, oppure dati alterati");
  }
}

export function newSymmetricKey(): Uint8Array {
  return sodium().randombytes_buf(KEY_BYTES);
}
