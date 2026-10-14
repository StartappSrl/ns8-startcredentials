/**
 * Chiavi dell'utente: X25519 per ricevere chiavi cifrate, Ed25519 per firmare.
 * Le parti private sono salvate sul server solo cifrate con una sottochiave
 * della master key.
 */
import { open, seal } from "./envelope.js";
import { deriveSubkey } from "./kdf.js";
import { CryptoError, fromB64, fromUtf8, sodium, toB64, utf8, wipe } from "./sodium.js";

export interface PublicKeys {
  box: string; // X25519, base64url
  sign: string; // Ed25519, base64url
}

export interface UserKeyPair {
  publicKeys: PublicKeys;
  boxPrivate: Uint8Array;
  signPrivate: Uint8Array;
}

export function generateUserKeys(): UserKeyPair {
  const s = sodium();
  const box = s.crypto_box_keypair();
  const sign = s.crypto_sign_keypair();
  return {
    publicKeys: { box: toB64(box.publicKey), sign: toB64(sign.publicKey) },
    boxPrivate: box.privateKey,
    signPrivate: sign.privateKey,
  };
}

function privateKeyContext(userId: string, keyVersion: number): string {
  return `sc:user-private:v1:${userId}:${keyVersion}`;
}

/** Serializzazione delle chiavi private (da usare solo dentro una busta cifrata). */
export function serializePrivateKeys(keys: UserKeyPair): Uint8Array {
  return utf8(JSON.stringify({ box: toB64(keys.boxPrivate), sign: toB64(keys.signPrivate), pub: keys.publicKeys }));
}

export function parsePrivateKeys(data: Uint8Array): UserKeyPair {
  const parsed = JSON.parse(fromUtf8(data)) as { box: string; sign: string; pub: PublicKeys };
  const keys = { publicKeys: parsed.pub, boxPrivate: fromB64(parsed.box), signPrivate: fromB64(parsed.sign) };
  // Le chiavi pubbliche dichiarate devono corrispondere alle private.
  const s = sodium();
  if (toB64(s.crypto_scalarmult_base(keys.boxPrivate)) !== keys.publicKeys.box ||
      toB64(s.crypto_sign_ed25519_sk_to_pk(keys.signPrivate)) !== keys.publicKeys.sign) {
    throw new CryptoError("invalid_input", "Chiavi private e pubbliche non corrispondono");
  }
  return keys;
}

/** Cifra dati per una chiave pubblica X25519 (sigillo anonimo). */
export function sealToPublicKey(data: Uint8Array, boxPublic: string): string {
  return toB64(sodium().crypto_box_seal(data, fromB64(boxPublic)));
}

export function openSealed(sealed: string, boxPublic: string, boxPrivate: Uint8Array): Uint8Array {
  try {
    return sodium().crypto_box_seal_open(fromB64(sealed), fromB64(boxPublic), boxPrivate);
  } catch {
    throw new CryptoError("decryption_failed", "Impossibile aprire il sigillo");
  }
}

/** Coppia X25519 da una chiave privata (per la chiave di recupero ricomposta). */
export function boxPublicFromPrivate(boxPrivate: Uint8Array): string {
  return toB64(sodium().crypto_scalarmult_base(boxPrivate));
}

/** Cifra le chiavi private con la master key. Il risultato va al server. */
export function wrapPrivateKeys(masterKey: Uint8Array, keys: UserKeyPair, userId: string, keyVersion: number): string {
  const wrapKey = deriveSubkey(masterKey, 1, "scuserpk");
  const payload = serializePrivateKeys(keys);
  try {
    return seal(wrapKey, payload, privateKeyContext(userId, keyVersion), `user:${userId}:${keyVersion}`);
  } finally {
    wipe(wrapKey);
    wipe(payload);
  }
}

export function unwrapPrivateKeys(masterKey: Uint8Array, wrapped: string, userId: string, keyVersion: number): UserKeyPair {
  const wrapKey = deriveSubkey(masterKey, 1, "scuserpk");
  let payload: Uint8Array | undefined;
  try {
    payload = open(wrapKey, wrapped, privateKeyContext(userId, keyVersion));
    return parsePrivateKeys(payload);
  } finally {
    wipe(wrapKey);
    wipe(payload);
  }
}

/**
 * Impronta leggibile delle chiavi pubbliche, da confrontare a voce o di persona
 * prima di firmare la chiave di un nuovo utente: 8 gruppi di 4 cifre esadecimali.
 */
export function fingerprint(pub: PublicKeys): string {
  const s = sodium();
  const data = utf8(`sc:fingerprint:v1:${pub.box}:${pub.sign}`);
  const hex = s.to_hex(s.crypto_generichash(16, data, null));
  return hex.match(/.{4}/g)!.join(" ").toUpperCase();
}

export function sign(message: Uint8Array, signPrivate: Uint8Array): string {
  return toB64(sodium().crypto_sign_detached(message, signPrivate));
}

export function verify(message: Uint8Array, signature: string, signPublic: string): boolean {
  try {
    return sodium().crypto_sign_verify_detached(fromB64(signature), message, fromB64(signPublic));
  } catch {
    return false;
  }
}

export function assertSignature(message: Uint8Array, signature: string, signPublic: string, what: string): void {
  if (!verify(message, signature, signPublic)) {
    throw new CryptoError("invalid_signature", `Firma non valida: ${what}`);
  }
}

/** Messaggio canonico con cui l'organizzazione certifica le chiavi pubbliche di un utente. */
export function keyCertificationMessage(userId: string, keyVersion: number, pub: PublicKeys): Uint8Array {
  return utf8(`sc:key-cert:v1|${userId}|${keyVersion}|${pub.box}|${pub.sign}`);
}

export function certifyUserKeys(userId: string, keyVersion: number, pub: PublicKeys, orgSignPrivate: Uint8Array): string {
  return sign(keyCertificationMessage(userId, keyVersion, pub), orgSignPrivate);
}

export function verifyUserCertification(
  userId: string,
  keyVersion: number,
  pub: PublicKeys,
  certification: string,
  orgSignPublic: string,
): void {
  assertSignature(keyCertificationMessage(userId, keyVersion, pub), certification, orgSignPublic, "certificazione chiave utente");
}
