/**
 * Chiavi dei contenitori (CK): una per contenitore e versione, consegnata a
 * ogni membro cifrata con la sua chiave pubblica X25519 (crypto_box_seal).
 * Il sigillo non autentica il mittente, quindi ogni consegna è firmata
 * Ed25519 da chi la concede e verificata dal destinatario.
 */
import { newSymmetricKey } from "./envelope.js";
import { assertSignature, PublicKeys, sign, UserKeyPair } from "./keys.js";
import { CryptoError, fromB64, sodium, toB64, utf8 } from "./sodium.js";

export type Permission = "read" | "write" | "manage";

export interface KeyGrant {
  containerId: string;
  keyVersion: number;
  recipientId: string;
  permission: Permission;
  sealedKey: string; // base64url
  grantedBy: string;
  signature: string; // Ed25519 di chi concede
}

export function newContainerKey(): Uint8Array {
  return newSymmetricKey();
}

export function grantMessage(g: Omit<KeyGrant, "signature">): Uint8Array {
  const s = sodium();
  const sealedHash = toB64(s.crypto_generichash(32, fromB64(g.sealedKey), null));
  return utf8(
    `sc:grant:v1|${g.containerId}|${g.keyVersion}|${g.recipientId}|${g.permission}|${g.grantedBy}|${sealedHash}`,
  );
}

/** Consegna la CK a un membro. `recipientPublic` deve essere già verificata (certificazione dell'organizzazione). */
export function grantContainerKey(params: {
  containerKey: Uint8Array;
  containerId: string;
  keyVersion: number;
  recipientId: string;
  recipientPublic: PublicKeys;
  permission: Permission;
  grantor: { userId: string; keys: UserKeyPair };
}): KeyGrant {
  const s = sodium();
  const sealed = s.crypto_box_seal(params.containerKey, fromB64(params.recipientPublic.box));
  const unsigned = {
    containerId: params.containerId,
    keyVersion: params.keyVersion,
    recipientId: params.recipientId,
    permission: params.permission,
    sealedKey: toB64(sealed),
    grantedBy: params.grantor.userId,
  };
  return { ...unsigned, signature: sign(grantMessage(unsigned), params.grantor.keys.signPrivate) };
}

/** Apre una consegna ricevuta, dopo averne verificato la firma. */
export function openContainerKey(grant: KeyGrant, me: { userId: string; keys: UserKeyPair }, grantorSignPublic: string): Uint8Array {
  if (grant.recipientId !== me.userId) {
    throw new CryptoError("invalid_input", "La consegna non è destinata a questo utente");
  }
  const { signature, ...unsigned } = grant;
  assertSignature(grantMessage(unsigned), signature, grantorSignPublic, "consegna chiave contenitore");
  const s = sodium();
  try {
    return s.crypto_box_seal_open(fromB64(grant.sealedKey), fromB64(me.keys.publicKeys.box), me.keys.boxPrivate);
  } catch {
    throw new CryptoError("decryption_failed", "Impossibile aprire la chiave del contenitore");
  }
}
