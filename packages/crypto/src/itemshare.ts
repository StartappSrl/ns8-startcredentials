/**
 * Condivisione di un singolo elemento: la sua chiave (IK) viene sigillata per
 * la chiave pubblica del destinatario e firmata da chi condivide. La versione
 * della IK è nel messaggio firmato: dopo una revoca la IK cambia e le
 * consegne vecchie non valgono più.
 */
import { assertSignature, sign, UserKeyPair } from "./keys.js";
import { CryptoError, fromB64, sodium, toB64, utf8 } from "./sodium.js";

export interface ItemShare {
  itemId: string;
  containerId: string;
  ikVersion: number;
  userId: string;
  sealedKey: string;
  grantedBy: string;
  signature: string;
}

export function itemShareMessage(s: Omit<ItemShare, "signature">): Uint8Array {
  const h = toB64(sodium().crypto_generichash(32, fromB64(s.sealedKey), null));
  return utf8(`sc:item-share:v1|${s.itemId}|${s.containerId}|${s.ikVersion}|${s.userId}|${s.grantedBy}|${h}`);
}

export function shareItemKey(p: {
  itemKey: Uint8Array; itemId: string; containerId: string; ikVersion: number; userId: string; userBoxPublic: string;
  grantor: { userId: string; keys: UserKeyPair };
}): ItemShare {
  const sealedKey = toB64(sodium().crypto_box_seal(p.itemKey, fromB64(p.userBoxPublic)));
  const unsigned = { itemId: p.itemId, containerId: p.containerId, ikVersion: p.ikVersion, userId: p.userId, sealedKey, grantedBy: p.grantor.userId };
  return { ...unsigned, signature: sign(itemShareMessage(unsigned), p.grantor.keys.signPrivate) };
}

export function openItemShare(s: ItemShare, me: { userId: string; keys: UserKeyPair }, grantorSignPublic: string): Uint8Array {
  if (s.userId !== me.userId) throw new CryptoError("invalid_input", "Condivisione non destinata a questo utente");
  const { signature, ...unsigned } = s;
  assertSignature(itemShareMessage(unsigned), signature, grantorSignPublic, "condivisione dell'elemento");
  try {
    return sodium().crypto_box_seal_open(fromB64(s.sealedKey), fromB64(me.keys.publicKeys.box), me.keys.boxPrivate);
  } catch {
    throw new CryptoError("decryption_failed", "Impossibile aprire la chiave dell'elemento");
  }
}
