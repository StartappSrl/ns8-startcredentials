/**
 * Gruppi. Ogni gruppo ha una coppia X25519 certificata dall'organizzazione.
 * - La chiave privata del gruppo è consegnata a ogni membro (sigillo + firma).
 * - Un contenitore condiviso con il gruppo ha la sua CK sigillata per la chiave
 *   pubblica del gruppo, firmata da chi concede.
 * Tutti i messaggi firmati includono l'hash del sigillo: il server non può
 * scambiare chiavi né alterare permessi o ruoli.
 */
import { assertSignature, sign, UserKeyPair } from "./keys.js";
import { CryptoError, fromB64, sodium, toB64, utf8 } from "./sodium.js";
import type { Permission } from "./container.js";

export type GroupRole = "member" | "manager";

export interface GroupKeyPair {
  boxPublic: string;
  boxPrivate: Uint8Array;
}

export function generateGroupKeys(): GroupKeyPair {
  const k = sodium().crypto_box_keypair();
  return { boxPublic: toB64(k.publicKey), boxPrivate: k.privateKey };
}

const h = (sealed: string) => toB64(sodium().crypto_generichash(32, fromB64(sealed), null));

// ------------------------------------------------------------------ certificazione

export function groupCertMessage(groupId: string, keyVersion: number, boxPublic: string): Uint8Array {
  return utf8(`sc:group-cert:v1|${groupId}|${keyVersion}|${boxPublic}`);
}

export function certifyGroup(groupId: string, keyVersion: number, boxPublic: string, orgSignPrivate: Uint8Array): string {
  return sign(groupCertMessage(groupId, keyVersion, boxPublic), orgSignPrivate);
}

export function verifyGroupCert(groupId: string, keyVersion: number, boxPublic: string, certification: string, orgSignPublic: string): void {
  assertSignature(groupCertMessage(groupId, keyVersion, boxPublic), certification, orgSignPublic, "certificazione del gruppo");
}

// ------------------------------------------------------------------ membri

export interface GroupMemberGrant {
  groupId: string;
  keyVersion: number;
  userId: string;
  role: GroupRole;
  sealedKey: string;
  grantedBy: string;
  signature: string;
}

export function groupMemberMessage(g: Omit<GroupMemberGrant, "signature">): Uint8Array {
  return utf8(`sc:group-member:v1|${g.groupId}|${g.keyVersion}|${g.userId}|${g.role}|${g.grantedBy}|${h(g.sealedKey)}`);
}

export function grantGroupMembership(p: {
  groupId: string; keyVersion: number; groupPrivate: Uint8Array; userId: string; userBoxPublic: string;
  role: GroupRole; grantor: { userId: string; keys: UserKeyPair };
}): GroupMemberGrant {
  const sealedKey = toB64(sodium().crypto_box_seal(p.groupPrivate, fromB64(p.userBoxPublic)));
  const unsigned = { groupId: p.groupId, keyVersion: p.keyVersion, userId: p.userId, role: p.role, sealedKey, grantedBy: p.grantor.userId };
  return { ...unsigned, signature: sign(groupMemberMessage(unsigned), p.grantor.keys.signPrivate) };
}

/** Apre la chiave privata del gruppo e controlla che corrisponda alla pubblica certificata. */
export function openGroupMembership(g: GroupMemberGrant, me: { userId: string; keys: UserKeyPair }, grantorSignPublic: string, groupBoxPublic: string): Uint8Array {
  if (g.userId !== me.userId) throw new CryptoError("invalid_input", "La chiave del gruppo non è destinata a questo utente");
  const { signature, ...unsigned } = g;
  assertSignature(groupMemberMessage(unsigned), signature, grantorSignPublic, "consegna della chiave del gruppo");
  const s = sodium();
  let priv: Uint8Array;
  try {
    priv = s.crypto_box_seal_open(fromB64(g.sealedKey), fromB64(me.keys.publicKeys.box), me.keys.boxPrivate);
  } catch {
    throw new CryptoError("decryption_failed", "Impossibile aprire la chiave del gruppo");
  }
  if (toB64(s.crypto_scalarmult_base(priv)) !== groupBoxPublic) {
    throw new CryptoError("invalid_signature", "La chiave del gruppo non corrisponde a quella certificata");
  }
  return priv;
}

// ------------------------------------------------------------------ contenitori condivisi con un gruppo

export interface GroupContainerGrant {
  containerId: string;
  keyVersion: number;
  groupId: string;
  groupKeyVersion: number;
  permission: Permission;
  sealedKey: string;
  grantedBy: string;
  signature: string;
}

export function groupContainerMessage(g: Omit<GroupContainerGrant, "signature">): Uint8Array {
  return utf8(`sc:group-grant:v1|${g.containerId}|${g.keyVersion}|${g.groupId}|${g.groupKeyVersion}|${g.permission}|${g.grantedBy}|${h(g.sealedKey)}`);
}

export function grantContainerToGroup(p: {
  containerKey: Uint8Array; containerId: string; keyVersion: number; groupId: string; groupKeyVersion: number;
  groupBoxPublic: string; permission: Permission; grantor: { userId: string; keys: UserKeyPair };
}): GroupContainerGrant {
  const sealedKey = toB64(sodium().crypto_box_seal(p.containerKey, fromB64(p.groupBoxPublic)));
  const unsigned = {
    containerId: p.containerId, keyVersion: p.keyVersion, groupId: p.groupId, groupKeyVersion: p.groupKeyVersion,
    permission: p.permission, sealedKey, grantedBy: p.grantor.userId,
  };
  return { ...unsigned, signature: sign(groupContainerMessage(unsigned), p.grantor.keys.signPrivate) };
}

export function openGroupContainerKey(g: GroupContainerGrant, groupBoxPublic: string, groupPrivate: Uint8Array, grantorSignPublic: string): Uint8Array {
  const { signature, ...unsigned } = g;
  assertSignature(groupContainerMessage(unsigned), signature, grantorSignPublic, "condivisione con il gruppo");
  try {
    return sodium().crypto_box_seal_open(fromB64(g.sealedKey), fromB64(groupBoxPublic), groupPrivate);
  } catch {
    throw new CryptoError("decryption_failed", "Impossibile aprire la chiave del contenitore tramite il gruppo");
  }
}
