/**
 * Elementi (password, OTP, note, file): ogni elemento ha una propria chiave
 * (IK) cifrata con la CK. Così un elemento si può condividere da solo e la
 * rotazione della CK ricifra solo le IK, non i dati.
 */
import { newSymmetricKey, open, seal } from "./envelope.js";
import { fromUtf8, utf8, wipe } from "./sodium.js";

export type ItemType = "login" | "totp" | "note" | "file" | "ssh_key";

export interface ItemData {
  type: ItemType;
  name: string;
  username?: string;
  password?: string;
  urls?: string[];
  totpUri?: string;
  notes?: string;
  fields?: { label: string; value: string; secret: boolean }[];
}

export interface EncryptedItem {
  ikEnc: string;
  dataEnc: string;
}

const ikContext = (containerId: string, itemId: string) => `sc:item-key:v1:${containerId}:${itemId}`;
const dataContext = (containerId: string, itemId: string) => `sc:item-data:v1:${containerId}:${itemId}`;

export function encryptItem(
  containerKey: Uint8Array,
  ckVersion: number,
  containerId: string,
  itemId: string,
  data: ItemData,
): EncryptedItem {
  const ik = newSymmetricKey();
  const plain = utf8(JSON.stringify(data));
  try {
    return {
      ikEnc: seal(containerKey, ik, ikContext(containerId, itemId), `ck:${containerId}:${ckVersion}`),
      dataEnc: seal(ik, plain, dataContext(containerId, itemId), `ik:${itemId}`),
    };
  } finally {
    wipe(ik);
    wipe(plain);
  }
}

export function openItemKey(containerKey: Uint8Array, containerId: string, itemId: string, ikEnc: string): Uint8Array {
  return open(containerKey, ikEnc, ikContext(containerId, itemId));
}

export function decryptItem(containerKey: Uint8Array, containerId: string, itemId: string, item: EncryptedItem): ItemData {
  const ik = openItemKey(containerKey, containerId, itemId, item.ikEnc);
  let plain: Uint8Array | undefined;
  try {
    plain = open(ik, item.dataEnc, dataContext(containerId, itemId));
    return JSON.parse(fromUtf8(plain)) as ItemData;
  } finally {
    wipe(ik);
    wipe(plain);
  }
}

/** Aggiorna i dati riusando la IK esistente (le condivisioni singole restano valide). */
export function reencryptItemData(ik: Uint8Array, containerId: string, itemId: string, data: ItemData): string {
  const plain = utf8(JSON.stringify(data));
  try {
    return seal(ik, plain, dataContext(containerId, itemId), `ik:${itemId}`);
  } finally {
    wipe(plain);
  }
}

/** Rotazione: ricifra la IK dalla vecchia alla nuova CK. I dati non cambiano. */
export function rewrapItemKey(
  oldKey: Uint8Array,
  newKey: Uint8Array,
  newVersion: number,
  containerId: string,
  itemId: string,
  ikEnc: string,
): string {
  const ik = openItemKey(oldKey, containerId, itemId, ikEnc);
  try {
    return seal(newKey, ik, ikContext(containerId, itemId), `ck:${containerId}:${newVersion}`);
  } finally {
    wipe(ik);
  }
}
