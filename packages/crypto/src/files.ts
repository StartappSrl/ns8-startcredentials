/**
 * Allegati cifrati a blocchi con libsodium secretstream
 * (XChaCha20-Poly1305): rileva blocchi alterati, riordinati o mancanti,
 * incluso il troncamento finale.
 */
import { CryptoError, sodium, utf8 } from "./sodium.js";

export const CHUNK_SIZE = 1024 * 1024;

export interface EncryptedFile {
  header: Uint8Array;
  chunks: Uint8Array[];
}

const fileAd = (attachmentId: string) => utf8(`sc:file:v1:${attachmentId}`);

export function newFileKey(): Uint8Array {
  return sodium().crypto_secretstream_xchacha20poly1305_keygen();
}

export function encryptFile(fileKey: Uint8Array, attachmentId: string, data: Uint8Array, chunkSize = CHUNK_SIZE): EncryptedFile {
  const s = sodium();
  const { state, header } = s.crypto_secretstream_xchacha20poly1305_init_push(fileKey);
  const ad = fileAd(attachmentId);
  const chunks: Uint8Array[] = [];
  const count = Math.max(1, Math.ceil(data.length / chunkSize));
  for (let i = 0; i < count; i++) {
    const part = data.subarray(i * chunkSize, (i + 1) * chunkSize);
    const tag = i === count - 1
      ? s.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    chunks.push(s.crypto_secretstream_xchacha20poly1305_push(state, part, ad, tag));
  }
  return { header, chunks };
}

export function decryptFile(fileKey: Uint8Array, attachmentId: string, file: EncryptedFile): Uint8Array {
  const s = sodium();
  const state = s.crypto_secretstream_xchacha20poly1305_init_pull(file.header, fileKey);
  const ad = fileAd(attachmentId);
  const parts: Uint8Array[] = [];
  let finished = false;
  for (const chunk of file.chunks) {
    if (finished) throw new CryptoError("decryption_failed", "Dati presenti dopo il blocco finale");
    const r = s.crypto_secretstream_xchacha20poly1305_pull(state, chunk, ad) as
      | { message: Uint8Array; tag: number }
      | false;
    if (!r) throw new CryptoError("decryption_failed", "Blocco dell'allegato alterato o fuori ordine");
    parts.push(r.message);
    if (r.tag === s.crypto_secretstream_xchacha20poly1305_TAG_FINAL) finished = true;
  }
  if (!finished) throw new CryptoError("file_truncated", "Allegato incompleto: manca il blocco finale");
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
