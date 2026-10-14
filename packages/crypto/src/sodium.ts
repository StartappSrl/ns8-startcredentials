/**
 * Inizializzazione unica di libsodium. Ogni funzione pubblica del pacchetto
 * richiede che `initCrypto()` sia stata attesa almeno una volta.
 */
import sodiumModule from "libsodium-wrappers-sumo";

let readyPromise: Promise<void> | null = null;
let isReady = false;

export async function initCrypto(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodiumModule.ready.then(() => {
      isReady = true;
    });
  }
  return readyPromise;
}

export function sodium(): typeof sodiumModule {
  if (!isReady) {
    throw new CryptoError("not_initialized", "Chiamare e attendere initCrypto() prima dell'uso");
  }
  return sodiumModule;
}

export type CryptoErrorCode =
  | "not_initialized"
  | "invalid_envelope"
  | "unsupported_version"
  | "decryption_failed"
  | "weak_kdf_params"
  | "invalid_signature"
  | "invalid_input"
  | "file_truncated";

export class CryptoError extends Error {
  constructor(public readonly code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

export function toB64(data: Uint8Array): string {
  const s = sodium();
  return s.to_base64(data, s.base64_variants.URLSAFE_NO_PADDING);
}

export function fromB64(data: string): Uint8Array {
  const s = sodium();
  try {
    return s.from_base64(data, s.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new CryptoError("invalid_input", "Base64 non valido");
  }
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function fromUtf8(data: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(data);
}

/** Cancella il contenuto di un buffer sensibile. */
export function wipe(data: Uint8Array | undefined | null): void {
  if (data) sodium().memzero(data);
}
