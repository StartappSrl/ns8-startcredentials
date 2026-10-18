/**
 * TOTP (RFC 6238) calcolato solo sul client. HMAC con @noble/hashes (librerie
 * verificate da audit), identico in browser, estensione, Node.js e React Native.
 */
import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/legacy";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { CryptoError } from "./sodium.js";

export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

export interface TotpParams {
  secret: Uint8Array;
  algorithm: TotpAlgorithm;
  digits: 6 | 7 | 8;
  period: number;
  issuer?: string;
  account?: string;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  if (!/^[A-Z2-7]+$/.test(clean)) throw new CryptoError("invalid_input", "Segreto TOTP non in Base32");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function parseOtpauthUri(uri: string): TotpParams {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new CryptoError("invalid_input", "URI otpauth non valido");
  }
  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw new CryptoError("invalid_input", "Solo URI otpauth://totp/ sono supportati");
  }
  const secret = url.searchParams.get("secret");
  if (!secret) throw new CryptoError("invalid_input", "Parametro secret mancante");
  const alg = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  const algorithm: TotpAlgorithm = alg === "SHA256" ? "SHA-256" : alg === "SHA512" ? "SHA-512" : alg === "SHA1" ? "SHA-1" : (() => {
    throw new CryptoError("invalid_input", `Algoritmo ${alg} non supportato`);
  })();
  const digits = Number(url.searchParams.get("digits") ?? 6);
  if (digits !== 6 && digits !== 7 && digits !== 8) throw new CryptoError("invalid_input", "Cifre non supportate");
  const period = Number(url.searchParams.get("period") ?? 30);
  if (!Number.isInteger(period) || period < 10 || period > 300) throw new CryptoError("invalid_input", "Periodo non valido");
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, account] = label.includes(":") ? label.split(/:(.*)/s) : [undefined, label];
  return {
    secret: base32Decode(secret),
    algorithm,
    digits,
    period,
    issuer: url.searchParams.get("issuer") ?? labelIssuer,
    account: account?.trim() || undefined,
  };
}

export async function generateTotp(p: Pick<TotpParams, "secret" | "algorithm" | "digits" | "period">, timeMs = Date.now()): Promise<{ code: string; secondsLeft: number }> {
  if (p.secret.length === 0) throw new CryptoError("invalid_input", "Segreto TOTP vuoto");
  const counter = Math.floor(timeMs / 1000 / p.period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const hash = p.algorithm === "SHA-256" ? sha256 : p.algorithm === "SHA-512" ? sha512 : sha1;
  const mac = hmac(hash, p.secret, msg);
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  const code = String(bin % 10 ** p.digits).padStart(p.digits, "0");
  const secondsLeft = p.period - (Math.floor(timeMs / 1000) % p.period);
  return { code, secondsLeft };
}
