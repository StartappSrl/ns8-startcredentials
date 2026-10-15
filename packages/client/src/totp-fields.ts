/**
 * Campi OTP nel formato nativo di KeePass 2.47+ (usato anche dall'export KDBX
 * di Passbolt): TimeOtp-Secret[-Hex|-Base32|-Base64], TimeOtp-Algorithm,
 * TimeOtp-Length, TimeOtp-Period. Li trasformiamo in un URI otpauth standard.
 */
import type { ItemData } from "@startcredentials/crypto";

export const KEEPASS_TOTP_FIELDS = [
  "TimeOtp-Secret", "TimeOtp-Secret-Hex", "TimeOtp-Secret-Base32", "TimeOtp-Secret-Base64",
  "TimeOtp-Algorithm", "TimeOtp-Length", "TimeOtp-Period",
];

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function secretToBase32(get: (name: string) => string | undefined): string | undefined {
  const b32 = get("TimeOtp-Secret-Base32")?.replace(/[\s=-]/g, "").toUpperCase();
  if (b32 && /^[A-Z2-7]+$/.test(b32)) return b32;
  const hex = get("TimeOtp-Secret-Hex")?.replace(/\s/g, "");
  if (hex && /^([0-9a-fA-F]{2})+$/.test(hex)) return base32(new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16))));
  const b64 = get("TimeOtp-Secret-Base64")?.trim();
  if (b64) {
    try {
      return base32(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    } catch {
      /* non valido */
    }
  }
  const raw = get("TimeOtp-Secret");
  if (raw) return base32(new TextEncoder().encode(raw));
  return undefined;
}

/** URI otpauth dai campi KeePass, se presenti. */
export function keepassTotpUri(get: (name: string) => string | undefined, label: string): string | undefined {
  const secret = secretToBase32(get);
  if (!secret) return undefined;
  const alg = (get("TimeOtp-Algorithm") ?? "").toUpperCase().replace("HMAC-", "").replace("-", "");
  const params = new URLSearchParams({ secret });
  if (alg === "SHA256" || alg === "SHA512") params.set("algorithm", alg);
  const digits = Number(get("TimeOtp-Length"));
  if (digits === 7 || digits === 8) params.set("digits", String(digits));
  const period = Number(get("TimeOtp-Period"));
  if (Number.isInteger(period) && period >= 10 && period <= 300 && period !== 30) params.set("period", String(period));
  return `otpauth://totp/${encodeURIComponent(label || "OTP")}?${params}`;
}

/**
 * OTP effettivo di un elemento: il campo OTP vero e proprio, oppure quello
 * ricavato dai campi KeePass degli elementi importati prima del supporto.
 */
export function effectiveTotpUri(d: ItemData): string | undefined {
  if (d.totpUri) return d.totpUri;
  if (!d.fields?.some((f) => f.label.startsWith("TimeOtp-Secret"))) return undefined;
  return keepassTotpUri((n) => d.fields!.find((f) => f.label === n)?.value, d.name);
}
