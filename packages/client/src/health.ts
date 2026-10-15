/**
 * Rapporto sulla salute delle password, calcolato solo sul client.
 */
import type { Container, Item } from "./vault.js";
import { effectiveTotpUri } from "./totp-fields.js";

export function estimateBits(pw: string): number {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size;
  return Math.log2(Math.max(pool, 1)) * Math.min(pw.length, unique * 2);
}

export interface HealthEntry { container: Container; item: Item }
export interface HealthReport {
  checked: number;
  weak: HealthEntry[];
  reused: HealthEntry[][];
  old: HealthEntry[];
  missingOtp: HealthEntry[];
}

export function passwordHealth(entries: HealthEntry[], opts: { oldDays?: number; now?: number } = {}): HealthReport {
  const now = opts.now ?? Date.now();
  const oldMs = (opts.oldDays ?? 365) * 86400_000;
  const withPw = entries.filter((e) => e.item.data.password && !e.item.deletedAt);
  const byPw = new Map<string, HealthEntry[]>();
  for (const e of withPw) {
    const list = byPw.get(e.item.data.password!) ?? [];
    list.push(e);
    byPw.set(e.item.data.password!, list);
  }
  return {
    checked: withPw.length,
    weak: withPw.filter((e) => estimateBits(e.item.data.password!) < 60),
    reused: [...byPw.values()].filter((l) => l.length > 1),
    old: withPw.filter((e) => now - new Date(e.item.updatedAt).getTime() > oldMs),
    // Siti amministrativi senza secondo fattore salvato: da valutare, non per forza un problema.
    missingOtp: withPw.filter((e) => !effectiveTotpUri(e.item.data) && (e.item.data.urls ?? []).some((u) => /admin|portal|console|login/i.test(u))),
  };
}
