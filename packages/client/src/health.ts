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

export const WEAK_BITS = 60;
export const isWeak = (pw: string) => estimateBits(pw) < WEAK_BITS;

/** Quando è stata cambiata la password l'ultima volta (per gli elementi vecchi: l'ultima modifica). */
export function passwordChangedAt(item: Pick<Item, "data" | "updatedAt">): string {
  return item.data.passwordChangedAt ?? item.updatedAt;
}

export const ROTATION_CHOICES = [30, 60, 90, 180, 365] as const;

/** Stato del promemoria di rotazione: null se non è impostato o non c'è password. */
export function rotationStatus(item: Pick<Item, "data" | "updatedAt">, now = Date.now()): { dueAt: Date; due: boolean; daysLeft: number } | null {
  const days = item.data.rotateDays;
  if (!days || !item.data.password) return null;
  const dueAt = new Date(new Date(passwordChangedAt(item)).getTime() + days * 86400_000);
  const daysLeft = Math.ceil((dueAt.getTime() - now) / 86400_000);
  return { dueAt, due: daysLeft <= 0, daysLeft };
}

export interface HealthEntry { container: Container; item: Item }
export interface HealthReport {
  checked: number;
  weak: HealthEntry[];
  reused: HealthEntry[][];
  old: HealthEntry[];
  /** Promemoria di rotazione scaduto. */
  rotation: HealthEntry[];
  missingOtp: HealthEntry[];
}

/**
 * `containerId` limita il rapporto a un cliente: le riutilizzate si cercano comunque
 * in tutto ciò che è leggibile (una password uguale in un altro cliente è un problema
 * anche per questo), ma si mostrano solo i gruppi che lo toccano.
 */
export function passwordHealth(entries: HealthEntry[], opts: { oldDays?: number; now?: number; containerId?: string } = {}): HealthReport {
  const now = opts.now ?? Date.now();
  const oldMs = (opts.oldDays ?? 365) * 86400_000;
  const all = entries.filter((e) => e.item.data.password && !e.item.deletedAt);
  const mine = (e: HealthEntry) => !opts.containerId || e.container.id === opts.containerId;
  const withPw = all.filter(mine);
  const byPw = new Map<string, HealthEntry[]>();
  for (const e of all) {
    const list = byPw.get(e.item.data.password!) ?? [];
    list.push(e);
    byPw.set(e.item.data.password!, list);
  }
  return {
    checked: withPw.length,
    weak: withPw.filter((e) => isWeak(e.item.data.password!)),
    reused: [...byPw.values()].filter((l) => l.length > 1 && l.some(mine)),
    // Con un promemoria di rotazione vale quello, non la soglia generica di un anno.
    old: withPw.filter((e) => !e.item.data.rotateDays && now - new Date(passwordChangedAt(e.item)).getTime() > oldMs),
    rotation: withPw.filter((e) => rotationStatus(e.item, now)?.due),
    // Siti amministrativi senza secondo fattore salvato: da valutare, non per forza un problema.
    missingOtp: withPw.filter((e) => !effectiveTotpUri(e.item.data) && (e.item.data.urls ?? []).some((u) => /admin|portal|console|login/i.test(u))),
  };
}
