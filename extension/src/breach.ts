/**
 * Controllo delle password comparse in violazioni note (Have I Been Pwned, Pwned Passwords).
 *
 * Anonimato a k: dal computer esce solo l'inizio (5 caratteri esadecimali) dell'impronta
 * SHA-1 della password; il servizio risponde con le centinaia di impronte che iniziano
 * così e il confronto avviene qui. Con "Add-Padding" la risposta ha sempre una lunghezza
 * simile, così nemmeno la dimensione rivela qualcosa. Password e impronta intera non
 * lasciano mai il computer.
 */

export const PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/";

export async function sha1Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/** Righe "SUFFISSO:CONTEGGIO"; le righe di riempimento hanno conteggio 0. */
export function parseRange(body: string): Map<string, number> {
  const m = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(":");
    const n = Number(count);
    if (suffix && /^[0-9A-F]{35}$/i.test(suffix) && n > 0) m.set(suffix.toUpperCase(), n);
  }
  return m;
}

/**
 * Quante volte compare ciascuna password nelle violazioni note (0 = mai).
 * Password uguali e prefissi uguali vengono interrogati una volta sola.
 */
export async function pwnedCounts(
  passwords: string[],
  opts: { fetch?: typeof fetch; concurrency?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<Map<string, number>> {
  const f = opts.fetch ?? fetch.bind(globalThis);
  const unique = [...new Set(passwords.filter(Boolean))];
  const hashes = new Map<string, string>();
  for (const p of unique) hashes.set(p, await sha1Hex(p));
  const prefixes = [...new Set([...hashes.values()].map((h) => h.slice(0, 5)))];
  const ranges = new Map<string, Map<string, number>>();
  let done = 0;
  const queue = [...prefixes];
  const worker = async () => {
    for (let p = queue.shift(); p; p = queue.shift()) {
      const r = await f(`${PWNED_RANGE_URL}${p}`, { headers: { "Add-Padding": "true" }, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" });
      if (!r.ok) throw new Error(r.status === 429 ? "Il servizio di controllo è occupato: riprova tra un minuto" : `Servizio di controllo non raggiungibile (${r.status})`);
      ranges.set(p, parseRange(await r.text()));
      opts.onProgress?.(++done, prefixes.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency ?? 4, prefixes.length) }, worker));
  const out = new Map<string, number>();
  for (const [pw, h] of hashes) out.set(pw, ranges.get(h.slice(0, 5))?.get(h.slice(5)) ?? 0);
  return out;
}
