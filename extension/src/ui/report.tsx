import { useState } from "preact/hooks";
import { Container, effectiveTotpUri, HealthReport, Item, passwordChangedAt, passwordHealth, rotationStatus, Vault } from "@startcredentials/client";
import { ACTION_LABEL, download } from "../shared";
import { ErrorNote, useAction } from "./kit";
import { loadAll } from "./tools";

/**
 * Rapporto di un cliente da consegnare o archiviare: elenco degli accessi custoditi
 * (mai le password) e registro di chi li ha visti o modificati.
 */

type AuditRow = Awaited<ReturnType<Vault["auditLog"]>>[number];
const TYPE_NAME: Record<Item["type"], string> = { login: "Password", totp: "OTP", note: "Nota sicura", file: "File", ssh_key: "Chiave SSH" };
const day = (d: string | Date) => new Date(d).toLocaleDateString("it-IT");
const stamp = (d: string | Date) => new Date(d).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" });
const yn = (b: boolean) => (b ? "sì" : "no");

/** Valore CSV sicuro: tra virgolette e senza formule eseguibili da Excel. */
export function csvCell(v: string | number): string {
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}
export function toCsv(rows: (string | number)[][]): Uint8Array {
  // BOM e punto e virgola: Excel in italiano lo apre già diviso in colonne.
  return new TextEncoder().encode(`﻿${rows.map((r) => r.map(csvCell).join(";")).join("\r\n")}\r\n`);
}
const esc = (v: string | number) => String(v).replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
const fileSafe = (s: string) => s.replace(/[^\p{L}\p{N} _-]+/gu, "").trim().replace(/\s+/g, "-").slice(0, 60) || "cliente";

interface ReportData {
  items: Item[];
  health: HealthReport;
  log: AuditRow[] | null;
  names: Map<string, string>;
}

function itemRows(d: ReportData, pathOf: (folderId: string | null) => string) {
  const weak = new Set(d.health.weak.map((e) => e.item.id));
  const reused = new Set(d.health.reused.flat().map((e) => e.item.id));
  return d.items.map((i) => {
    const r = rotationStatus(i);
    return {
      name: i.data.name, type: TYPE_NAME[i.type], folder: pathOf(i.folderId), username: i.data.username ?? "",
      urls: (i.data.urls ?? []).join(" "), otp: !!effectiveTotpUri(i.data), changed: i.data.password ? day(passwordChangedAt(i)) : "",
      rotate: i.data.rotateDays ? `ogni ${i.data.rotateDays} giorni` : "",
      rotateState: r ? (r.due ? "da cambiare" : `entro il ${day(r.dueAt)}`) : "",
      weak: weak.has(i.id), reused: reused.has(i.id), updated: day(i.updatedAt), by: i.updatedBy,
      files: i.attachments.length, shares: i.shares,
    };
  });
}

export function ReportDialog({ vault, container, pathOf, onClose }: {
  vault: Vault; container: Container; pathOf: (folderId: string | null) => string; onClose: () => void;
}) {
  const canLog = container.permission === "manage" || vault.me.role === "admin";
  const [days, setDays] = useState(90);
  const [progress, setProgress] = useState<string | null>(null);
  const { busy, error, run } = useAction();

  const collect = async (withLog: boolean): Promise<ReportData> => {
    setProgress("Decifratura degli elementi…");
    const all = await loadAll(vault);
    const items = all.filter((e) => e.container.id === container.id).map((e) => e.item)
      .sort((a, b) => `${pathOf(a.folderId)}\u0000${a.data.name}`.localeCompare(`${pathOf(b.folderId)}\u0000${b.data.name}`, "it"));
    const health = passwordHealth(all, { containerId: container.id });
    const names = new Map<string, string>();
    for (const i of items) names.set(i.id, i.data.name);
    let log: AuditRow[] | null = null;
    if (withLog && canLog) {
      for (const i of await vault.items(container.id, { trash: true }).catch(() => [] as Item[])) names.set(i.id, i.data.name);
      log = [];
      const since = Date.now() - days * 86400_000;
      let before: number | undefined;
      // Al massimo 20 pagine da 500 eventi: basta per qualsiasi cliente reale.
      for (let page = 0; page < 20; page++) {
        setProgress(`Lettura del registro… ${log.length} eventi`);
        const rows = await vault.auditLog({ containerId: container.id, before, limit: 500 });
        const recent = rows.filter((r) => new Date(r.at).getTime() >= since);
        log.push(...recent);
        if (rows.length < 500 || recent.length < rows.length) break;
        before = rows[rows.length - 1]!.id;
      }
    }
    setProgress(null);
    return { items, health, log, names };
  };

  const logRows = (d: ReportData) => (d.log ?? []).map((r) => {
    const itemId = r.targetType === "item" ? r.targetId : typeof r.details?.itemId === "string" ? r.details.itemId : null;
    return { at: stamp(r.at), who: r.actorName ?? (r.action === "send.opened" ? "Destinatario dell'invio sicuro" : "—"), what: ACTION_LABEL[r.action] ?? r.action, item: itemId ? d.names.get(itemId) ?? "(elemento eliminato)" : "", ip: r.ip ?? "" };
  });

  const base = `rapporto-${fileSafe(container.meta.name)}-${new Date().toISOString().slice(0, 10)}`;

  const csvItems = () => run(async () => {
    const d = await collect(false);
    const rows = itemRows(d, pathOf);
    download(toCsv([
      ["Elemento", "Tipo", "Cartella", "Nome utente", "Indirizzi", "OTP", "Password cambiata il", "Promemoria", "Stato promemoria", "Debole", "Usata anche altrove", "Ultima modifica", "Modificato da", "Allegati", "Condivisioni singole"],
      ...rows.map((r) => [r.name, r.type, r.folder, r.username, r.urls, yn(r.otp), r.changed, r.rotate, r.rotateState, yn(r.weak), yn(r.reused), r.updated, r.by, r.files, r.shares]),
    ]), `${base}-elementi.csv`, "text/csv");
  }).finally(() => setProgress(null));

  const csvLog = () => run(async () => {
    const d = await collect(true);
    download(toCsv([["Data", "Persona", "Azione", "Elemento", "Indirizzo IP"], ...logRows(d).map((r) => [r.at, r.who, r.what, r.item, r.ip])]), `${base}-registro.csv`, "text/csv");
  }).finally(() => setProgress(null));

  const printable = () => {
    // La finestra si apre subito (dentro il clic), poi si riempie: così il browser non la blocca.
    const w = window.open("", "_blank");
    if (!w) return void run(async () => { throw new Error("Il browser ha bloccato la nuova finestra: consentila e riprova."); });
    w.document.write("<p style='font-family:sans-serif'>Preparazione del rapporto…</p>");
    void run(async () => {
      const d = await collect(true);
      w.document.open();
      w.document.write(printableHtml(container, d, itemRows(d, pathOf), canLog ? logRows(d) : null, days));
      w.document.close();
      setTimeout(() => w.print(), 300);
      return true;
    }).then((ok) => { if (!ok) w.close(); }).finally(() => setProgress(null));
  };

  return (
    <div class="stack">
      <p>Il rapporto elenca gli accessi custoditi per <b>{container.meta.name}</b>, il loro stato e {canLog ? "chi li ha usati" : "quando sono stati cambiati"}. <b>Non contiene mai le password.</b></p>
      {canLog ? (
        <label class="field" style="max-width:260px">Registro degli accessi
          <select class="input" value={days} onChange={(e) => setDays(Number(e.currentTarget.value))}>
            <option value={30}>Ultimi 30 giorni</option>
            <option value={90}>Ultimi 90 giorni</option>
            <option value={365}>Ultimo anno</option>
          </select>
        </label>
      ) : <p class="small muted">Il registro degli accessi è incluso solo per chi gestisce il cliente.</p>}
      <ErrorNote error={error} />
      {progress && <p class="small muted" aria-live="polite">{progress}</p>}
      <div class="row" style="justify-content:flex-end">
        <button class="btn" onClick={onClose}>Chiudi</button>
        <button class="btn" disabled={busy} onClick={csvItems}>Elenco elementi (CSV)</button>
        {canLog && <button class="btn" disabled={busy} onClick={csvLog}>Registro accessi (CSV)</button>}
        <button class="btn primary" disabled={busy} onClick={printable}>Stampa o salva in PDF</button>
      </div>
    </div>
  );
}

function printableHtml(c: Container, d: ReportData, rows: ReturnType<typeof itemRows>, log: { at: string; who: string; what: string; item: string; ip: string }[] | null, days: number): string {
  const h = d.health;
  const reusedIds = new Set(h.reused.flat().filter((e) => e.container.id === c.id).map((e) => e.item.id));
  const stat = (label: string, n: number) => `<div class="stat"><div>${esc(label)}</div><b>${n}</b></div>`;
  const flags = (r: (typeof rows)[number]) => [r.weak && "debole", r.reused && "usata altrove", r.rotateState === "da cambiare" && "da cambiare"].filter(Boolean).join(", ");
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><title>Rapporto ${esc(c.meta.name)}</title><style>
    body{font:12px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111;margin:24px}
    h1{font-size:20px;margin:0}h2{font-size:15px;margin:22px 0 8px}.muted{color:#555}
    .stats{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.stat{border:1px solid #ccc;border-radius:6px;padding:8px 12px;min-width:110px}.stat b{font-size:18px}
    table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f2f2f2}
    .warn{color:#a40000;font-weight:600}@media print{body{margin:0}tr{break-inside:avoid}}
  </style></head><body>
  <h1>Rapporto accessi · ${esc(c.meta.name)}</h1>
  <div class="muted">${c.meta.sector ? `${esc(c.meta.sector)} · ` : ""}generato il ${esc(stamp(new Date()))} con StartCredentials. Il rapporto non contiene password.</div>
  <div class="stats">${stat("Elementi", rows.length)}${stat("Password analizzate", h.checked)}${stat("Deboli", h.weak.length)}${stat("Usate anche altrove", reusedIds.size)}${stat("Da cambiare", h.rotation.length)}${stat("Non cambiate da oltre un anno", h.old.length)}</div>
  <h2>Elementi custoditi</h2>
  <table><thead><tr><th>Elemento</th><th>Cartella</th><th>Nome utente</th><th>Tipo</th><th>OTP</th><th>Password cambiata</th><th>Promemoria</th><th>Da verificare</th></tr></thead><tbody>
  ${rows.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.folder)}</td><td>${esc(r.username)}</td><td>${esc(r.type)}</td><td>${yn(r.otp)}</td><td>${esc(r.changed)}</td><td>${esc([r.rotate, r.rotateState].filter(Boolean).join(" · "))}</td><td class="warn">${esc(flags(r))}</td></tr>`).join("") || `<tr><td colspan="8">Nessun elemento</td></tr>`}
  </tbody></table>
  ${log ? `<h2>Registro degli accessi · ultimi ${days} giorni</h2>
  <table><thead><tr><th>Data</th><th>Persona</th><th>Azione</th><th>Elemento</th><th>IP</th></tr></thead><tbody>
  ${log.map((r) => `<tr><td>${esc(r.at)}</td><td>${esc(r.who)}</td><td>${esc(r.what)}</td><td>${esc(r.item)}</td><td>${esc(r.ip)}</td></tr>`).join("") || `<tr><td colspan="5">Nessun evento nel periodo</td></tr>`}
  </tbody></table>` : ""}
  </body></html>`;
}
