import { useMemo, useState } from "preact/hooks";
import { Container, HealthEntry, Item, passwordChangedAt, passwordHealth, Vault } from "@startcredentials/client";
import { relTime } from "../shared";
import { ErrorNote, useAction, useLoad } from "./kit";
import { pwnedCounts } from "../breach";

/** Tutti gli elementi leggibili, decifrati in locale. */
export async function loadAll(vault: Vault, withShared = false): Promise<HealthEntry[]> {
  const out: HealthEntry[] = [];
  for (const c of await vault.containers()) {
    if (c.kind === "org") continue;
    for (const item of await vault.items(c.id)) out.push({ container: c, item });
  }
  if (withShared) {
    for (const item of await vault.sharedWithMe().catch(() => [])) {
      out.push({ container: { id: item.containerId, kind: "client", keyVersion: 0, permission: "read", meta: { name: `Condivisa da ${item.sharedBy}` }, members: 0, items: 0, totpItems: 0, updatedAt: item.updatedAt, grantedBy: "", rotationRequired: false, groups: 0, viaGroups: [] }, item });
    }
  }
  return out;
}

const where = (c: Container) => (c.kind === "personal" ? "Area personale" : c.meta.name);

function Row({ container, item, note }: { container: Container; item: Item; note?: string }) {
  return (
    <a class="item-row" href={item.sharedBy ? `#/condivisi/i/${item.id}` : `#/c/${container.id}/i/${item.id}`} style="text-decoration:none;color:inherit">
      <span class="grow">
        <span class="ellipsis" style="display:block;font-weight:500">{item.data.name}</span>
        <span class="ellipsis small muted" style="display:block">{where(container)}{item.data.username ? ` · ${item.data.username}` : ""}</span>
      </span>
      {note && <span class="small muted">{note}</span>}
    </a>
  );
}

/** La ricerca resta quando si torna indietro dal dettaglio di un elemento. */
let lastQuery = "";

export function Search({ vault }: { vault: Vault }) {
  const all = useLoad(() => loadAll(vault, true), []);
  const [q, setQState] = useState(lastQuery);
  const setQ = (v: string) => { lastQuery = v; setQState(v); };
  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s || !all.data) return [];
    return all.data.filter(({ container, item }) =>
      [item.data.name, item.data.username, item.data.notes, container.meta.name, ...(item.data.urls ?? []), ...(item.data.fields ?? []).filter((f) => !f.secret).map((f) => f.value)]
        .some((v) => v?.toLowerCase().includes(s))).slice(0, 100);
  }, [q, all.data]);
  return (
    <>
      <h1>Cerca</h1>
      <input class="input" type="search" autoFocus aria-label="Cerca in tutti i clienti" placeholder="Nome, utente, indirizzo, cliente…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
      <ErrorNote error={all.error} />
      {!all.data && <p class="muted">Decifratura di tutti gli elementi…</p>}
      {all.data && q && (
        <div class="card list">
          {results.length === 0 ? <div class="empty">Nessun risultato</div> : results.map((r) => <Row {...r} />)}
        </div>
      )}
      {all.data && !q && <p class="muted small">{all.data.length} elementi in {new Set(all.data.map((e) => e.container.id)).size} contenitori. La ricerca avviene solo su questo computer.</p>}
    </>
  );
}

/** Risultati del controllo violazioni, solo in memoria e solo per questa sessione. */
const breachCache = new Map<string, number>();

/**
 * Controllo delle password comparse in violazioni note. Parte solo su richiesta,
 * perché contatta un servizio esterno (che riceve solo l'inizio dell'impronta).
 */
function BreachCheck({ entries }: { entries: HealthEntry[] }) {
  const withPw = entries.filter((e) => e.item.data.password && !e.item.deletedAt);
  const [, setTick] = useState(0);
  const [progress, setProgress] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const checked = withPw.filter((e) => breachCache.has(e.item.data.password!));
  const found = checked.filter((e) => (breachCache.get(e.item.data.password!) ?? 0) > 0)
    .sort((a, b) => (breachCache.get(b.item.data.password!) ?? 0) - (breachCache.get(a.item.data.password!) ?? 0));
  const allChecked = withPw.length > 0 && checked.length === withPw.length;
  const start = () => run(async () => {
    const todo = withPw.map((e) => e.item.data.password!).filter((p) => !breachCache.has(p));
    const r = await pwnedCounts(todo, { onProgress: (d, t) => setProgress(`Controllo ${d} di ${t}…`) });
    for (const [pw, n] of r) breachCache.set(pw, n);
    setTick((x) => x + 1);
  }).finally(() => setProgress(null));
  if (!withPw.length) return null;
  return (
    <section class="stack">
      <h2>Comparse in violazioni note</h2>
      <p class="small muted">
        Confronta le password con l'archivio pubblico delle password trapelate (Have I Been Pwned). Dal computer esce solo l'inizio
        dell'impronta di ogni password, mai la password: il confronto avviene qui.
      </p>
      {!allChecked && (
        <button class="btn" style="align-self:flex-start" disabled={busy} onClick={start}>
          {busy ? (progress ?? "Controllo…") : `Controlla ${withPw.length - checked.length} password online`}
        </button>
      )}
      <ErrorNote error={error} />
      {allChecked && found.length === 0 && <div class="notice ok">Nessuna password compare nelle violazioni note.</div>}
      {found.length > 0 && (
        <>
          <p class="small">Una password che compare in una violazione è nelle liste usate per indovinare le password: <b>va cambiata</b>, anche se è lunga.</p>
          <div class="card list">{found.map((e) => <Row {...e} note={`trovata ${breachCache.get(e.item.data.password!)!.toLocaleString("it-IT")} volte`} />)}</div>
        </>
      )}
    </section>
  );
}

export function Health({ vault, containerId }: { vault: Vault; containerId?: string }) {
  const all = useLoad(() => loadAll(vault), []);
  const report = useMemo(() => (all.data ? passwordHealth(all.data, { containerId }) : null), [all.data, containerId]);
  const clients = useMemo(() => {
    const m = new Map<string, Container>();
    for (const e of all.data ?? []) m.set(e.container.id, e.container);
    return [...m.values()].sort((a, b) => where(a).localeCompare(where(b), "it"));
  }, [all.data]);
  const scope = clients.find((c) => c.id === containerId);
  const reusedCount = report ? new Set(report.reused.flat().filter((e) => !containerId || e.container.id === containerId).map((e) => e.item.id)).size : 0;
  return (
    <>
      {scope && <div class="small muted"><a href="#/clienti">Clienti</a> / <a href={`#/c/${scope.id}`}>{where(scope)}</a> / Salute</div>}
      <div class="row between">
        <div class="stack" style="gap:4px">
          <h1>Salute delle password{scope ? ` · ${where(scope)}` : ""}</h1>
          <p class="muted">Analisi fatta solo su questo computer, sugli elementi che puoi leggere.</p>
        </div>
        {clients.length > 0 && (
          <label class="field" style="min-width:220px">Cliente
            <select class="input" aria-label="Cliente da analizzare" value={containerId ?? ""} onChange={(e) => { location.hash = e.currentTarget.value ? `/salute/${e.currentTarget.value}` : "/salute"; }}>
              <option value="">Tutti i clienti</option>
              {clients.map((c) => <option value={c.id}>{where(c)}</option>)}
            </select>
          </label>
        )}
      </div>
      <ErrorNote error={all.error} />
      {!report && <p class="muted">Analisi in corso…</p>}
      {report && (
        <>
          <div class="grid">
            {[
              ["Password analizzate", report.checked],
              ["Deboli", report.weak.length],
              ["Usate in più punti", reusedCount],
              ["Da cambiare (promemoria)", report.rotation.length],
              ["Non cambiate da oltre un anno", report.old.length],
            ].map(([l, n]) => (
              <div class="card pad"><div class="small muted">{l}</div><div class="mono" style="font-size:26px">{n}</div></div>
            ))}
          </div>
          <BreachCheck entries={(all.data ?? []).filter((e) => !containerId || e.container.id === containerId)} />
          {report.reused.length > 0 && (
            <section class="stack">
              <h2>Usate in più punti</h2>
              <p class="small muted">Se una viene compromessa, lo sono anche le altre: è il problema più urgente.{containerId ? " Sono cercate anche negli altri clienti." : ""}</p>
              {report.reused.map((g) => (
                <div class="card list">
                  <div class="group-h"><span>Stessa password in {g.length} elementi</span></div>
                  {g.map((e) => <Row {...e} />)}
                </div>
              ))}
            </section>
          )}
          {report.rotation.length > 0 && (
            <section class="stack">
              <h2>Da cambiare secondo il promemoria</h2>
              <div class="card list">{report.rotation.map((e) => <Row {...e} note={`ogni ${e.item.data.rotateDays} giorni · cambiata ${relTime(passwordChangedAt(e.item))}`} />)}</div>
            </section>
          )}
          {report.weak.length > 0 && (
            <section class="stack">
              <h2>Deboli</h2>
              <div class="card list">{report.weak.map((e) => <Row {...e} />)}</div>
            </section>
          )}
          {report.old.length > 0 && (
            <section class="stack">
              <h2>Non cambiate da oltre un anno</h2>
              <p class="small muted">Per gli elementi salvati prima della versione 0.7.12 conta l'ultima modifica, perché la data del cambio password non era registrata.</p>
              <div class="card list">{report.old.map((e) => <Row {...e} note={relTime(passwordChangedAt(e.item))} />)}</div>
            </section>
          )}
          {report.missingOtp.length > 0 && (
            <section class="stack">
              <h2>Pannelli di amministrazione senza OTP salvato</h2>
              <p class="small muted">Se il servizio supporta il secondo fattore, conviene attivarlo e salvarne il codice qui.</p>
              <div class="card list">{report.missingOtp.map((e) => <Row {...e} />)}</div>
            </section>
          )}
          {report.checked > 0 && !report.weak.length && !report.reused.length && !report.old.length && !report.rotation.length && (
            <div class="notice ok">Nessun problema trovato.</div>
          )}
          {report.checked === 0 && <p class="muted">Nessuna password da analizzare.</p>}
        </>
      )}
    </>
  );
}
