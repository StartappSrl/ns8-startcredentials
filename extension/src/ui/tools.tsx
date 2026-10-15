import { useMemo, useState } from "preact/hooks";
import { Container, HealthEntry, Item, passwordHealth, Vault } from "@startcredentials/client";
import { relTime } from "../shared";
import { ErrorNote, useLoad } from "./kit";

/** Tutti gli elementi leggibili, decifrati in locale. */
async function loadAll(vault: Vault): Promise<HealthEntry[]> {
  const out: HealthEntry[] = [];
  for (const c of await vault.containers()) {
    if (c.kind === "org") continue;
    for (const item of await vault.items(c.id)) out.push({ container: c, item });
  }
  return out;
}

const where = (c: Container) => (c.kind === "personal" ? "Area personale" : c.meta.name);

function Row({ container, item, note }: { container: Container; item: Item; note?: string }) {
  return (
    <a class="item-row" href={`#/c/${container.id}`} style="text-decoration:none;color:inherit">
      <span class="grow">
        <span class="ellipsis" style="display:block;font-weight:500">{item.data.name}</span>
        <span class="ellipsis small muted" style="display:block">{where(container)}{item.data.username ? ` · ${item.data.username}` : ""}</span>
      </span>
      {note && <span class="small muted">{note}</span>}
    </a>
  );
}

export function Search({ vault }: { vault: Vault }) {
  const all = useLoad(() => loadAll(vault), []);
  const [q, setQ] = useState("");
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

export function Health({ vault }: { vault: Vault }) {
  const all = useLoad(() => loadAll(vault), []);
  const report = useMemo(() => (all.data ? passwordHealth(all.data) : null), [all.data]);
  return (
    <>
      <div class="stack" style="gap:4px">
        <h1>Salute delle password</h1>
        <p class="muted">Analisi fatta solo su questo computer, sugli elementi che puoi leggere.</p>
      </div>
      <ErrorNote error={all.error} />
      {!report && <p class="muted">Analisi in corso…</p>}
      {report && (
        <>
          <div class="grid">
            {[
              ["Password analizzate", report.checked],
              ["Deboli", report.weak.length],
              ["Usate in più punti", report.reused.reduce((n, g) => n + g.length, 0)],
              ["Non cambiate da oltre un anno", report.old.length],
            ].map(([l, n]) => (
              <div class="card pad"><div class="small muted">{l}</div><div class="mono" style="font-size:26px">{n}</div></div>
            ))}
          </div>
          {report.reused.length > 0 && (
            <section class="stack">
              <h2>Usate in più punti</h2>
              <p class="small muted">Se una viene compromessa, lo sono anche le altre: è il problema più urgente.</p>
              {report.reused.map((g) => (
                <div class="card list">
                  <div class="group-h"><span>Stessa password in {g.length} elementi</span></div>
                  {g.map((e) => <Row {...e} />)}
                </div>
              ))}
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
              <div class="card list">{report.old.map((e) => <Row {...e} note={relTime(e.item.updatedAt)} />)}</div>
            </section>
          )}
          {report.missingOtp.length > 0 && (
            <section class="stack">
              <h2>Pannelli di amministrazione senza OTP salvato</h2>
              <p class="small muted">Se il servizio supporta il secondo fattore, conviene attivarlo e salvarne il codice qui.</p>
              <div class="card list">{report.missingOtp.map((e) => <Row {...e} />)}</div>
            </section>
          )}
          {report.checked > 0 && !report.weak.length && !report.reused.length && !report.old.length && (
            <div class="notice ok">Nessun problema trovato.</div>
          )}
        </>
      )}
    </>
  );
}
