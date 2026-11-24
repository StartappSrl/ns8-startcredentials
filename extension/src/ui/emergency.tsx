import { useState } from "preact/hooks";
import { Container, EmergencyDesignation, MyEmergency, Permission, Vault } from "@startcredentials/client";
import { errorText } from "../shared";
import { Dialog, ErrorNote, useAction, useLoad, useToast } from "./kit";

/**
 * Accesso d'emergenza: un gestore designa un collega, che può chiedere l'accesso
 * al cliente. Gestori e amministratori vengono avvisati e possono rifiutare; se
 * nessuno rifiuta entro il tempo di attesa, l'accesso viene concesso.
 */

const PERM: Record<Permission, string> = { read: "Sola lettura", write: "Può modificare", manage: "Può gestire" };
const WAITS = [[24, "24 ore"], [48, "48 ore"], [72, "3 giorni"], [168, "7 giorni"]] as const;
const waitLabel = (h: number) => WAITS.find(([n]) => n === h)?.[1] ?? `${h} ore`;
const at = (d: string | null) => (d ? new Date(d).toLocaleString("it-IT", { dateStyle: "medium", timeStyle: "short" }) : "");

const STATUS: Record<EmergencyDesignation["status"], [string, string]> = {
  idle: ["Pronto, mai richiesto", ""],
  pending: ["Richiesta in corso", "warn"],
  ready: ["Attesa scaduta: accesso in concessione", "warn"],
  rejected: ["Rifiutata: va riattivata", ""],
  stale: ["Da rinnovare", "warn"],
};

// ------------------------------------------------------------------ gestori: designazioni del cliente

export function EmergencyDialog({ vault, container, onClose }: { vault: Vault; container: Container; onClose: () => void }) {
  const list = useLoad(() => vault.emergencyDesignations(container.id), [container.id]);
  const dir = useLoad(() => vault.directory(true), []);
  const members = useLoad(() => vault.members(container.id), [container.id]);
  const [userId, setUserId] = useState("");
  const [permission, setPermission] = useState<Permission>("read");
  const [wait, setWait] = useState(48);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const designated = new Set((list.data ?? []).map((d) => d.userId));
  const memberIds = new Set((members.data ?? []).map((m) => m.userId));
  const candidates = (dir.data ?? []).filter((u) => u.id !== vault.me.id && u.status === "active" && !designated.has(u.id) && !memberIds.has(u.id));
  const act = (fn: () => Promise<unknown>, msg: string) => run(async () => { await fn(); list.reload(); members.reload(); toast(msg); });

  return (
    <Dialog title={`Accesso d'emergenza · ${container.meta.name}`} onClose={onClose} wide>
      <div class="stack">
        <p class="small">
          Se nessun gestore è raggiungibile, un collega designato può chiedere l'accesso a questo cliente. Gestori e amministratori
          ricevono subito un'email e un avviso nell'app e possono <b>rifiutare</b>; se nessuno rifiuta entro il tempo di attesa,
          l'accesso viene concesso. La chiave è preparata ora, cifrata solo per il collega: il server non può leggerla, ma è il server a far
          rispettare l'attesa. Designa quindi solo persone di cui ti fideresti come se condividessi il cliente subito. Se la togli o la persona
          lascia il cliente, la designazione viene cancellata.
        </p>
        <ErrorNote error={list.error ?? error} />
        <div class="card list emergency-list">
          {list.data?.length === 0 && <div class="empty small">Nessun collega designato.</div>}
          {list.data?.map((d) => {
            const [label, tone] = STATUS[d.status];
            return (
              <div class="item-row emergency-row" style="cursor:default">
                <span class="grow">
                  <span class="ellipsis" style="display:block;font-weight:500">{d.displayName}</span>
                  <span class="small muted" style="display:block">
                    {PERM[d.permission]} · attesa {waitLabel(d.waitHours)}
                    {d.status === "pending" && ` · concesso il ${at(d.activatesAt)} se nessuno rifiuta`}
                    {d.status === "rejected" && ` · rifiutata il ${at(d.rejectedAt)}`}
                  </span>
                </span>
                <span class={`badge${tone ? ` ${tone}` : ""}`}>{label}</span>
                {(d.status === "pending" || d.status === "ready") && (
                  <>
                    <button class="btn sm danger" disabled={busy} onClick={() => act(() => vault.rejectEmergency(container.id, d.userId), "Richiesta rifiutata")}>Rifiuta</button>
                    <button class="btn sm" disabled={busy} onClick={() => act(() => vault.approveEmergency(container.id, d.userId), "Accesso concesso")}>Approva subito</button>
                  </>
                )}
                {(d.status === "stale" || d.status === "rejected") && (
                  <button class="btn sm" disabled={busy} onClick={() => act(() => vault.designateEmergency(container.id, d.userId, d.permission, d.waitHours), "Designazione riattivata")}>
                    {d.status === "stale" ? "Rinnova" : "Riattiva"}
                  </button>
                )}
                <button class="btn sm ghost" disabled={busy} aria-label={`Togli la designazione di ${d.displayName}`}
                  onClick={() => act(() => vault.removeEmergency(container.id, d.userId), "Designazione tolta")}>Togli</button>
              </div>
            );
          })}
        </div>
        <h3>Designa un collega</h3>
        <div class="row" style="align-items:flex-end">
          <label class="field" style="flex:2 1 220px">Collega
            <select class="input" value={userId} onChange={(e) => setUserId(e.currentTarget.value)}>
              <option value="">Scegli…</option>
              {candidates.map((u) => <option value={u.id} disabled={!u.verified}>{u.displayName}{u.verified ? "" : " (chiave non certificata)"}</option>)}
            </select>
          </label>
          <label class="field" style="flex:1 1 150px">Permesso
            <select class="input" value={permission} onChange={(e) => setPermission(e.currentTarget.value as Permission)}>
              {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM[p]}</option>)}
            </select>
          </label>
          <label class="field" style="flex:1 1 130px">Tempo di attesa
            <select class="input" value={wait} onChange={(e) => setWait(Number(e.currentTarget.value))}>
              {WAITS.map(([h, l]) => <option value={h}>{l}</option>)}
            </select>
          </label>
          <button class="btn primary" disabled={!userId || busy}
            onClick={() => act(async () => { await vault.designateEmergency(container.id, userId, permission, wait); setUserId(""); }, "Collega designato")}>
            Designa
          </button>
        </div>
        <p class="small muted">Chi ha già accesso al cliente non compare. Il collega deve avere la chiave certificata da un amministratore.</p>
        <div class="row" style="justify-content:flex-end"><button class="btn" onClick={onClose}>Chiudi</button></div>
      </div>
    </Dialog>
  );
}

// ------------------------------------------------------------------ gestori: avviso delle richieste in corso

export function EmergencyAlerts({ vault, containers, onChanged }: { vault: Vault; containers: Container[]; onChanged: () => void }) {
  const pending = useLoad(() => vault.pendingEmergencies().catch(() => []), [containers.length]);
  const { busy, error, run } = useAction();
  const toast = useToast();
  if (!pending.data?.length) return null;
  return (
    <div class="notice warn stack" role="alert" style="gap:8px">
      <b>Richieste di accesso d'emergenza</b>
      <ErrorNote error={error} />
      {pending.data.map((p) => {
        const known = containers.find((c) => c.id === p.containerId);
        const name = known?.meta.name ?? "un cliente a cui non hai accesso";
        return (
          <div class="row" style="gap:8px">
            <span class="grow">
              <b>{p.displayName}</b> ha chiesto l'accesso a <b>{name}</b>: sarà concesso il {at(p.activatesAt)} se nessuno rifiuta.
            </span>
            <button class="btn sm danger" disabled={busy}
              onClick={() => run(async () => { await vault.rejectEmergency(p.containerId, p.userId); pending.reload(); toast("Richiesta rifiutata"); })}>Rifiuta</button>
            {known?.permission === "manage" && <button class="btn sm" disabled={busy}
              onClick={() => run(async () => { await vault.approveEmergency(p.containerId, p.userId); pending.reload(); onChanged(); toast("Accesso concesso"); })}>Approva subito</button>}
          </div>
        );
      })}
    </div>
  );
}

// ------------------------------------------------------------------ designato: le mie designazioni

export function EmergencyPage({ vault, onChanged }: { vault: Vault; onChanged: () => void }) {
  const list = useLoad(() => vault.myEmergencyAccess(), []);
  const [confirm, setConfirm] = useState<MyEmergency | null>(null);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const claim = (e: MyEmergency) => run(async () => {
    try {
      const cid = await vault.claimEmergency(e.id);
      onChanged();
      toast("Accesso ottenuto");
      location.hash = `/c/${cid}`;
    } catch (err) {
      list.reload();
      throw new Error(errorText(err));
    }
  });
  return (
    <>
      <div class="stack" style="gap:4px">
        <h1>Accesso d'emergenza</h1>
        <p class="muted">Clienti per cui un gestore ti ha designato. Chiedi l'accesso solo se nessun gestore è raggiungibile: tutti i gestori e gli amministratori vengono avvisati.</p>
      </div>
      <ErrorNote error={list.error ?? error} />
      {!list.data && <p class="muted">Caricamento…</p>}
      {list.data?.length === 0 && <div class="card empty"><p>Non sei designato per nessun cliente.</p></div>}
      {list.data && list.data.length > 0 && (
        <div class="card list emergency-list">
          {list.data.map((e) => (
            <div class="item-row emergency-row" style="cursor:default">
              <span class="grow">
                <span class="ellipsis" style="display:block;font-weight:500">{e.name}</span>
                <span class="small muted" style="display:block">
                  {PERM[e.permission]} · attesa {waitLabel(e.waitHours)} · designato da {e.createdBy}
                  {e.status === "pending" && ` · accesso il ${at(e.activatesAt)} se nessuno rifiuta`}
                  {e.status === "rejected" && ` · richiesta rifiutata il ${at(e.rejectedAt)}: un gestore deve riattivarla`}
                  {e.status === "stale" && " · un gestore deve rinnovare la designazione"}
                </span>
              </span>
              {e.status === "idle" && <button class="btn sm" disabled={busy} onClick={() => setConfirm(e)}>Richiedi accesso</button>}
              {e.status === "pending" && <span class="badge warn">In attesa</span>}
              {e.status === "ready" && <button class="btn sm primary" disabled={busy} onClick={() => claim(e)}>Ottieni l'accesso</button>}
              {e.status === "stale" && <span class="badge">Da rinnovare</span>}
            </div>
          ))}
        </div>
      )}
      {confirm && (
        <Dialog title={`Chiedere l'accesso a ${confirm.name}?`} onClose={() => setConfirm(null)}>
          <p>Tutti i gestori del cliente e gli amministratori riceveranno subito un'email e potranno rifiutare.</p>
          <p>Se nessuno rifiuta, otterrai l'accesso ({PERM[confirm.permission].toLowerCase()}) tra <b>{waitLabel(confirm.waitHours)}</b>. La richiesta resta nel registro attività.</p>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirm(null)}>Annulla</button>
            <button class="btn primary" disabled={busy} onClick={() => run(async () => {
              await vault.requestEmergency(confirm.id);
              setConfirm(null);
              list.reload();
              toast("Richiesta inviata ai gestori");
            })}>Chiedi l'accesso</button>
          </div>
        </Dialog>
      )}
    </>
  );
}
