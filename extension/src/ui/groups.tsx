import { useState } from "preact/hooks";
import { Group, Vault } from "@startcredentials/client";
import { initials } from "../shared";
import { Dialog, ErrorNote, useAction, useLoad, useToast } from "./kit";

export function Groups({ vault }: { vault: Vault }) {
  const groups = useLoad(() => vault.groups(), []);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<Group | null>(null);
  const { busy, error, run } = useAction();
  const toast = useToast();
  return (
    <>
      <div class="row between">
        <div class="stack" style="gap:4px">
          <h1>Gruppi</h1>
          <p class="muted">Condividi un cliente con un gruppo una volta sola: chi entra nel gruppo lo vede subito, chi esce perde l'accesso e le chiavi vengono ruotate.</p>
        </div>
        <button class="btn primary" disabled={!vault.me.org} onClick={() => setCreating(true)}>Nuovo gruppo</button>
      </div>
      {!vault.me.org && <div class="notice warn">Prima <a href="#/admin/org">inizializza l'organizzazione</a>: la chiave di ogni gruppo viene certificata con quella dell'organizzazione.</div>}
      <ErrorNote error={groups.error ?? error} />
      {groups.data?.length === 0 && (
        <div class="card empty">
          <h3>Nessun gruppo</h3>
          <p>Per esempio «Tecnici», «Amministrazione» o «Reperibilità».</p>
        </div>
      )}
      {!!groups.data?.length && (
        <div class="card table-wrap">
          <table>
            <thead><tr><th>Gruppo</th><th>Membri</th><th>Clienti</th><th>Tuo ruolo</th><th></th></tr></thead>
            <tbody>
              {groups.data.map((g) => (
                <tr>
                  <td>
                    <div class="row" style="flex-wrap:nowrap">
                      <div class="avatar">{initials(g.name)}</div>
                      <div>
                        <div style="font-weight:500">{g.name}</div>
                        {!g.verified && <span class="badge warn">Chiave non certificata</span>}
                        {g.rotationRequired && <span class="badge warn">Rotazione in sospeso</span>}
                      </div>
                    </div>
                  </td>
                  <td>{g.members}</td>
                  <td>{g.containers}</td>
                  <td>{g.myRole === "manager" ? "Gestore" : g.myRole === "member" ? "Membro" : "—"}</td>
                  <td>
                    <div class="row" style="justify-content:flex-end;flex-wrap:nowrap">
                      {g.rotationRequired && g.myRole === "manager" && (
                        <button class="btn sm primary" disabled={busy} onClick={() => run(async () => {
                          await vault.completePendingRotations();
                          groups.reload();
                          toast("Chiavi ruotate");
                        })}>Ruota ora</button>
                      )}
                      {g.myRole === "manager" && <button class="btn sm" onClick={() => setOpen(g)}>Gestisci</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p class="small muted">Puoi gestire solo i gruppi in cui sei gestore. Un amministratore che non ne fa parte non vede la chiave del gruppo.</p>
      {creating && <CreateGroup vault={vault} onClose={() => setCreating(false)} onCreated={() => { setCreating(false); groups.reload(); }} />}
      {open && <ManageGroup vault={vault} group={open} onClose={() => { setOpen(null); groups.reload(); }} />}
    </>
  );
}

function CreateGroup({ vault, onClose, onCreated }: { vault: Vault; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Dialog title="Nuovo gruppo" onClose={onClose}>
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await vault.createGroup(name.trim()); onCreated(); }); }}>
        <label class="field">Nome del gruppo<input class="input" required autoFocus maxLength={80} value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Tecnici" /></label>
        <p class="small muted">Diventi gestore del gruppo. La sua chiave viene generata qui e certificata con la chiave dell'organizzazione.</p>
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>Crea gruppo</button>
        </div>
      </form>
    </Dialog>
  );
}

function ManageGroup({ vault, group, onClose }: { vault: Vault; group: Group; onClose: () => void }) {
  const members = useLoad(() => vault.groupMembers(group.id), [group.id]);
  const dir = useLoad(() => vault.directory(true), []);
  const [pick, setPick] = useState("");
  const [name, setName] = useState(group.name);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const candidates = (dir.data ?? []).filter((u) => u.status === "active" && !members.data?.some((m) => m.userId === u.id));
  const chosen = candidates.find((u) => u.id === pick);
  return (
    <Dialog title={`Gruppo ${group.name}`} onClose={onClose} wide>
      {group.rotationRequired && <div class="notice warn">La chiave del gruppo è in attesa di rotazione: prima di aggiungere persone premi «Ruota ora» nell'elenco dei gruppi.</div>}
      <div class="row" style="flex-wrap:nowrap;align-items:flex-end">
        <label class="field grow">Aggiungi un collega
          <select class="input" value={pick} onChange={(e) => setPick(e.currentTarget.value)}>
            <option value="">Scegli…</option>
            {candidates.map((u) => <option value={u.id}>{u.displayName} ({u.email}){u.verified ? "" : " – chiave non certificata"}</option>)}
          </select>
        </label>
        <button class="btn primary" disabled={busy || !chosen?.verified || group.rotationRequired} onClick={() => run(async () => {
          await vault.setGroupMember(group.id, pick, "member");
          setPick("");
          members.reload();
          toast("Aggiunto al gruppo");
        })}>Aggiungi</button>
      </div>
      {chosen && !chosen.verified && <div class="notice warn">La chiave di {chosen.displayName} va prima certificata nella pagina Utenti.</div>}
      <div class="card">
        {members.data?.map((m) => (
          <div class="row" style="padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:nowrap">
            <div class="avatar">{initials(m.displayName)}</div>
            <div class="grow">
              <div style="font-weight:500">{m.displayName}{m.userId === vault.me.id ? " (tu)" : ""}</div>
              <div class="small muted">{m.email}</div>
            </div>
            <span class="badge">{m.role === "manager" ? "Gestore" : "Membro"}</span>
            {m.role === "member" && dir.data?.find((u) => u.id === m.userId)?.role === "admin" && (
              <button class="btn sm" disabled={busy || group.rotationRequired} onClick={() => run(async () => { await vault.setGroupMember(group.id, m.userId, "manager"); members.reload(); })}>Rendi gestore</button>
            )}
            {m.userId !== vault.me.id && (
              <button class="btn sm ghost danger" disabled={busy} onClick={() => run(async () => {
                const r = await vault.removeGroupMember(group.id, m.userId);
                members.reload();
                toast(r.failed.length ? `Rimosso. Rotazioni da completare: ${r.failed.map((f) => f.name).join(", ")}` : "Rimosso e chiavi ruotate");
              })}>Rimuovi</button>
            )}
          </div>
        ))}
      </div>
      <p class="small muted">Chi viene rimosso perde subito l'accesso. La chiave del gruppo viene ruotata; quelle dei clienti del gruppo vengono ruotate subito dove sei gestore, altrimenti dal primo gestore al suo accesso.</p>
      <div class="row" style="align-items:flex-end">
        <label class="field grow">Nome<input class="input" value={name} maxLength={80} onInput={(e) => setName(e.currentTarget.value)} /></label>
        <button class="btn" disabled={busy || !name.trim() || name.trim() === group.name} onClick={() => run(async () => { await vault.renameGroup(group.id, name.trim()); toast("Nome aggiornato"); })}>Rinomina</button>
      </div>
      <ErrorNote error={error} />
      <div class="row between">
        <button class="btn ghost danger sm" onClick={() => setConfirmDelete(true)}>Elimina gruppo</button>
        <button class="btn primary" onClick={onClose}>Fatto</button>
      </div>
      {confirmDelete && (
        <Dialog title={`Eliminare il gruppo ${group.name}?`} onClose={() => setConfirmDelete(false)}>
          <p>I membri perdono l'accesso ai clienti condivisi con il gruppo, salvo chi ce l'ha anche direttamente. Le chiavi di quei clienti vengono ruotate.</p>
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirmDelete(false)}>Annulla</button>
            <button class="btn primary" style="background:var(--danger);border-color:var(--danger)" disabled={busy} onClick={() => run(async () => { await vault.deleteGroup(group.id); onClose(); })}>Elimina</button>
          </div>
        </Dialog>
      )}
    </Dialog>
  );
}
