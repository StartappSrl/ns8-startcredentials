import { ComponentChildren } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import { Container, DirectoryUser, Folder, generatePassword, Item, ItemData, Permission, Vault } from "@startcredentials/client";
import { download, initials, lock, relTime, signOut, tint } from "../shared";
import { CopyButton, Dialog, ErrorNote, Meter, OtpCode, Secret, useAction, useLoad, useToast } from "./kit";

export const PERM_LABEL: Record<Permission, string> = { read: "Sola lettura", write: "Può modificare", manage: "Può gestire" };
const TYPE_LABEL: Record<ItemData["type"], string> = { login: "Password", totp: "OTP", note: "Nota sicura", file: "File", ssh_key: "Chiave SSH" };
const TYPE_TAG: Record<ItemData["type"], string> = { login: "PWD", totp: "OTP", note: "NOTA", file: "FILE", ssh_key: "SSH" };

export function useRoute(): string {
  const [r, setR] = useState(location.hash.replace(/^#/, "") || "/clienti");
  useEffect(() => {
    const h = () => setR(location.hash.replace(/^#/, "") || "/clienti");
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return r;
}
export const go = (path: string) => { location.hash = path; };

// ------------------------------------------------------------------ struttura

export function Shell({ vault, route, children, counts }: { vault: Vault; route: string; children: ComponentChildren; counts: { clients: number; shared: number } }) {
  const link = (path: string, label: string, count?: number | string) => (
    <a href={`#${path}`} class={route === path || route.startsWith(`${path}/`) ? "on" : ""} aria-current={route === path ? "page" : undefined}>
      <span>{label}</span>{count !== undefined && <span class="count">{count}</span>}
    </a>
  );
  const me = vault.me;
  return (
    <div class="shell">
      <nav class="side" aria-label="Navigazione principale">
        <div class="brand" style="padding:0 8px"><img src="icons/128.png" alt="" />StartCredentials</div>
        <div class="nav">
          {link("/cerca", "Cerca")}
          {link("/personale", "Area personale")}
          {link("/clienti", "Clienti", counts.clients)}
          {link("/condivisi", "Condivisi con me", counts.shared)}
          {link("/salute", "Salute password")}
          {link("/generatore", "Generatore")}
          {link("/import", "Importa")}
        </div>
        {me.role === "admin" && (
          <div class="nav">
            <div class="nav-title">Amministrazione</div>
            {link("/admin/utenti", "Utenti")}
            {link("/admin/audit", "Registro attività")}
            {link("/admin/org", "Organizzazione")}
          </div>
        )}
        <div class="me">
          <div class="avatar">{initials(me.displayName)}</div>
          <div class="grow">
            <div class="ellipsis" style="font-weight:500">{me.displayName}</div>
            <a href="#/impostazioni" class="small">Impostazioni</a>
          </div>
          <button class="btn icon-btn sm" aria-label="Blocca la cassaforte" title="Blocca" onClick={async () => { await lock(); location.reload(); }}>
            <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>
          </button>
        </div>
      </nav>
      <main class="main">{children}</main>
    </div>
  );
}

// ------------------------------------------------------------------ elenco clienti

export function Clients({ vault, containers, reload, shared }: { vault: Vault; containers: Container[]; reload: () => void; shared?: boolean }) {
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "manage" | "otp" | "recent">("all");
  const [creating, setCreating] = useState(false);
  let list = containers.filter((c) => c.kind === "client" && (!shared || c.grantedBy !== vault.me.id));
  if (q) list = list.filter((c) => `${c.meta.name} ${c.meta.sector ?? ""}`.toLowerCase().includes(q.toLowerCase()));
  if (filter === "manage") list = list.filter((c) => c.permission === "manage");
  if (filter === "otp") list = list.filter((c) => c.totpItems > 0);
  if (filter === "recent") list = [...list].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 12);
  return (
    <>
      <div class="row">
        <label class="grow" style="flex:1 1 320px">
          <span class="sr-only">Cerca clienti</span>
          <input class="input" type="search" placeholder="Cerca clienti…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        </label>
        <a class="btn" href="#/import">Importa</a>
        {!shared && <button class="btn primary" onClick={() => setCreating(true)}>Nuovo cliente</button>}
      </div>
      <div class="row between">
        <div class="stack" style="gap:4px">
          <h1>{shared ? "Condivisi con me" : "Clienti"}</h1>
          <p class="muted">{shared ? "Clienti che altri colleghi hanno condiviso con te." : "Ogni cliente è un contenitore con la propria chiave. Vedi solo quelli a cui hai accesso."}</p>
        </div>
        <div class="chips" role="group" aria-label="Filtri">
          {([["all", "Tutti"], ["manage", "Gestiti da me"], ["otp", "Con OTP"], ["recent", "Recenti"]] as const).map(([k, l]) => (
            <button class={`chip${filter === k ? " on" : ""}`} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>
      </div>
      {list.length === 0 ? (
        <div class="card empty">
          <h3>{q ? "Nessun cliente corrisponde alla ricerca" : shared ? "Nessun cliente condiviso con te" : "Non hai ancora clienti"}</h3>
          {!shared && !q && <button class="btn primary" onClick={() => setCreating(true)}>Crea il primo cliente</button>}
        </div>
      ) : (
        <div class="grid">
          {list.map((c) => {
            const t = tint(c.id);
            return (
              <button class="client" onClick={() => go(`/c/${c.id}`)}>
                <div class="row" style="flex-wrap:nowrap">
                  <div class="mono-tile" style={`background:${t.bg};color:${t.fg}`}>{initials(c.meta.name)}</div>
                  <div class="grow">
                    <div class="ellipsis" style="font-weight:600;font-size:15px">{c.meta.name}</div>
                    <div class="small muted ellipsis">{c.meta.sector || "—"}</div>
                  </div>
                  <span class="badge">{PERM_LABEL[c.permission]}</span>
                </div>
                <div class="stats">
                  <span><b>{c.items}</b> elementi</span>
                  <span><b>{c.totpItems}</b> OTP</span>
                  <span><b>{c.members}</b> {c.members === 1 ? "persona" : "persone"}</span>
                </div>
                <div class="small muted">Aggiornato {relTime(c.updatedAt)}</div>
              </button>
            );
          })}
        </div>
      )}
      {creating && <ContainerDialog vault={vault} onClose={() => setCreating(false)} onSaved={(id) => { setCreating(false); reload(); go(`/c/${id}`); }} />}
    </>
  );
}

function ContainerDialog({ vault, container, onClose, onSaved }: { vault: Vault; container?: Container; onClose: () => void; onSaved: (id: string) => void }) {
  const [name, setName] = useState(container?.meta.name ?? "");
  const [sector, setSector] = useState(container?.meta.sector ?? "");
  const [notes, setNotes] = useState(container?.meta.notes ?? "");
  const { busy, error, run } = useAction();
  return (
    <Dialog title={container ? "Modifica cliente" : "Nuovo cliente"} onClose={onClose}>
      <form class="stack" onSubmit={(e) => {
        e.preventDefault();
        run(async () => {
          const meta = { name: name.trim(), sector: sector.trim() || undefined, notes: notes.trim() || undefined };
          if (container) {
            await vault.updateContainer(container.id, meta);
            onSaved(container.id);
          } else onSaved(await vault.createContainer(meta));
        });
      }}>
        <label class="field">Nome del cliente<input class="input" required autoFocus value={name} onInput={(e) => setName(e.currentTarget.value)} /></label>
        <label class="field">Settore e città<input class="input" value={sector} placeholder="Studio legale · Roma" onInput={(e) => setSector(e.currentTarget.value)} /></label>
        <label class="field">Note<textarea class="input" value={notes} onInput={(e) => setNotes(e.currentTarget.value)} /></label>
        <p class="small muted">Nome, settore e note sono cifrati come le password.</p>
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>{container ? "Salva" : "Crea cliente"}</button>
        </div>
      </form>
    </Dialog>
  );
}

// ------------------------------------------------------------------ contenitore

type Tab = "all" | "login" | "totp" | "note" | "files" | "trash";

export function ContainerView({ vault, id, onChanged }: { vault: Vault; id: string; onChanged: () => void }) {
  const [tab, setTab] = useState<Tab>("all");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<Item | "new" | null>(null);
  const [sharing, setSharing] = useState(false);
  const [editMeta, setEditMeta] = useState(false);
  const [newFolder, setNewFolder] = useState(false);
  const info = useLoad(() => vault.container(id), [id]);
  const items = useLoad(() => vault.items(id, { trash: tab === "trash" }), [id, tab === "trash"]);
  const toast = useToast();
  const c = info.data;

  const visible = useMemo(() => {
    let l = items.data ?? [];
    if (tab === "login") l = l.filter((i) => i.type === "login");
    if (tab === "totp") l = l.filter((i) => !!i.data.totpUri);
    if (tab === "note") l = l.filter((i) => i.type === "note");
    if (tab === "files") l = l.filter((i) => i.attachments.length > 0);
    if (q) {
      const s = q.toLowerCase();
      l = l.filter((i) => [i.data.name, i.data.username, ...(i.data.urls ?? []), i.data.notes].some((v) => v?.toLowerCase().includes(s)));
    }
    return l;
  }, [items.data, tab, q]);

  if (info.error) return <ErrorNote error={info.error} />;
  if (!c) return <p class="muted">Caricamento…</p>;
  const canWrite = c.permission !== "read";
  const canManage = c.permission === "manage";
  const all = items.data ?? [];
  const sel = all.find((i) => i.id === selected) ?? null;
  const t = tint(c.id);
  const reloadAll = () => { items.reload(); info.reload(); onChanged(); };

  const groups: { folder: Folder | null; items: Item[] }[] = [];
  for (const f of [null, ...c.folders]) {
    const g = visible.filter((i) => (i.folderId ?? null) === (f?.id ?? null));
    if (g.length || (f && !q && tab === "all")) groups.push({ folder: f, items: g });
  }

  return (
    <>
      {c.kind === "client" && <div class="small muted"><a href="#/clienti">Clienti</a> / {c.meta.name}</div>}
      <div class="row between">
        <div class="row" style="flex-wrap:nowrap">
          <div class="mono-tile" style={`width:52px;height:52px;font-size:18px;background:${t.bg};color:${t.fg}`}>{initials(c.meta.name)}</div>
          <div>
            <h1>{c.meta.name}</h1>
            <div class="muted">
              {c.kind === "personal" ? "Visibile solo a te" : `${c.meta.sector ? `${c.meta.sector} · ` : ""}${c.members} ${c.members === 1 ? "persona" : "persone"} · ${PERM_LABEL[c.permission]}`}
            </div>
          </div>
        </div>
        <div class="row">
          {canManage && c.kind === "client" && <button class="btn" onClick={() => setEditMeta(true)}>Modifica cliente</button>}
          {canManage && c.kind === "client" && <button class="btn" onClick={() => setSharing(true)}>Condividi</button>}
          {canWrite && <button class="btn" onClick={() => setNewFolder(true)}>Nuova cartella</button>}
          {canWrite && <button class="btn primary" onClick={() => setEditing("new")}>Nuovo elemento</button>}
        </div>
      </div>
      {c.meta.notes && <div class="notice info">{c.meta.notes}</div>}

      <div class="row between">
        <div class="tabs" role="tablist">
          {([["all", "Tutto"], ["login", "Password"], ["totp", "OTP"], ["note", "Note"], ["files", "Con allegati"], ["trash", "Cestino"]] as const).map(([k, l]) => (
            <button role="tab" aria-selected={tab === k} class={`tab${tab === k ? " on" : ""}`} onClick={() => { setTab(k); setSelected(null); }}>{l}</button>
          ))}
        </div>
        <input class="input" type="search" style="max-width:260px" aria-label="Cerca nel cliente" placeholder="Cerca nel cliente…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
      </div>

      <div class="split">
        <section class="card list" aria-label="Elementi">
          {items.loading && !items.data && <div class="empty">Decifratura…</div>}
          {items.data && visible.length === 0 && (
            <div class="empty">
              <h3>{tab === "trash" ? "Il cestino è vuoto" : q ? "Nessun risultato" : "Nessun elemento"}</h3>
              {tab !== "trash" && canWrite && !q && <button class="btn primary" onClick={() => setEditing("new")}>Aggiungi una password</button>}
              {tab === "trash" && <p class="small">Gli elementi eliminati restano qui 30 giorni.</p>}
            </div>
          )}
          {groups.map((g) => (
            <>
              {(g.folder || c.folders.length > 0) && (
                <div class="group-h">
                  <span>{g.folder?.name ?? "Senza cartella"}</span>
                  <span class="row" style="gap:6px">
                    {g.items.length}
                    {g.folder && canWrite && g.items.length === 0 && (
                      <button class="btn ghost sm" style="min-height:24px;padding:0 6px" onClick={async () => { await vault.deleteFolder(g.folder!.id); info.reload(); }}>Elimina</button>
                    )}
                  </span>
                </div>
              )}
              {g.items.map((i) => (
                <button class={`item-row${i.id === selected ? " on" : ""}`} onClick={() => setSelected(i.id)}>
                  <span class="kind">{i.data.totpUri && i.type === "login" ? "PWD" : TYPE_TAG[i.type]}</span>
                  <span class="grow">
                    <span class="ellipsis" style="display:block;font-weight:500">{i.data.name}</span>
                    <span class="ellipsis small muted" style="display:block">{i.data.username || (i.data.urls?.[0] ?? TYPE_LABEL[i.type])}</span>
                  </span>
                  <span class="small muted">{[i.data.totpUri && "OTP", i.attachments.length && `${i.attachments.length} file`].filter(Boolean).join(" · ")}</span>
                </button>
              ))}
            </>
          ))}
        </section>
        <aside class="detail">
          {sel ? (
            <ItemDetail key={sel.id} vault={vault} item={sel} canWrite={canWrite} folders={c.folders}
              onEdit={() => setEditing(sel)} onChanged={reloadAll}
              onDeleted={() => { setSelected(null); reloadAll(); toast(tab === "trash" ? "Elemento ripristinato" : "Elemento spostato nel cestino"); }} />
          ) : (
            <div class="card empty"><p>Seleziona un elemento per vederne i dettagli.</p></div>
          )}
        </aside>
      </div>

      {editing && <ItemEditor vault={vault} containerId={id} folders={c.folders} item={editing === "new" ? undefined : editing}
        onClose={() => setEditing(null)} onSaved={(iid) => { setEditing(null); setSelected(iid); reloadAll(); toast("Salvato"); }} />}
      {sharing && <ShareDialog vault={vault} container={c} onClose={() => { setSharing(false); reloadAll(); }} />}
      {editMeta && <ContainerDialog vault={vault} container={c} onClose={() => setEditMeta(false)} onSaved={() => { setEditMeta(false); reloadAll(); }} />}
      {newFolder && <FolderDialog vault={vault} containerId={id} onClose={() => setNewFolder(false)} onSaved={() => { setNewFolder(false); info.reload(); }} />}
      {canManage && c.kind === "client" && (
        <div class="row" style="justify-content:flex-end">
          <DeleteContainer vault={vault} container={c} onDeleted={() => { onChanged(); go("/clienti"); }} />
        </div>
      )}
    </>
  );
}

function DeleteContainer({ vault, container, onDeleted }: { vault: Vault; container: Container; onDeleted: () => void }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const { busy, error, run } = useAction();
  return (
    <>
      <button class="btn ghost danger sm" onClick={() => setOpen(true)}>Elimina cliente</button>
      {open && (
        <Dialog title="Eliminare il cliente?" onClose={() => setOpen(false)}>
          <p>Tutti gli elementi di <b>{container.meta.name}</b> diventeranno inaccessibili per ogni membro. Per confermare scrivi il nome del cliente.</p>
          <input class="input" aria-label="Nome del cliente" value={typed} onInput={(e) => setTyped(e.currentTarget.value)} />
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setOpen(false)}>Annulla</button>
            <button class="btn primary" style="background:var(--danger);border-color:var(--danger)" disabled={busy || typed.trim() !== container.meta.name}
              onClick={() => run(async () => { await vault.deleteContainer(container.id); onDeleted(); })}>Elimina definitivamente</button>
          </div>
        </Dialog>
      )}
    </>
  );
}

function FolderDialog({ vault, containerId, onClose, onSaved }: { vault: Vault; containerId: string; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Dialog title="Nuova cartella" onClose={onClose}>
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await vault.createFolder(containerId, name.trim()); onSaved(); }); }}>
        <label class="field">Nome<input class="input" required autoFocus value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Rete e server" /></label>
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>Crea cartella</button>
        </div>
      </form>
    </Dialog>
  );
}

// ------------------------------------------------------------------ dettaglio elemento

function ItemDetail({ vault, item, canWrite, folders, onEdit, onChanged, onDeleted }: {
  vault: Vault; item: Item; canWrite: boolean; folders: Folder[]; onEdit: () => void; onChanged: () => void; onDeleted: () => void;
}) {
  const d = item.data;
  const [history, setHistory] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const { error, run } = useAction();
  const report = (a: Parameters<Vault["report"]>[0]) => vault.report(a, item.containerId, item.id);
  const folder = folders.find((f) => f.id === item.folderId);
  return (
    <div class="card pad stack">
      <div>
        <h2 style="word-break:break-word">{d.name}</h2>
        <div class="small muted">{TYPE_LABEL[d.type]}{folder ? ` · ${folder.name}` : ""}</div>
        {(d.urls ?? []).map((u) => <div class="small"><a href={/^https?:\/\//.test(u) ? u : `https://${u}`} target="_blank" rel="noopener noreferrer">{u}</a></div>)}
      </div>
      {item.deletedAt && <div class="notice warn">Nel cestino dal {new Date(item.deletedAt).toLocaleDateString("it-IT")}</div>}
      {d.username && (
        <div class="stack" style="gap:6px">
          <span class="small muted">Nome utente</span>
          <div class="input-group">
            <input class="input mono" readOnly value={d.username} aria-label="Nome utente" />
            <CopyButton value={d.username} />
          </div>
        </div>
      )}
      {d.password && (
        <div class="stack" style="gap:6px">
          <span class="small muted">Password</span>
          <Secret value={d.password} onReveal={() => report("item.reveal")} onCopy={() => report("item.copy")} />
          <Meter value={d.password} />
        </div>
      )}
      {d.totpUri && <OtpCode uri={d.totpUri} onCopy={() => report("item.totp_copy")} />}
      {d.notes && (
        <div class="stack" style="gap:6px">
          <span class="small muted">Note</span>
          <div style="white-space:pre-wrap;word-break:break-word" class="file">{d.notes}</div>
        </div>
      )}
      {(d.fields ?? []).map((f) => (
        <div class="stack" style="gap:6px">
          <span class="small muted">{f.label}</span>
          {f.secret ? <Secret value={f.value} onReveal={() => report("item.reveal")} onCopy={() => report("item.copy")} /> : (
            <div class="input-group"><input class="input" readOnly value={f.value} aria-label={f.label} /><CopyButton value={f.value} /></div>
          )}
        </div>
      ))}
      <div class="stack" style="gap:8px">
        <span class="small muted">Allegati</span>
        {item.attachments.map((a) => (
          <div class="file">
            <span class="badge">{(a.name.split(".").pop() ?? "file").slice(0, 4).toUpperCase()}</span>
            <span class="grow ellipsis">{a.name}</span>
            <span class="small muted">{a.size < 1048576 ? `${Math.ceil(a.size / 1024)} KB` : `${(a.size / 1048576).toFixed(1)} MB`}</span>
            <button class="btn sm" onClick={() => run(async () => download(await vault.downloadAttachment(item, a), a.name, a.mime))}>Scarica</button>
            {canWrite && !item.deletedAt && <button class="btn sm ghost danger" aria-label={`Elimina ${a.name}`} onClick={() => run(async () => { await vault.deleteAttachment(a.id); onChanged(); })}>✕</button>}
          </div>
        ))}
        {canWrite && !item.deletedAt && (
          <label class="btn sm" style="align-self:flex-start">
            {progress ?? "Aggiungi file"}
            <input type="file" class="sr-only" onChange={(e) => {
              const f = e.currentTarget.files?.[0];
              e.currentTarget.value = "";
              if (!f) return;
              run(async () => {
                setProgress("Cifratura…");
                await vault.addAttachment(item, new Uint8Array(await f.arrayBuffer()), f.name, f.type || "application/octet-stream",
                  (done, total) => setProgress(`Caricamento ${Math.round((done / total) * 100)}%`));
                setProgress(null);
                onChanged();
              }).finally(() => setProgress(null));
            }} />
          </label>
        )}
      </div>
      <ErrorNote error={error} />
      <div class="row">
        {canWrite && !item.deletedAt && <button class="btn sm" onClick={onEdit}>Modifica</button>}
        <button class="btn sm" onClick={() => setHistory(true)}>Cronologia</button>
        {canWrite && (item.deletedAt
          ? <button class="btn sm" onClick={() => run(async () => { await vault.restoreItem(item.id); onDeleted(); })}>Ripristina</button>
          : <button class="btn sm ghost danger" onClick={() => run(async () => { await vault.deleteItem(item.id); onDeleted(); })}>Sposta nel cestino</button>)}
      </div>
      <div class="small muted">Modificato da {item.updatedBy} · {relTime(item.updatedAt)} · revisione {item.revision}</div>
      {history && <HistoryDialog vault={vault} item={item} onClose={() => setHistory(false)} />}
    </div>
  );
}

function HistoryDialog({ vault, item, onClose }: { vault: Vault; item: Item; onClose: () => void }) {
  const v = useLoad(() => vault.itemVersions(item), [item.id]);
  return (
    <Dialog title="Cronologia delle modifiche" onClose={onClose} wide>
      <ErrorNote error={v.error} />
      {v.data?.length === 0 && <p class="muted">Nessuna versione precedente.</p>}
      <div class="stack">
        {v.data?.map((x) => (
          <div class="file" style="align-items:flex-start;flex-direction:column;gap:6px">
            <div class="row between" style="width:100%"><b>Revisione {x.revision}</b><span class="small muted">{x.by} · {new Date(x.createdAt).toLocaleString("it-IT")}</span></div>
            <div class="small">Utente: {x.data.username || "—"} · URL: {(x.data.urls ?? []).join(", ") || "—"}</div>
            {x.data.password && <Secret value={x.data.password} onReveal={() => vault.report("item.reveal", item.containerId, item.id)} />}
          </div>
        ))}
      </div>
    </Dialog>
  );
}

// ------------------------------------------------------------------ editor elemento

function ItemEditor({ vault, containerId, folders, item, onClose, onSaved }: {
  vault: Vault; containerId: string; folders: Folder[]; item?: Item; onClose: () => void; onSaved: (id: string) => void;
}) {
  const d = item?.data;
  const [type, setType] = useState<ItemData["type"]>(d?.type ?? "login");
  const [name, setName] = useState(d?.name ?? "");
  const [username, setUsername] = useState(d?.username ?? "");
  const [password, setPassword] = useState(d?.password ?? "");
  const [urls, setUrls] = useState((d?.urls ?? []).join("\n"));
  const [totp, setTotp] = useState(d?.totpUri ?? "");
  const [notes, setNotes] = useState(d?.notes ?? "");
  const [folderId, setFolderId] = useState(item?.folderId ?? "");
  const [fields, setFields] = useState(d?.fields ?? []);
  const { busy, error, setError, run } = useAction();

  const save = (e: Event) => {
    e.preventDefault();
    let totpUri: string | undefined;
    const t = totp.trim();
    if (t) {
      totpUri = t.startsWith("otpauth://") ? t : `otpauth://totp/${encodeURIComponent(name || "OTP")}?secret=${t.replace(/\s/g, "").toUpperCase()}`;
    }
    const data: ItemData = {
      type, name: name.trim(),
      username: username.trim() || undefined, password: password || undefined,
      urls: urls.split("\n").map((u) => u.trim()).filter(Boolean),
      totpUri, notes: notes || undefined,
      fields: fields.filter((f) => f.label.trim()),
    };
    run(async () => {
      if (totpUri) await Vault.totp(totpUri).catch(() => { throw new Error("Segreto OTP non valido: incolla l'URI otpauth:// o la chiave in Base32"); });
      if (item) {
        await vault.updateItem(item, data, folderId || null);
        onSaved(item.id);
      } else onSaved(await vault.createItem(containerId, data, folderId || null));
    }).catch((err) => setError(String(err)));
  };

  return (
    <Dialog title={item ? "Modifica elemento" : "Nuovo elemento"} onClose={onClose} wide>
      <form class="stack" onSubmit={save}>
        <div class="row" style="align-items:flex-end">
          <label class="field" style="flex:1 1 160px">Tipo
            <select class="input" value={type} onChange={(e) => setType(e.currentTarget.value as ItemData["type"])}>
              <option value="login">Password</option><option value="totp">Solo OTP</option><option value="note">Nota sicura</option><option value="ssh_key">Chiave SSH</option>
            </select>
          </label>
          <label class="field" style="flex:2 1 260px">Nome<input class="input" required autoFocus value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Microsoft 365 – amministratore" /></label>
          {folders.length > 0 && (
            <label class="field" style="flex:1 1 160px">Cartella
              <select class="input" value={folderId} onChange={(e) => setFolderId(e.currentTarget.value)}>
                <option value="">Nessuna</option>{folders.map((f) => <option value={f.id}>{f.name}</option>)}
              </select>
            </label>
          )}
        </div>
        {type !== "note" && (
          <>
            <label class="field">Nome utente<input class="input mono" value={username} onInput={(e) => setUsername(e.currentTarget.value)} autoComplete="off" /></label>
            <label class="field">{type === "ssh_key" ? "Chiave privata o passphrase" : "Password"}
              <div class="input-group">
                <input class="input mono" value={password} onInput={(e) => setPassword(e.currentTarget.value)} autoComplete="off" spellcheck={false} />
                <button type="button" class="btn sm" onClick={() => setPassword(generatePassword({ length: 24 }))}>Genera</button>
              </div>
            </label>
            <Meter value={password} />
            <label class="field">Indirizzi web (uno per riga; servono per la compilazione automatica)
              <textarea class="input mono" style="min-height:64px" value={urls} onInput={(e) => setUrls(e.currentTarget.value)} placeholder="https://admin.microsoft.com" />
            </label>
            <label class="field">OTP: URI otpauth:// o chiave segreta
              <input class="input mono" value={totp} onInput={(e) => setTotp(e.currentTarget.value)} placeholder="otpauth://totp/… oppure JBSWY3DPEHPK3PXP" autoComplete="off" />
            </label>
          </>
        )}
        <label class="field">Note<textarea class="input" value={notes} onInput={(e) => setNotes(e.currentTarget.value)} /></label>
        <div class="stack" style="gap:8px">
          <span class="small muted">Campi aggiuntivi</span>
          {fields.map((f, i) => (
            <div class="row" style="flex-wrap:nowrap">
              <input class="input" style="flex:1" aria-label="Etichetta" placeholder="Etichetta" value={f.label} onInput={(e) => setFields(fields.map((x, j) => j === i ? { ...x, label: e.currentTarget.value } : x))} />
              <input class="input mono" style="flex:2" aria-label="Valore" placeholder="Valore" value={f.value} onInput={(e) => setFields(fields.map((x, j) => j === i ? { ...x, value: e.currentTarget.value } : x))} />
              <label class="check"><input type="checkbox" checked={f.secret} onChange={(e) => setFields(fields.map((x, j) => j === i ? { ...x, secret: e.currentTarget.checked } : x))} />Riservato</label>
              <button type="button" class="btn sm ghost" aria-label="Rimuovi campo" onClick={() => setFields(fields.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
          <button type="button" class="btn sm" style="align-self:flex-start" onClick={() => setFields([...fields, { label: "", value: "", secret: true }])}>Aggiungi campo</button>
        </div>
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>{busy ? "Cifratura…" : "Salva"}</button>
        </div>
      </form>
    </Dialog>
  );
}

// ------------------------------------------------------------------ condivisione

function ShareDialog({ vault, container, onClose }: { vault: Vault; container: Container; onClose: () => void }) {
  const members = useLoad(() => vault.members(container.id), [container.id]);
  const dir = useLoad(() => vault.directory(true), []);
  const [pick, setPick] = useState("");
  const [perm, setPerm] = useState<Permission>("read");
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const candidates = (dir.data ?? []).filter((u) => u.status === "active" && !members.data?.some((m) => m.userId === u.id));
  const chosen: DirectoryUser | undefined = candidates.find((u) => u.id === pick);
  return (
    <Dialog title={`Condividi «${container.meta.name}»`} onClose={onClose} wide>
      <div class="row" style="flex-wrap:nowrap;align-items:flex-end">
        <label class="field grow">Aggiungi un collega
          <select class="input" value={pick} onChange={(e) => setPick(e.currentTarget.value)}>
            <option value="">Scegli…</option>
            {candidates.map((u) => <option value={u.id}>{u.displayName} ({u.email}){u.verified ? "" : " – chiave non certificata"}</option>)}
          </select>
        </label>
        <label class="field">Permesso
          <select class="input" value={perm} onChange={(e) => setPerm(e.currentTarget.value as Permission)}>
            {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM_LABEL[p]}</option>)}
          </select>
        </label>
        <button class="btn primary" disabled={busy || !chosen?.verified} onClick={() => run(async () => {
          await vault.share(container.id, pick, perm);
          setPick("");
          members.reload();
          toast("Accesso concesso");
        })}>Condividi</button>
      </div>
      {chosen && (chosen.verified
        ? <div class="small muted">Impronta della chiave di {chosen.displayName}: <span class="mono">{chosen.fingerprint}</span></div>
        : <div class="notice warn">La chiave di {chosen.displayName} non è ancora certificata: un amministratore deve verificarla nella pagina Utenti.</div>)}
      <div class="card">
        {members.data?.map((m) => (
          <div class="row" style="padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:nowrap">
            <div class="avatar">{initials(m.displayName)}</div>
            <div class="grow">
              <div style="font-weight:500">{m.displayName}{m.userId === vault.me.id ? " (tu)" : ""}</div>
              <div class="small muted">{m.email}</div>
            </div>
            <select class="input" style="width:auto" aria-label={`Permesso di ${m.displayName}`} value={m.permission} disabled={busy}
              onChange={(e) => { const p = e.currentTarget.value as Permission; run(async () => { await vault.share(container.id, m.userId, p); members.reload(); }); }}>
              {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM_LABEL[p]}</option>)}
            </select>
            {m.userId !== vault.me.id && <button class="btn sm ghost danger" onClick={() => setConfirmRevoke(m.userId)}>Rimuovi</button>}
          </div>
        ))}
      </div>
      <div class="notice info">La chiave del cliente viene cifrata qui, con la chiave pubblica certificata di ogni destinatario. Rimuovendo una persona la chiave viene ruotata subito.</div>
      <ErrorNote error={error} />
      {confirmRevoke && (
        <Dialog title="Rimuovere l'accesso?" onClose={() => setConfirmRevoke(null)}>
          <p>La chiave del cliente verrà sostituita e tutte le chiavi degli elementi ricifrate. Le password già viste da questa persona andrebbero cambiate alla fonte.</p>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirmRevoke(null)}>Annulla</button>
            <button class="btn primary" disabled={busy} onClick={() => run(async () => {
              await vault.revoke(container.id, confirmRevoke);
              setConfirmRevoke(null);
              members.reload();
              toast("Accesso rimosso e chiave ruotata");
            })}>{busy ? "Rotazione…" : "Rimuovi e ruota la chiave"}</button>
          </div>
        </Dialog>
      )}
    </Dialog>
  );
}

export { signOut };
