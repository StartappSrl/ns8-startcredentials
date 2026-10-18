import { ComponentChildren } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { Container, DirectoryUser, effectiveTotpUri, Folder, generatePassword, Item, ItemData, KEEPASS_TOTP_FIELDS, Permission, Vault } from "@startcredentials/client";
import { download, initials, loadCollapsed, lock, relTime, saveCollapsed, signOut, tint } from "../shared";
import { Brand, CopyButton, Dialog, ErrorNote, Meter, OtpCode, Secret, useAction, useLoad, useToast } from "./kit";

/** Indirizzo apribile: senza protocollo si usa HTTPS; solo http/https sono ammessi. */
export function siteUrl(u: string): string {
  const t = u.trim();
  if (/^https?:\/\//i.test(t)) return t;
  if (/^[a-z][a-z0-9+.-]*:/i.test(t)) return "about:blank";
  return `https://${t}`;
}

export function openSite(u: string): void {
  const url = siteUrl(u);
  if (url === "about:blank") return;
  if (typeof chrome !== "undefined" && chrome.tabs?.create) void chrome.tabs.create({ url });
  else window.open(url, "_blank", "noopener");
}

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
        <div style="padding:0 8px"><Brand /></div>
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
            {link("/admin/gruppi", "Gruppi")}
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
  const [selecting, setSelecting] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
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
        {!shared && containers.some((c) => c.kind === "client" && c.permission === "manage") && !selecting && (
          <button class="btn" onClick={() => setSelecting(true)}>Seleziona</button>
        )}
        {!shared && vault.me.role === "admin" && <button class="btn primary" onClick={() => setCreating(true)}>Nuovo cliente</button>}
      </div>
      {selecting && (
        <div class="bulk-bar card" role="toolbar" aria-label="Azioni sui clienti selezionati">
          <span class="grow" aria-live="polite"><b>{picked.size}</b> {picked.size === 1 ? "cliente selezionato" : "clienti selezionati"}</span>
          <button class="btn sm ghost" onClick={() => setPicked(new Set(list.filter((c) => c.permission === "manage").map((c) => c.id)))}>
            Seleziona tutti quelli che gestisci ({list.filter((c) => c.permission === "manage").length})
          </button>
          <button class="btn sm ghost" disabled={!picked.size} onClick={() => setPicked(new Set())}>Deseleziona</button>
          <button class="btn sm primary" disabled={!picked.size} onClick={() => setBulk(true)}>Condividi o togli accesso</button>
          <button class="btn sm" onClick={() => { setSelecting(false); setPicked(new Set()); }}>Fine</button>
        </div>
      )}
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
          {!shared && !q && vault.me.role === "admin" && <button class="btn primary" onClick={() => setCreating(true)}>Crea il primo cliente</button>}
          {!shared && !q && vault.me.role !== "admin" && <p class="small">I clienti li crea un amministratore: quando ne condividerà uno con te, lo troverai qui.</p>}
        </div>
      ) : (
        <div class="grid">
          {list.map((c) => {
            const t = tint(c.id);
            return (
              <button class={`client${selecting && picked.has(c.id) ? " picked" : ""}`} aria-pressed={selecting ? picked.has(c.id) : undefined}
                disabled={selecting && c.permission !== "manage"}
                title={selecting && c.permission !== "manage" ? "Solo i gestori del cliente possono condividerlo" : undefined}
                onClick={() => {
                  if (!selecting) return go(`/c/${c.id}`);
                  setPicked((prev) => { const n = new Set(prev); if (n.has(c.id)) n.delete(c.id); else n.add(c.id); return n; });
                }}>
                <div class="row" style="flex-wrap:nowrap">
                  {selecting && <input type="checkbox" class="row-check" tabIndex={-1} checked={picked.has(c.id)} disabled={c.permission !== "manage"} aria-hidden="true" />}
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
      {bulk && (
        <BulkShareDialog vault={vault} containers={containers.filter((c) => picked.has(c.id))}
          onClose={(changed) => { setBulk(false); if (changed) { setSelecting(false); setPicked(new Set()); reload(); } }} />
      )}
    </>
  );
}

/** Condivisione (o revoca) di più clienti insieme con colleghi e gruppi. */
function BulkShareDialog({ vault, containers, onClose }: { vault: Vault; containers: Container[]; onClose: (changed: boolean) => void }) {
  const dir = useLoad(() => vault.directory(true), []);
  const groups = useLoad(() => vault.groups(), []);
  const [mode, setMode] = useState<"add" | "remove">("add");
  const [users, setUsers] = useState<Set<string>>(new Set());
  const [grps, setGrps] = useState<Set<string>>(new Set());
  const [perm, setPerm] = useState<Permission>("read");
  const [overwrite, setOverwrite] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<{ done: number; unchanged: number; failed: { containerId: string; target: string; error: string }[] } | null>(null);
  const { busy, error, run } = useAction();
  const toggle = (set: Set<string>, setter: (s: Set<string>) => void, id: string) => { const n = new Set(set); if (n.has(id)) n.delete(id); else n.add(id); setter(n); };
  const people = (dir.data ?? []).filter((u) => u.status === "active" && u.id !== vault.me.id);
  const usable = (groups.data ?? []).filter((g) => g.verified && !g.rotationRequired);
  const name = (id: string) => people.find((u) => u.id === id)?.displayName ?? usable.find((g) => g.id === id)?.name ?? id;
  const cname = (id: string) => containers.find((c) => c.id === id)?.meta.name ?? id;

  if (result) {
    return (
      <Dialog title={mode === "add" ? "Condivisione completata" : "Revoca completata"} onClose={() => onClose(true)}>
        <div class="notice ok">
          {mode === "add"
            ? `${result.done} ${result.done === 1 ? "accesso concesso" : "accessi concessi"}`
            : `${result.done} ${result.done === 1 ? "accesso tolto" : "accessi tolti"}, chiavi ruotate`} su {containers.length} {containers.length === 1 ? "cliente" : "clienti"}.
          {result.unchanged ? ` ${result.unchanged} ${mode === "add" ? (result.unchanged === 1 ? "già presente (nessun declassamento)" : "già presenti (nessun declassamento)") : (result.unchanged === 1 ? "cliente senza nulla da togliere" : "clienti senza nulla da togliere")}.` : ""}
        </div>
        {result.failed.length > 0 && (
          <div class="notice warn">
            Non riusciti: {result.failed.map((f) => `${cname(f.containerId)}${f.target.includes(",") ? "" : ` – ${name(f.target)}`} (${f.error})`).join("; ")}.
          </div>
        )}
        <div class="row" style="justify-content:flex-end"><button class="btn primary" onClick={() => onClose(true)}>Fatto</button></div>
      </Dialog>
    );
  }
  return (
    <Dialog title={`${containers.length} ${containers.length === 1 ? "cliente selezionato" : "clienti selezionati"}`} onClose={() => onClose(false)} wide>
      <div class="chips" role="group" aria-label="Operazione">
        <button class={`chip${mode === "add" ? " on" : ""}`} aria-pressed={mode === "add"} onClick={() => setMode("add")}>Dai accesso</button>
        <button class={`chip${mode === "remove" ? " on" : ""}`} aria-pressed={mode === "remove"} onClick={() => setMode("remove")}>Togli accesso</button>
      </div>
      <div class="small muted ellipsis">{containers.map((c) => c.meta.name).join(", ")}</div>
      <div class="split" style="grid-template-columns:1fr 1fr">
        <div class="card" style="max-height:260px;overflow:auto">
          <div class="group-h"><span>Colleghi</span><span>{users.size}</span></div>
          {people.map((u) => (
            <label class="item-row" style="cursor:pointer">
              <input type="checkbox" class="row-check" checked={users.has(u.id)} disabled={mode === "add" && !u.verified} onChange={() => toggle(users, setUsers, u.id)} />
              <span class="grow"><span style="display:block;font-weight:500">{u.displayName}</span><span class="small muted">{u.email}{!u.verified ? " · chiave da certificare" : ""}</span></span>
            </label>
          ))}
        </div>
        <div class="card" style="max-height:260px;overflow:auto">
          <div class="group-h"><span>Gruppi</span><span>{grps.size}</span></div>
          {usable.length === 0 && <div class="small muted" style="padding:10px 14px">Nessun gruppo.</div>}
          {usable.map((g) => (
            <label class="item-row" style="cursor:pointer">
              <input type="checkbox" class="row-check" checked={grps.has(g.id)} onChange={() => toggle(grps, setGrps, g.id)} />
              <span class="grow"><span style="display:block;font-weight:500">{g.name}</span><span class="small muted">{g.members} {g.members === 1 ? "persona" : "persone"}</span></span>
            </label>
          ))}
        </div>
      </div>
      {mode === "add" ? (
        <div class="row" style="align-items:flex-end">
          <label class="field">Permesso
            <select class="input" value={perm} onChange={(e) => setPerm(e.currentTarget.value as Permission)}>
              {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM_LABEL[p]}</option>)}
            </select>
          </label>
          <label class="check grow"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.currentTarget.checked)} />
            Allinea anche chi ha già un permesso più alto (altrimenti resta com'è)</label>
        </div>
      ) : (
        <div class="notice info">Ai clienti selezionati verrà tolto l'accesso dei colleghi e dei gruppi scelti; la chiave di ogni cliente coinvolto viene ruotata.</div>
      )}
      <ErrorNote error={error} />
      <div class="row" style="justify-content:flex-end">
        <button class="btn" onClick={() => onClose(false)}>Annulla</button>
        <button class={`btn ${mode === "add" ? "primary" : "danger"}`} disabled={busy || (!users.size && !grps.size)} onClick={() => run(async () => {
          const onProgress = (d: number, t: number) => setProgress(`${d} di ${t}`);
          const to = { userIds: [...users], groupIds: [...grps] };
          setResult(mode === "add" ? await vault.shareMany(containers.map((c) => c.id), to, perm, { overwrite, onProgress }) : await vault.revokeMany(containers.map((c) => c.id), to, { onProgress }));
        })}>
          {busy ? `Cifratura ${progress ?? "…"}` : mode === "add" ? `Dai accesso a ${containers.length} clienti` : `Togli accesso da ${containers.length} clienti`}
        </button>
      </div>
    </Dialog>
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

export function ContainerView({ vault, id, focusItem, onChanged }: { vault: Vault; id: string; focusItem?: string; onChanged: () => void }) {
  const [tab, setTab] = useState<Tab>("all");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<Item | "new" | null>(null);
  const [sharing, setSharing] = useState(false);
  const [editMeta, setEditMeta] = useState(false);
  const [newFolder, setNewFolder] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selecting, setSelecting] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [confirmBulk, setConfirmBulk] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveTarget, setMoveTarget] = useState("");
  const bulk = useAction();
  useEffect(() => { setChecked(new Set()); }, [tab, id]);
  useEffect(() => { void loadCollapsed(id).then((ids) => setCollapsed(new Set(ids))); }, [id]);
  const info = useLoad(() => vault.container(id), [id]);
  const items = useLoad(() => vault.items(id, { trash: tab === "trash" }), [id, tab === "trash"]);
  const toast = useToast();
  // Arrivo da ricerca o rapporto: seleziona l'elemento, apre le sue cartelle e lo porta in vista.
  // Cambiamenti fatti dai colleghi su questo cliente: si ricarica, salvo durante una modifica.
  useEffect(() => {
    const onChanges = (e: Event) => {
      const ids = (e as CustomEvent<string[]>).detail ?? [];
      if (!ids.includes(id) || editing) return;
      items.reload();
      info.reload();
    };
    window.addEventListener("sc-changes", onChanges);
    return () => window.removeEventListener("sc-changes", onChanges);
  }, [id, editing]);
  const focused = useRef<string | null>(null);
  useEffect(() => {
    if (!focusItem || focused.current === focusItem || !items.data || !info.data) return;
    const it = items.data.find((i) => i.id === focusItem);
    if (!it) return;
    focused.current = focusItem;
    setTab("all");
    setQ("");
    setSelected(it.id);
    const ancestors = new Set<string>();
    let f = info.data.folders.find((x) => x.id === it.folderId);
    for (let guard = 0; f && guard < 50; guard++) {
      ancestors.add(f.id);
      f = info.data.folders.find((x) => x.id === f!.parentId);
    }
    setCollapsed((prev) => new Set([...prev].filter((x) => !ancestors.has(x))));
    setTimeout(() => document.querySelector(`[data-item="${it.id}"]`)?.scrollIntoView?.({ block: "center" }), 50);
  }, [focusItem, items.data, info.data]);
  const c = info.data;

  const visible = useMemo(() => {
    let l = items.data ?? [];
    if (tab === "login") l = l.filter((i) => i.type === "login");
    if (tab === "totp") l = l.filter((i) => !!effectiveTotpUri(i.data));
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

  // Albero delle cartelle: figli ordinati per nome, conteggi comprensivi delle sottocartelle.
  const children = new Map<string | null, Folder[]>();
  for (const f of c.folders) {
    const k = f.parentId ?? null;
    children.set(k, [...(children.get(k) ?? []), f].sort((a, b) => a.name.localeCompare(b.name, "it")));
  }
  const itemsIn = (fid: string | null) => visible.filter((i) => (i.folderId ?? null) === fid);
  const countDeep = (fid: string): number => itemsIn(fid).length + (children.get(fid) ?? []).reduce((n, ch) => n + countDeep(ch.id), 0);
  const deepItems = (fid: string): Item[] => [...itemsIn(fid), ...(children.get(fid) ?? []).flatMap((ch) => deepItems(ch.id))];
  // Aggiornamenti calcolati sullo stato più recente: clic rapidi non si sovrascrivono.
  const toggleItem = (iid: string) => setChecked((prev) => {
    const next = new Set(prev);
    if (next.has(iid)) next.delete(iid);
    else next.add(iid);
    return next;
  });
  const toggleFolder = (fid: string) => {
    const ids = deepItems(fid).map((i) => i.id);
    setChecked((prev) => {
      const all = ids.length > 0 && ids.every((x) => prev.has(x));
      const next = new Set(prev);
      for (const x of ids) {
        if (all) next.delete(x);
        else next.add(x);
      }
      return next;
    });
  };
  const endSelection = () => { setSelecting(false); setChecked(new Set()); };
  const runMove = () => bulk.run(async () => {
    const n = await vault.moveItems(id, [...checked], moveTarget || null);
    setMoveOpen(false);
    endSelection();
    reloadAll();
    toast(`${n} ${n === 1 ? "elemento spostato" : "elementi spostati"}`);
  });
  const runBulk = (action: "delete" | "restore") => bulk.run(async () => {
    const ids = [...checked];
    const n = action === "delete" ? await vault.deleteItems(id, ids) : await vault.restoreItems(id, ids);
    if (selected && checked.has(selected)) setSelected(null);
    setConfirmBulk(false);
    endSelection();
    reloadAll();
    toast(action === "delete" ? `${n} ${n === 1 ? "elemento spostato" : "elementi spostati"} nel cestino` : `${n} ${n === 1 ? "elemento ripristinato" : "elementi ripristinati"}`);
  });

  // Con ricerca o filtri attivi si aprono solo le cartelle che contengono risultati.
  const filtering = !!q || tab !== "all";
  const toggle = (fid: string) => setCollapsed((prev) => {
    const next = new Set(prev);
    if (next.has(fid)) next.delete(fid);
    else next.add(fid);
    void saveCollapsed(id, [...next]);
    return next;
  });
  const setAll = (close: boolean) => {
    const next = new Set(close ? c.folders.map((f) => f.id) : []);
    setCollapsed(next);
    void saveCollapsed(id, [...next]);
  };

  const itemContent = (i: Item) => (
    <>
      <span class="kind">{TYPE_TAG[i.type]}</span>
      <span class="grow">
        <span class="ellipsis" style="display:block;font-weight:500">{i.data.name}</span>
        <span class="ellipsis small muted" style="display:block">{i.data.username || (i.data.urls?.[0] ?? TYPE_LABEL[i.type])}</span>
      </span>
      <span class="small muted">{[effectiveTotpUri(i.data) && "OTP", i.attachments.length && `${i.attachments.length} file`].filter(Boolean).join(" · ")}</span>
    </>
  );
  const renderItem = (i: Item, depth: number) => selecting ? (
    <label class={`item-row${checked.has(i.id) ? " on" : ""}`} data-item={i.id} style={`padding-left:${18 + depth * 20}px;cursor:pointer`}>
      <input type="checkbox" class="row-check" checked={checked.has(i.id)} onChange={() => toggleItem(i.id)} aria-label={`Seleziona ${i.data.name}`} />
      {itemContent(i)}
    </label>
  ) : (
    <button class={`item-row${i.id === selected ? " on" : ""}`} data-item={i.id} aria-current={i.id === selected ? "true" : undefined} style={`padding-left:${18 + depth * 20}px`} onClick={() => setSelected(i.id)}>
      {itemContent(i)}
    </button>
  );

  const renderFolder = (f: Folder, depth: number): ComponentChildren => {
    const n = countDeep(f.id);
    if (filtering && n === 0) return null;
    const open = filtering || !collapsed.has(f.id);
    const kids = children.get(f.id) ?? [];
    return (
      <>
        <div class="group-h" style={`padding-left:${10 + depth * 20}px`}>
          {selecting && n > 0 && (
            <input type="checkbox" class="row-check" aria-label={`Seleziona tutta la cartella ${f.name}`}
              checked={deepItems(f.id).every((x) => checked.has(x.id))} onChange={() => toggleFolder(f.id)} />
          )}
          <button class="folder-toggle" aria-expanded={open} disabled={filtering} onClick={() => toggle(f.id)}>
            <svg class={`chevron${open ? " open" : ""}`} aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6" /></svg>
            <span>{f.name}</span>
          </button>
          <span class="row" style="gap:6px">
            {n}
            {canWrite && !filtering && n === 0 && kids.length === 0 && (
              <button class="btn ghost sm" style="min-height:24px;padding:0 6px" onClick={async () => { await vault.deleteFolder(f.id); info.reload(); }}>Elimina</button>
            )}
          </span>
        </div>
        {open && itemsIn(f.id).map((i) => renderItem(i, depth + 1))}
        {open && kids.map((k) => renderFolder(k, depth + 1))}
      </>
    );
  };
  const rootItems = itemsIn(null);

  return (
    <>
      {c.kind === "client" && <div class="small muted"><a href="#/clienti">Clienti</a> / {c.meta.name}</div>}
      <div class="row between">
        <div class="row" style="flex-wrap:nowrap">
          <div class="mono-tile" style={`width:52px;height:52px;font-size:18px;background:${t.bg};color:${t.fg}`}>{initials(c.meta.name)}</div>
          <div>
            <h1>{c.meta.name}</h1>
            <div class="muted">
              {c.kind === "personal" ? "Visibile solo a te" : `${c.meta.sector ? `${c.meta.sector} · ` : ""}${c.members} ${c.members === 1 ? "persona" : "persone"}${c.groups ? ` e ${c.groups} ${c.groups === 1 ? "gruppo" : "gruppi"}` : ""} · ${PERM_LABEL[c.permission]}${c.viaGroups.length ? ` tramite il gruppo ${c.viaGroups.join(", ")}` : ""}`}
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
        <div class="row" style="gap:6px">
          {canWrite && !selecting && visible.length > 0 && <button class="btn sm" onClick={() => setSelecting(true)}>Seleziona</button>}
          {c.folders.length > 0 && !filtering && (
            <>
              <button class="btn sm ghost" onClick={() => setAll(false)}>Espandi tutto</button>
              <button class="btn sm ghost" onClick={() => setAll(true)}>Comprimi tutto</button>
            </>
          )}
        <input class="input" type="search" style="max-width:260px" aria-label="Cerca nel cliente" placeholder="Cerca nel cliente…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        </div>
      </div>

      <div class="split">
        <section class="card list" aria-label="Elementi">
          {selecting && (
            <div class="bulk-bar" role="toolbar" aria-label="Azioni sugli elementi selezionati">
              <span class="grow" aria-live="polite"><b>{checked.size}</b> {checked.size === 1 ? "selezionato" : "selezionati"}</span>
              <button class="btn sm ghost" onClick={() => setChecked(new Set(visible.map((i) => i.id)))}>Seleziona tutti ({visible.length})</button>
              <button class="btn sm ghost" disabled={!checked.size} onClick={() => setChecked(new Set())}>Deseleziona</button>
              {tab === "trash"
                ? <button class="btn sm primary" disabled={!checked.size || bulk.busy} onClick={() => runBulk("restore")}>Ripristina</button>
                : (
                  <>
                    <button class="btn sm" disabled={!checked.size || bulk.busy} onClick={() => { setMoveTarget(""); setMoveOpen(true); }}>Sposta in cartella</button>
                    <button class="btn sm danger" disabled={!checked.size || bulk.busy} onClick={() => setConfirmBulk(true)}>Sposta nel cestino</button>
                  </>
                )}
              <button class="btn sm" onClick={endSelection}>Fine</button>
            </div>
          )}
          {selecting && <ErrorNote error={bulk.error} />}
          {items.loading && !items.data && <div class="empty">Decifratura…</div>}
          {items.data && visible.length === 0 && (
            <div class="empty">
              <h3>{tab === "trash" ? "Il cestino è vuoto" : q ? "Nessun risultato" : "Nessun elemento"}</h3>
              {tab !== "trash" && canWrite && !q && <button class="btn primary" onClick={() => setEditing("new")}>Aggiungi una password</button>}
              {tab === "trash" && <p class="small">Gli elementi eliminati restano qui 30 giorni.</p>}
            </div>
          )}
          {c.folders.length > 0 && rootItems.length > 0 && <div class="group-h"><span style="padding-left:4px">Senza cartella</span><span>{rootItems.length}</span></div>}
          {rootItems.map((i) => renderItem(i, 0))}
          {(children.get(null) ?? []).map((f) => renderFolder(f, 0))}
        </section>
        <aside class="detail">
          {sel ? (
            <ItemDetail key={sel.id} vault={vault} item={sel} canWrite={canWrite} canShare={canManage && c.kind === "client"} folders={c.folders}
              onEdit={() => setEditing(sel)} onChanged={reloadAll}
              onDeleted={() => { setSelected(null); reloadAll(); toast(tab === "trash" ? "Elemento ripristinato" : "Elemento spostato nel cestino"); }} />
          ) : (
            <div class="card empty"><p>Seleziona un elemento per vederne i dettagli.</p></div>
          )}
        </aside>
      </div>

      {editing && <ItemEditor vault={vault} containerId={id} folders={c.folders} item={editing === "new" ? undefined : editing}
        onClose={() => setEditing(null)} onSaved={(iid) => { setEditing(null); setSelected(iid); reloadAll(); toast("Salvato"); }} />}
      {moveOpen && (
        <Dialog title={`Spostare ${checked.size} ${checked.size === 1 ? "elemento" : "elementi"}`} onClose={() => setMoveOpen(false)}>
          <label class="field">Nella cartella
            <select class="input" value={moveTarget} onChange={(e) => setMoveTarget(e.currentTarget.value)}>
              <option value="">Nessuna cartella</option>
              {[...c.folders].sort((a, b) => folderPath(c.folders, a.id).localeCompare(folderPath(c.folders, b.id), "it")).map((f) => <option value={f.id}>{folderPath(c.folders, f.id)}</option>)}
            </select>
          </label>
          <ErrorNote error={bulk.error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setMoveOpen(false)}>Annulla</button>
            <button class="btn primary" disabled={bulk.busy} onClick={runMove}>{bulk.busy ? "Spostamento…" : "Sposta"}</button>
          </div>
        </Dialog>
      )}
      {confirmBulk && (
        <Dialog title={`Spostare ${checked.size} ${checked.size === 1 ? "elemento" : "elementi"} nel cestino?`} onClose={() => setConfirmBulk(false)}>
          <p>Restano recuperabili dal Cestino per 30 giorni, poi vengono eliminati definitivamente. Gli altri membri del cliente non li vedranno più.</p>
          <ErrorNote error={bulk.error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirmBulk(false)}>Annulla</button>
            <button class="btn primary" style="background:var(--danger);border-color:var(--danger)" disabled={bulk.busy} onClick={() => runBulk("delete")}>
              {bulk.busy ? "Spostamento…" : "Sposta nel cestino"}
            </button>
          </div>
        </Dialog>
      )}
      {sharing && <ShareDialog vault={vault} container={c} onClose={() => { setSharing(false); reloadAll(); }} />}
      {editMeta && <ContainerDialog vault={vault} container={c} onClose={() => setEditMeta(false)} onSaved={() => { setEditMeta(false); reloadAll(); }} />}
      {newFolder && <FolderDialog vault={vault} containerId={id} folders={c.folders} onClose={() => setNewFolder(false)} onSaved={() => { setNewFolder(false); info.reload(); }} />}
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

function FolderDialog({ vault, containerId, folders, onClose, onSaved }: { vault: Vault; containerId: string; folders: Folder[]; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [parent, setParent] = useState("");
  const { busy, error, run } = useAction();
  const options = folders.map((f) => ({ id: f.id, path: folderPath(folders, f.id) })).sort((a, b) => a.path.localeCompare(b.path, "it"));
  return (
    <Dialog title="Nuova cartella" onClose={onClose}>
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await vault.createFolder(containerId, name.trim(), parent || null); onSaved(); }); }}>
        <label class="field">Nome<input class="input" required autoFocus value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Rete e server" /></label>
        {options.length > 0 && (
          <label class="field">Dentro la cartella
            <select class="input" value={parent} onChange={(e) => setParent(e.currentTarget.value)}>
              <option value="">Nessuna (primo livello)</option>
              {options.map((o) => <option value={o.id}>{o.path}</option>)}
            </select>
          </label>
        )}
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>Crea cartella</button>
        </div>
      </form>
    </Dialog>
  );
}

/** Percorso completo di una cartella: "Rete / Server". */
export function folderPath(folders: Folder[], id: string | null): string {
  const parts: string[] = [];
  let f = folders.find((x) => x.id === id);
  for (let guard = 0; f && guard < 50; guard++) {
    parts.unshift(f.name);
    f = folders.find((x) => x.id === f!.parentId);
  }
  return parts.join(" / ");
}

// ------------------------------------------------------------------ dettaglio elemento

export function ItemDetail({ vault, item, canWrite, canShare, folders, onEdit, onChanged, onDeleted }: {
  vault: Vault; item: Item; canWrite: boolean; canShare?: boolean; folders: Folder[]; onEdit: () => void; onChanged: () => void; onDeleted: () => void;
}) {
  const d = item.data;
  const [sharing, setSharing] = useState(false);
  const [history, setHistory] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const { error, run } = useAction();
  const report = (a: Parameters<Vault["report"]>[0]) => vault.report(a, item.containerId, item.id);
  const folder = item.folderId ? folderPath(folders, item.folderId) : "";
  return (
    <div class="card pad stack">
      <div>
        <h2 style="word-break:break-word">{d.name}</h2>
        <div class="small muted">{TYPE_LABEL[d.type]}{folder ? ` · ${folder}` : ""}</div>

      </div>
      {item.deletedAt && <div class="notice warn">Nel cestino dal {new Date(item.deletedAt).toLocaleDateString("it-IT")}</div>}
      {(d.urls ?? []).length > 0 && (
        <div class="stack" style="gap:6px">
          <span class="small muted">{(d.urls ?? []).length > 1 ? "Siti" : "Sito"}</span>
          {(d.urls ?? []).map((u) => (
            <div class="input-group">
              <a class="input mono ellipsis site-link" href={siteUrl(u)} target="_blank" rel="noopener noreferrer" title={`Apri ${u}`}>{u}</a>
              <button class="btn sm" type="button" onClick={() => openSite(u)}>Apri</button>
              <CopyButton value={u} />
            </div>
          ))}
        </div>
      )}
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
      {effectiveTotpUri(d) && <OtpCode uri={effectiveTotpUri(d)!} onCopy={() => report("item.totp_copy")} />}
      {d.notes && (
        <div class="stack" style="gap:6px">
          <span class="small muted">Note</span>
          <div style="white-space:pre-wrap;word-break:break-word" class="file">{d.notes}</div>
        </div>
      )}
      {(d.fields ?? []).filter((f) => !(effectiveTotpUri(d) && KEEPASS_TOTP_FIELDS.includes(f.label))).map((f) => (
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
        {!item.sharedBy && <button class="btn sm" onClick={() => setHistory(true)}>Cronologia</button>}
        {canShare && !item.deletedAt && <button class="btn sm" onClick={() => setSharing(true)}>Condividi solo questa password{item.shares ? ` (${item.shares})` : ""}</button>}
        {canWrite && (item.deletedAt
          ? <button class="btn sm" onClick={() => run(async () => { await vault.restoreItem(item.id); onDeleted(); })}>Ripristina</button>
          : <button class="btn sm ghost danger" onClick={() => run(async () => { await vault.deleteItem(item.id); onDeleted(); })}>Sposta nel cestino</button>)}
      </div>
      <div class="small muted">Modificato da {item.updatedBy} · {relTime(item.updatedAt)} · revisione {item.revision}</div>
      {history && <HistoryDialog vault={vault} item={item} onClose={() => setHistory(false)} />}
      {sharing && <ItemShareDialog vault={vault} item={item} onClose={() => { setSharing(false); onChanged(); }} />}
      {item.sharedBy && <div class="notice info">Condivisa con te da {item.sharedBy}, in sola lettura.</div>}
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
  // Gli elementi importati con i campi OTP di KeePass vengono convertiti al salvataggio.
  const legacyTotp = !!d && !d.totpUri && !!effectiveTotpUri(d);
  const [totp, setTotp] = useState(d ? effectiveTotpUri(d) ?? "" : "");
  const [notes, setNotes] = useState(d?.notes ?? "");
  const [folderId, setFolderId] = useState(item?.folderId ?? "");
  const [fields, setFields] = useState((d?.fields ?? []).filter((f) => !legacyTotp || !KEEPASS_TOTP_FIELDS.includes(f.label)));
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
                <option value="">Nessuna</option>{[...folders].sort((a, b) => folderPath(folders, a.id).localeCompare(folderPath(folders, b.id), "it")).map((f) => <option value={f.id}>{folderPath(folders, f.id)}</option>)}
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
      <GroupShares vault={vault} container={container} />
      <div class="notice info">La chiave del cliente viene cifrata qui, con la chiave pubblica certificata di ogni destinatario o gruppo. Rimuovendo una persona o un gruppo la chiave viene ruotata subito.</div>
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

function ItemShareDialog({ vault, item, onClose }: { vault: Vault; item: Item; onClose: () => void }) {
  const shares = useLoad(() => vault.itemShares(item.id), [item.id]);
  const dir = useLoad(() => vault.directory(true), []);
  const [pick, setPick] = useState("");
  const [confirm, setConfirm] = useState<{ userId: string; name: string } | null>(null);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const candidates = (dir.data ?? []).filter((u) => u.status === "active" && u.id !== vault.me.id && !shares.data?.some((x) => x.userId === u.id));
  const chosen = candidates.find((u) => u.id === pick);
  return (
    <Dialog title={`Condividi «${item.data.name}»`} onClose={onClose}>
      <p class="small muted">Il collega vede solo questa password, in sola lettura, anche senza accesso al cliente. Per dargli tutto il cliente usa invece «Condividi» in alto.</p>
      <div class="row" style="flex-wrap:nowrap;align-items:flex-end">
        <label class="field grow">Collega
          <select class="input" value={pick} onChange={(e) => setPick(e.currentTarget.value)}>
            <option value="">Scegli…</option>
            {candidates.map((u) => <option value={u.id}>{u.displayName} ({u.email}){u.verified ? "" : " – chiave non certificata"}</option>)}
          </select>
        </label>
        <button class="btn primary" disabled={busy || !chosen?.verified} onClick={() => run(async () => {
          await vault.shareItem(item, pick);
          setPick("");
          shares.reload();
          toast("Password condivisa");
        })}>Condividi</button>
      </div>
      {chosen && !chosen.verified && <div class="notice warn">La chiave di {chosen.displayName} va prima certificata da un amministratore.</div>}
      {(shares.data ?? []).length > 0 && (
        <div class="card">
          {shares.data!.map((x) => (
            <div class="row" style="padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:nowrap">
              <div class="avatar">{initials(x.displayName)}</div>
              <div class="grow"><div style="font-weight:500">{x.displayName}</div><div class="small muted">{x.email}</div></div>
              <button class="btn sm ghost danger" onClick={() => setConfirm({ userId: x.userId, name: x.displayName })}>Rimuovi</button>
            </div>
          ))}
        </div>
      )}
      <ErrorNote error={error} />
      {confirm && (
        <Dialog title={`Togliere la password a ${confirm.name}?`} onClose={() => setConfirm(null)}>
          <p>La password viene ricifrata con una chiave nuova, cronologia e allegati compresi. Se {confirm.name} l'ha già vista, conviene cambiarla anche sul servizio.</p>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirm(null)}>Annulla</button>
            <button class="btn primary" disabled={busy} onClick={() => run(async () => {
              await vault.unshareItem(item, confirm.userId);
              setConfirm(null);
              shares.reload();
              toast("Condivisione rimossa e password ricifrata");
            })}>{busy ? "Ricifratura…" : "Rimuovi"}</button>
          </div>
        </Dialog>
      )}
    </Dialog>
  );
}

/** Password condivise singolarmente con l'utente (sola lettura). */
export function SharedItems({ vault, focus }: { vault: Vault; focus?: string }) {
  const items = useLoad(() => vault.sharedWithMe(), []);
  const [selected, setSelected] = useState<string | null>(focus ?? null);
  useEffect(() => { if (focus) setSelected(focus); }, [focus]);
  if (!items.data?.length) return null;
  const sel = items.data.find((i) => i.id === selected) ?? null;
  return (
    <>
      <h2>Password condivise con te</h2>
      <div class="split">
        <section class="card list" aria-label="Password condivise con te">
          {items.data.map((i) => (
            <button class={`item-row${i.id === selected ? " on" : ""}`} data-item={i.id} onClick={() => setSelected(i.id)}>
              <span class="kind">{TYPE_TAG[i.type]}</span>
              <span class="grow">
                <span class="ellipsis" style="display:block;font-weight:500">{i.data.name}</span>
                <span class="ellipsis small muted" style="display:block">da {i.sharedBy}{i.data.username ? ` · ${i.data.username}` : ""}</span>
              </span>
            </button>
          ))}
        </section>
        <aside class="detail">
          {sel ? <ItemDetail key={sel.id} vault={vault} item={sel} canWrite={false} folders={[]} onEdit={() => undefined} onChanged={items.reload} onDeleted={items.reload} />
               : <div class="card empty"><p>Seleziona una password per vederne i dettagli.</p></div>}
        </aside>
      </div>
    </>
  );
}

function GroupShares({ vault, container }: { vault: Vault; container: Container }) {
  const shared = useLoad(() => vault.containerGroups(container.id), [container.id]);
  const groups = useLoad(() => vault.groups(), []);
  const [pick, setPick] = useState("");
  const [perm, setPerm] = useState<Permission>("read");
  const [confirm, setConfirm] = useState<{ groupId: string; name: string } | null>(null);
  const { busy, error, run } = useAction();
  const toast = useToast();
  const available = (groups.data ?? []).filter((g) => g.verified && !g.rotationRequired && !shared.data?.some((x) => x.groupId === g.id));
  if (!groups.data?.length) return null;
  return (
    <div class="stack">
      <h3>Gruppi</h3>
      <div class="row" style="flex-wrap:nowrap;align-items:flex-end">
        <label class="field grow">Condividi con un gruppo
          <select class="input" value={pick} onChange={(e) => setPick(e.currentTarget.value)}>
            <option value="">Scegli…</option>
            {available.map((g) => <option value={g.id}>{g.name} ({g.members} {g.members === 1 ? "persona" : "persone"})</option>)}
          </select>
        </label>
        <label class="field">Permesso del gruppo
          <select class="input" value={perm} onChange={(e) => setPerm(e.currentTarget.value as Permission)}>
            {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM_LABEL[p]}</option>)}
          </select>
        </label>
        <button class="btn primary" disabled={busy || !pick} onClick={() => run(async () => {
          await vault.shareWithGroup(container.id, pick, perm);
          setPick("");
          shared.reload();
          toast("Condiviso con il gruppo");
        })}>Condividi con il gruppo</button>
      </div>
      {(shared.data ?? []).length > 0 && (
        <div class="card">
          {shared.data!.map((g) => (
            <div class="row" style="padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:nowrap">
              <div class="avatar">{initials(g.name)}</div>
              <div class="grow">
                <div style="font-weight:500">Gruppo {g.name}</div>
                <div class="small muted">{g.members} {g.members === 1 ? "persona" : "persone"}</div>
              </div>
              <select class="input" style="width:auto" aria-label={`Permesso del gruppo ${g.name}`} value={g.permission} disabled={busy}
                onChange={(e) => { const p = e.currentTarget.value as Permission; run(async () => { await vault.shareWithGroup(container.id, g.groupId, p); shared.reload(); }); }}>
                {(["read", "write", "manage"] as const).map((p) => <option value={p}>{PERM_LABEL[p]}</option>)}
              </select>
              <button class="btn sm ghost danger" onClick={() => setConfirm({ groupId: g.groupId, name: g.name })}>Rimuovi</button>
            </div>
          ))}
        </div>
      )}
      <ErrorNote error={error} />
      {confirm && (
        <Dialog title={`Togliere il gruppo ${confirm.name}?`} onClose={() => setConfirm(null)}>
          <p>Tutti i membri del gruppo perdono l'accesso a questo cliente, salvo chi ce l'ha anche direttamente. La chiave del cliente viene ruotata subito.</p>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button class="btn" onClick={() => setConfirm(null)}>Annulla</button>
            <button class="btn primary" disabled={busy} onClick={() => run(async () => {
              await vault.unshareGroup(container.id, confirm.groupId);
              setConfirm(null);
              shared.reload();
              toast("Gruppo rimosso e chiave ruotata");
            })}>{busy ? "Rotazione…" : "Rimuovi e ruota la chiave"}</button>
          </div>
        </Dialog>
      )}
    </div>
  );
}

export { signOut };
