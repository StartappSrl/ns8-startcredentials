import { ReactElement, useCallback, useEffect, useMemo, useState } from "react";
import { ActivityIndicator, FlatList, Linking, Pressable, RefreshControl, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { File, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import type { Container, Folder, Item } from "@startcredentials/client";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { Button, CopyButton, Notice, OtpView } from "../ui/kit";
import { color, mono } from "../theme";

const where = (c: { kind: string; meta: { name: string } }) => (c.kind === "personal" ? "Area personale" : c.meta.name);
const initials = (n: string) => n.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]!.toUpperCase()).join("");

export function Header({ title, subtitle, back }: { title: string; subtitle?: string; back?: boolean }) {
  const app = useApp();
  return (
    <View style={st.header}>
      {back && <Pressable accessibilityRole="button" accessibilityLabel="Indietro" onPress={app.pop} hitSlop={12} style={{ paddingRight: 8 }}><Text style={{ fontSize: 24, color: color.accent }}>‹</Text></Pressable>}
      <View style={{ flex: 1 }}>
        <Text style={st.title} numberOfLines={1} accessibilityRole="header">{title}</Text>
        {subtitle && <Text style={st.subtitle} numberOfLines={1}>{subtitle}</Text>}
      </View>
    </View>
  );
}

function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return <TextInput value={value} onChangeText={onChange} placeholder={placeholder} placeholderTextColor={color.muted} style={st.search} autoCorrect={false} autoCapitalize="none" accessibilityLabel={placeholder} />;
}

function ItemRow({ item, subtitle, depth = 0, onPress }: { item: Item; subtitle?: string; depth?: number; onPress: () => void }) {
  return (
    <Pressable onPress={onPress} accessibilityRole="button" style={({ pressed }) => [st.row, { paddingLeft: 16 + depth * 18 }, pressed && { backgroundColor: color.accentSoft }]}>
      <View style={st.kind}><Text style={st.kindText}>{item.type === "note" ? "NOTA" : "PWD"}</Text></View>
      <View style={{ flex: 1 }}>
        <Text style={st.rowTitle} numberOfLines={1}>{item.data.name}</Text>
        <Text style={st.rowSub} numberOfLines={1}>{subtitle ?? (item.data.username || item.data.urls?.[0] || "")}</Text>
      </View>
    </Pressable>
  );
}

// ------------------------------------------------------------------ clienti

export function ClientsScreen() {
  const engine = useEngine();
  const app = useApp();
  const [list, setList] = useState<Container[] | null>(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const load = useCallback(async () => {
    try {
      const cs = await engine.call<Container[]>("containers");
      setList(cs.filter((c) => c.kind !== "org").sort((a, b) => (a.kind === "personal" ? -1 : b.kind === "personal" ? 1 : a.meta.name.localeCompare(b.meta.name, "it"))));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);
  useEffect(() => { void load(); }, []);
  const shown = (list ?? []).filter((c) => !q || `${c.meta.name} ${c.meta.sector ?? ""}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <View style={{ flex: 1 }}>
      <Header title="Clienti" subtitle={list ? `${list.filter((c) => c.kind === "client").length} clienti` : undefined} />
      <SearchBox value={q} onChange={setQ} placeholder="Cerca clienti…" />
      {error && <View style={{ padding: 16 }}><Notice kind="error">{error}</Notice></View>}
      {!list && !error && <ActivityIndicator style={{ marginTop: 32 }} color={color.accent} />}
      <FlatList
        data={shown}
        keyExtractor={(c) => c.id}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); await engine.syncForOffline(); setRefreshing(false); }} />}
        renderItem={({ item: c }) => (
          <Pressable accessibilityRole="button" onPress={() => app.push({ name: "container", id: c.id, title: where(c) })} style={({ pressed }) => [st.row, pressed && { backgroundColor: color.accentSoft }]}>
            <View style={st.mono}><Text style={st.monoText}>{c.kind === "personal" ? "AP" : initials(c.meta.name)}</Text></View>
            <View style={{ flex: 1 }}>
              <Text style={st.rowTitle} numberOfLines={1}>{where(c)}</Text>
              <Text style={st.rowSub} numberOfLines={1}>{c.items} elementi{c.totpItems ? ` · ${c.totpItems} OTP` : ""}{c.viaGroups.length ? ` · gruppo ${c.viaGroups.join(", ")}` : ""}</Text>
            </View>
          </Pressable>
        )}
        ListEmptyComponent={list ? <Text style={st.empty}>{q ? "Nessun cliente trovato." : "Nessun cliente condiviso con te."}</Text> : null}
      />
    </View>
  );
}

// ------------------------------------------------------------------ cliente con cartelle

export function ContainerScreen({ id, title }: { id: string; title: string }) {
  const engine = useEngine();
  const app = useApp();
  const [folders, setFolders] = useState<Folder[]>([]);
  const [items, setItems] = useState<Item[] | null>(null);
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    (async () => {
      try {
        const [c, its] = await Promise.all([engine.call<{ folders: Folder[] }>("container", id), engine.call<Item[]>("items", id)]);
        setFolders(c.folders);
        setItems(its);
      } catch (e) {
        setError(errorText(e));
      }
    })();
  }, [id]);
  const visible = useMemo(() => (items ?? []).filter((i) => !q || [i.data.name, i.data.username, ...(i.data.urls ?? [])].some((v) => v?.toLowerCase().includes(q.toLowerCase()))), [items, q]);
  const children = (pid: string | null) => folders.filter((f) => (f.parentId ?? null) === pid).sort((a, b) => a.name.localeCompare(b.name, "it"));
  const itemsIn = (fid: string | null) => visible.filter((i) => (i.folderId ?? null) === fid);
  const count = (fid: string): number => itemsIn(fid).length + children(fid).reduce((n, c) => n + count(c.id), 0);

  // Righe dell'albero: cartelle comprimibili e relativi elementi.
  const rows: { key: string; node: ReactElement }[] = [];
  const open = (i: Item) => app.push({ name: "item", item: i, where: title });
  for (const i of itemsIn(null)) rows.push({ key: i.id, node: <ItemRow item={i} onPress={() => open(i)} /> });
  const walk = (f: Folder, depth: number) => {
    const n = count(f.id);
    if (q && n === 0) return;
    const isOpen = !!q || !closed.has(f.id);
    rows.push({ key: `f-${f.id}`, node: (
      <Pressable accessibilityRole="button" accessibilityState={{ expanded: isOpen }} onPress={() => setClosed((p) => { const s = new Set(p); if (s.has(f.id)) s.delete(f.id); else s.add(f.id); return s; })}
        style={[st.folder, { paddingLeft: 12 + depth * 18 }]}>
        <Text style={{ color: color.muted, width: 16 }}>{isOpen ? "▾" : "▸"}</Text>
        <Text style={st.folderText} numberOfLines={1}>{f.name}</Text>
        <Text style={st.rowSub}>{n}</Text>
      </Pressable>
    ) });
    if (!isOpen) return;
    for (const i of itemsIn(f.id)) rows.push({ key: i.id, node: <ItemRow item={i} depth={depth + 1} onPress={() => open(i)} /> });
    for (const c of children(f.id)) walk(c, depth + 1);
  };
  for (const f of children(null)) walk(f, 0);

  return (
    <View style={{ flex: 1 }}>
      <Header title={title} back />
      <SearchBox value={q} onChange={setQ} placeholder="Cerca nel cliente…" />
      {error && <View style={{ padding: 16 }}><Notice kind="error">{error}</Notice></View>}
      {!items && !error ? <ActivityIndicator style={{ marginTop: 32 }} color={color.accent} /> : (
        <FlatList data={rows} keyExtractor={(r) => r.key} renderItem={({ item }) => item.node} ListEmptyComponent={<Text style={st.empty}>Nessun elemento.</Text>} />
      )}
    </View>
  );
}

// ------------------------------------------------------------------ dettaglio

export function ItemScreen({ item, whereName }: { item: Item; whereName: string }) {
  const engine = useEngine();
  const app = useApp();
  const d = item.data;
  const [shown, setShown] = useState(false);
  const [otp, setOtp] = useState<string | null>(null);
  const [busyFile, setBusyFile] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const report = (a: string) => engine.call("report", a, item.containerId, item.id).catch(() => undefined);
  useEffect(() => { engine.call<string | null>("effectiveTotp", item.id).then(setOtp).catch(() => undefined); }, [item.id]);
  const url = (u: string) => (/^https?:\/\//i.test(u) ? u : /^[a-z][a-z0-9+.-]*:/i.test(u) ? null : `https://${u}`);

  const openFile = async (attId: string) => {
    setBusyFile(attId);
    setError(null);
    try {
      const f = await engine.call<{ name: string; mime: string; data: string }>("downloadAttachment", item.id, attId);
      const file = new File(Paths.cache, f.name.replace(/[\\/:*?"<>|]/g, "_"));
      if (file.exists) file.delete();
      file.create();
      const bin = atob(f.data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      file.write(bytes);
      await Sharing.shareAsync(file.uri, { mimeType: f.mime, dialogTitle: f.name });
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusyFile(null);
    }
  };

  return (
    <View style={{ flex: 1 }}>
      <Header title={d.name} subtitle={item.sharedBy ? `Condivisa da ${item.sharedBy}` : whereName} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 16 }}>
        {(d.urls ?? []).map((u) => (
          <View key={u} style={st.fieldBox}>
            <Text style={st.fieldLabel}>Sito</Text>
            <Text style={[st.fieldValue, { color: color.accentDark }]} onPress={() => { const x = url(u); if (x) void Linking.openURL(x); }} accessibilityRole="link">{u}</Text>
          </View>
        ))}
        {d.username ? (
          <View style={st.fieldBox}>
            <Text style={st.fieldLabel}>Nome utente</Text>
            <View style={st.fieldRow}><Text style={[st.fieldValue, { flex: 1 }]} selectable>{d.username}</Text><CopyButton value={d.username} toast={app.toast} /></View>
          </View>
        ) : null}
        {d.password ? (
          <View style={st.fieldBox}>
            <Text style={st.fieldLabel}>Password</Text>
            <View style={st.fieldRow}>
              <Text style={[st.fieldValue, { flex: 1, fontFamily: mono }]} selectable={shown}>{shown ? d.password : "••••••••••••"}</Text>
              <Button kind="secondary" title={shown ? "Nascondi" : "Mostra"} onPress={() => { if (!shown) void report("item.reveal"); setShown(!shown); }} style={{ minHeight: 40, paddingHorizontal: 12 }} />
              <CopyButton value={d.password} onCopied={() => void report("item.copy")} toast={app.toast} />
            </View>
          </View>
        ) : null}
        {otp && <OtpView uri={otp} onCopy={() => void report("item.totp_copy")} toast={app.toast} />}
        {d.notes ? <View style={st.fieldBox}><Text style={st.fieldLabel}>Note</Text><Text style={st.fieldValue} selectable>{d.notes}</Text></View> : null}
        {(d.fields ?? []).filter((f) => !f.label.startsWith("TimeOtp-")).map((f) => (
          <View key={f.label} style={st.fieldBox}>
            <Text style={st.fieldLabel}>{f.label}</Text>
            <View style={st.fieldRow}><Text style={[st.fieldValue, { flex: 1 }]}>{f.secret ? "••••••••" : f.value}</Text><CopyButton value={f.value} toast={app.toast} /></View>
          </View>
        ))}
        {item.attachments.length > 0 && (
          <View style={st.fieldBox}>
            <Text style={st.fieldLabel}>Allegati</Text>
            {item.attachments.map((a) => (
              <View key={a.id} style={st.fieldRow}>
                <Text style={[st.fieldValue, { flex: 1 }]} numberOfLines={1}>{a.name}</Text>
                <Button kind="secondary" title={busyFile === a.id ? "…" : "Apri"} busy={busyFile === a.id} onPress={() => openFile(a.id)} style={{ minHeight: 40, paddingHorizontal: 12 }} />
              </View>
            ))}
          </View>
        )}
        {error && <Notice kind="error">{error}</Notice>}
        <Text style={st.rowSub}>Le modifiche si fanno dall'estensione per Chrome o Edge.</Text>
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ ricerca e condivisi

export function SearchScreen() {
  const engine = useEngine();
  const app = useApp();
  const [all, setAll] = useState<{ item: Item; where: string }[] | null>(null);
  const [q, setQ] = useState("");
  useEffect(() => {
    (async () => {
      const out: { item: Item; where: string }[] = [];
      for (const c of await engine.call<Container[]>("containers")) {
        if (c.kind === "org") continue;
        for (const i of await engine.call<Item[]>("items", c.id)) out.push({ item: i, where: where(c) });
      }
      for (const i of await engine.call<Item[]>("sharedWithMe").catch(() => [] as Item[])) out.push({ item: i, where: `Condivisa da ${i.sharedBy}` });
      setAll(out);
    })().catch(() => setAll([]));
  }, []);
  const s = q.trim().toLowerCase();
  const res = s && all ? all.filter(({ item, where: w }) => [item.data.name, item.data.username, w, ...(item.data.urls ?? [])].some((v) => v?.toLowerCase().includes(s))).slice(0, 100) : [];
  return (
    <View style={{ flex: 1 }}>
      <Header title="Cerca" subtitle={all ? `${all.length} elementi, ricerca solo sul telefono` : "Decifratura…"} />
      <SearchBox value={q} onChange={setQ} placeholder="Nome, utente, sito, cliente…" />
      <FlatList data={res} keyExtractor={(r) => r.item.id} renderItem={({ item: r }) => (
        <ItemRow item={r.item} subtitle={`${r.where}${r.item.data.username ? ` · ${r.item.data.username}` : ""}`} onPress={() => app.push({ name: "item", item: r.item, where: r.where })} />
      )} ListEmptyComponent={s && all ? <Text style={st.empty}>Nessun risultato.</Text> : null} />
    </View>
  );
}

export function SharedScreen() {
  const engine = useEngine();
  const app = useApp();
  const [items, setItems] = useState<Item[] | null>(null);
  useEffect(() => { engine.call<Item[]>("sharedWithMe").then(setItems).catch(() => setItems([])); }, []);
  return (
    <View style={{ flex: 1 }}>
      <Header title="Condivise con te" subtitle="Password singole, in sola lettura" />
      {!items ? <ActivityIndicator style={{ marginTop: 32 }} color={color.accent} /> : (
        <FlatList data={items} keyExtractor={(i) => i.id} renderItem={({ item }) => (
          <ItemRow item={item} subtitle={`da ${item.sharedBy}`} onPress={() => app.push({ name: "item", item, where: `Condivisa da ${item.sharedBy}` })} />
        )} ListEmptyComponent={<Text style={st.empty}>Nessuna password condivisa singolarmente con te.</Text>} />
      )}
    </View>
  );
}

const st = StyleSheet.create({
  header: { flexDirection: "row", alignItems: "center", paddingHorizontal: 16, paddingTop: 12, paddingBottom: 10, backgroundColor: color.surface, borderBottomWidth: 1, borderBottomColor: color.line },
  title: { fontSize: 20, fontWeight: "700", color: color.ink },
  subtitle: { fontSize: 13, color: color.muted },
  search: { margin: 12, minHeight: 44, borderWidth: 1, borderColor: color.line, borderRadius: 10, paddingHorizontal: 12, fontSize: 16, backgroundColor: color.surface, color: color.ink },
  row: { flexDirection: "row", alignItems: "center", gap: 12, paddingHorizontal: 16, paddingVertical: 12, backgroundColor: color.surface, borderBottomWidth: 1, borderBottomColor: color.line, minHeight: 56 },
  rowTitle: { fontSize: 16, fontWeight: "600", color: color.ink },
  rowSub: { fontSize: 13, color: color.muted },
  mono: { width: 40, height: 40, borderRadius: 10, backgroundColor: color.accentSoft, alignItems: "center", justifyContent: "center" },
  monoText: { color: color.accentDark, fontWeight: "700" },
  kind: { width: 36, height: 36, borderRadius: 9, borderWidth: 1, borderColor: color.line, alignItems: "center", justifyContent: "center", backgroundColor: color.ground },
  kindText: { fontFamily: mono, fontSize: 10, color: color.ink2 },
  folder: { flexDirection: "row", alignItems: "center", gap: 6, paddingRight: 16, paddingVertical: 10, backgroundColor: color.ground, borderBottomWidth: 1, borderBottomColor: color.line, minHeight: 44 },
  folderText: { flex: 1, fontWeight: "600", color: color.ink2 },
  empty: { textAlign: "center", color: color.muted, padding: 32 },
  fieldBox: { gap: 6, backgroundColor: color.surface, borderRadius: 12, borderWidth: 1, borderColor: color.line, padding: 12 },
  fieldLabel: { fontSize: 13, color: color.muted },
  fieldRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  fieldValue: { fontSize: 16, color: color.ink },
});
