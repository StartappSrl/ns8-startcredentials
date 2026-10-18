import { useEffect, useState } from "react";
import { Alert, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import type { Item, ItemData, Me } from "@startcredentials/client";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { Brand, Button, Card, Field, Notice } from "../ui/kit";
import { Header } from "./Vault";
import { color, mono } from "../theme";

type Perm = "read" | "write" | "manage";
const PERM: Record<Perm, string> = { read: "Lettura", write: "Modifica", manage: "Gestione" };
interface DirUser { id: string; displayName: string; email: string; status: string; verified: boolean }

function Choice<T extends string>({ value, options, onChange }: { value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <View style={{ flexDirection: "row", gap: 6, flexWrap: "wrap" }}>
      {options.map(([v, l]) => (
        <Button key={v} title={l} kind={value === v ? "primary" : "secondary"} onPress={() => onChange(v)} style={{ minHeight: 38, paddingHorizontal: 12 }} />
      ))}
    </View>
  );
}

// ------------------------------------------------------------------ cronologia

export function HistoryScreen({ item, where }: { item: Item; where: string }) {
  const engine = useEngine();
  const app = useApp();
  const [versions, setVersions] = useState<{ revision: number; createdAt: string; by: string; data: ItemData }[] | null>(null);
  const [shown, setShown] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { engine.call<typeof versions>("itemVersions", item.id).then(setVersions).catch((e) => setError(errorText(e))); }, [item.id]);
  return (
    <View style={{ flex: 1 }}>
      <Header title="Cronologia" subtitle={item.data.name} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
        {error && <Notice kind="error">{error}</Notice>}
        {versions?.length === 0 && <Text style={{ color: color.muted }}>Nessuna versione precedente.</Text>}
        {versions?.map((v) => (
          <Card key={v.revision}>
            <Text style={{ fontWeight: "700", color: color.ink }}>Versione {v.revision} · {new Date(v.createdAt).toLocaleString("it-IT")}</Text>
            <Text style={{ color: color.muted }}>Modificata da {v.by}</Text>
            {v.data.username ? <Text style={{ color: color.ink2 }}>Utente: {v.data.username}</Text> : null}
            {v.data.password ? <Text style={{ fontFamily: mono, color: color.ink }}>{shown === v.revision ? v.data.password : "••••••••••"}</Text> : null}
            <View style={{ flexDirection: "row", gap: 8 }}>
              {v.data.password ? <Button title={shown === v.revision ? "Nascondi" : "Mostra"} kind="secondary" onPress={() => setShown(shown === v.revision ? null : v.revision)} style={{ flex: 1 }} /> : null}
              {!engine.offline && (
                <Button title="Ripristina" style={{ flex: 1 }} onPress={() => Alert.alert("Ripristinare questa versione?", "La versione attuale resta nella cronologia.", [
                  { text: "Annulla", style: "cancel" },
                  { text: "Ripristina", onPress: async () => {
                    try { await engine.call("restoreVersion", item.id, v.revision); app.toast("Versione ripristinata"); app.back(3); } catch (e) { setError(errorText(e)); }
                  } },
                ])} />
              )}
            </View>
          </Card>
        ))}
        <Text style={{ color: color.muted, fontSize: 13 }}>{where}</Text>
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ condivisione di un cliente

export function ShareScreen({ containerId, title }: { containerId: string; title: string }) {
  const engine = useEngine();
  const app = useApp();
  const [members, setMembers] = useState<{ userId: string; displayName: string; email: string; permission: Perm }[]>([]);
  const [groups, setGroups] = useState<{ groupId: string; name: string; permission: Perm }[]>([]);
  const [dir, setDir] = useState<DirUser[]>([]);
  const [allGroups, setAllGroups] = useState<{ id: string; name: string; verified: boolean; rotationRequired: boolean }[]>([]);
  const [perm, setPerm] = useState<Perm>("read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    try {
      const [m, g, d, ag] = await Promise.all([
        engine.call<typeof members>("members", containerId), engine.call<typeof groups>("containerGroups", containerId),
        engine.call<DirUser[]>("directory"), engine.call<typeof allGroups>("groups"),
      ]);
      setMembers(m); setGroups(g); setDir(d); setAllGroups(ag);
    } catch (e) {
      setError(errorText(e));
    }
  };
  useEffect(() => { void load(); }, [containerId]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try { await fn(); app.toast(done); await load(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  };
  const candidates = dir.filter((u) => u.status === "active" && u.id !== app.me?.id && !members.some((m) => m.userId === u.id));
  const groupCandidates = allGroups.filter((g) => g.verified && !g.rotationRequired && !groups.some((x) => x.groupId === g.id));
  if (engine.offline) {
    return <View style={{ flex: 1 }}><Header title="Condividi" subtitle={title} back /><View style={{ padding: 16 }}><Notice kind="warn">Le condivisioni richiedono la rete.</Notice></View></View>;
  }
  return (
    <View style={{ flex: 1 }}>
      <Header title="Condividi" subtitle={title} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        <Card>
          <Text style={st.h}>Con accesso</Text>
          {members.map((m) => (
            <View key={m.userId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{m.displayName}{m.userId === app.me?.id ? " (tu)" : ""}</Text><Text style={st.sub}>{m.email} · {PERM[m.permission]}</Text></View>
              {m.userId !== app.me?.id && (
                <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => Alert.alert(`Togliere l'accesso a ${m.displayName}?`, "La chiave del cliente viene ruotata subito.", [
                  { text: "Annulla", style: "cancel" },
                  { text: "Rimuovi", style: "destructive", onPress: () => void act(() => engine.call("revoke", containerId, m.userId), "Accesso rimosso e chiave ruotata") },
                ])} />
              )}
            </View>
          ))}
          {groups.map((g) => (
            <View key={g.groupId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>Gruppo {g.name}</Text><Text style={st.sub}>{PERM[g.permission]}</Text></View>
              <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => void act(() => engine.call("unshareGroup", containerId, g.groupId), "Gruppo rimosso e chiave ruotata")} />
            </View>
          ))}
        </Card>
        <Card>
          <Text style={st.h}>Aggiungi</Text>
          <Text style={st.sub}>Permesso</Text>
          <Choice value={perm} options={[["read", "Lettura"], ["write", "Modifica"], ["manage", "Gestione"]]} onChange={setPerm} />
          {candidates.map((u) => (
            <Pressable key={u.id} disabled={busy || !u.verified} onPress={() => void act(() => engine.call("share", containerId, u.id, perm), `Condiviso con ${u.displayName}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{u.displayName}</Text><Text style={st.sub}>{u.email}{u.verified ? "" : " · chiave da certificare"}</Text></View>
              {u.verified && <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>}
            </Pressable>
          ))}
          {groupCandidates.map((g) => (
            <Pressable key={g.id} disabled={busy} onPress={() => void act(() => engine.call("shareWithGroup", containerId, g.id, perm), `Condiviso con il gruppo ${g.name}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>Gruppo {g.name}</Text></View>
              <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>
            </Pressable>
          ))}
          {!candidates.length && !groupCandidates.length && <Text style={st.sub}>Nessun altro collega o gruppo da aggiungere.</Text>}
        </Card>
        {error && <Notice kind="error">{error}</Notice>}
        <Text style={st.sub}>La chiave del cliente viene cifrata sul telefono per la chiave certificata di ogni destinatario. Le chiavi si certificano dall'estensione.</Text>
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ condivisione di una singola password

export function ItemShareScreen({ item }: { item: Item }) {
  const engine = useEngine();
  const app = useApp();
  const [shares, setShares] = useState<{ userId: string; displayName: string; email: string }[]>([]);
  const [dir, setDir] = useState<DirUser[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    try {
      const [s, d] = await Promise.all([engine.call<typeof shares>("itemShares", item.id), engine.call<DirUser[]>("directory")]);
      setShares(s); setDir(d);
    } catch (e) { setError(errorText(e)); }
  };
  useEffect(() => { void load(); }, [item.id]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try { await fn(); app.toast(done); await load(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  };
  const candidates = dir.filter((u) => u.status === "active" && u.verified && u.id !== app.me?.id && !shares.some((x) => x.userId === u.id));
  return (
    <View style={{ flex: 1 }}>
      <Header title="Condividi solo questa password" subtitle={item.data.name} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        <Text style={st.sub}>Il collega la vede in sola lettura, anche senza accesso al cliente. Togliendola, la password viene ricifrata.</Text>
        <Card>
          <Text style={st.h}>Condivisa con</Text>
          {shares.length === 0 && <Text style={st.sub}>Nessuno.</Text>}
          {shares.map((x) => (
            <View key={x.userId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{x.displayName}</Text><Text style={st.sub}>{x.email}</Text></View>
              <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => void act(() => engine.call("unshareItem", item.id, x.userId), "Condivisione rimossa e password ricifrata")} />
            </View>
          ))}
        </Card>
        <Card>
          <Text style={st.h}>Aggiungi</Text>
          {candidates.map((u) => (
            <Pressable key={u.id} disabled={busy} onPress={() => void act(() => engine.call("shareItem", item.id, u.id), `Condivisa con ${u.displayName}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{u.displayName}</Text><Text style={st.sub}>{u.email}</Text></View>
              <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>
            </Pressable>
          ))}
          {!candidates.length && <Text style={st.sub}>Nessun altro collega con chiave certificata.</Text>}
        </Card>
        {error && <Notice kind="error">{error}</Notice>}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ salute delle password

type Ref = { itemId: string; name: string; where: string };
export function HealthScreen() {
  const engine = useEngine();
  const app = useApp();
  const [r, setR] = useState<{ checked: number; weak: Ref[]; reused: Ref[][]; old: Ref[]; missingOtp: Ref[] } | null>(null);
  useEffect(() => { engine.call<typeof r>("health").then(setR).catch(() => undefined); }, []);
  const open = async (x: Ref) => {
    const it = await engine.call<Item | null>("item", x.itemId);
    if (it) app.push({ name: "item", item: it, where: x.where, canWrite: true });
  };
  const list = (title: string, help: string, refs: Ref[]) => refs.length > 0 && (
    <Card>
      <Text style={st.h}>{title} ({refs.length})</Text>
      <Text style={st.sub}>{help}</Text>
      {refs.map((x, i) => (
        <Pressable key={`${x.itemId}-${i}`} onPress={() => void open(x)} style={st.row}>
          <View style={{ flex: 1 }}><Text style={st.name}>{x.name}</Text><Text style={st.sub}>{x.where}</Text></View>
        </Pressable>
      ))}
    </Card>
  );
  return (
    <View style={{ flex: 1 }}>
      <Header title="Salute password" subtitle={r ? `${r.checked} password analizzate sul telefono` : "Analisi…"} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        {r && list("Usate in più punti", "Se una viene compromessa, lo sono anche le altre: cambiale per prime.", r.reused.flat())}
        {r && list("Deboli", "Brevi o prevedibili.", r.weak)}
        {r && list("Non cambiate da oltre un anno", "Valuta se cambiarle.", r.old)}
        {r && list("Pannelli senza OTP", "Se il servizio lo supporta, attiva il secondo fattore e aggancialo qui.", r.missingOtp)}
        {r && !r.reused.length && !r.weak.length && !r.old.length && <Notice kind="ok">Nessun problema trovato.</Notice>}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ account

export function ChangePasswordScreen() {
  const engine = useEngine();
  const app = useApp();
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if ([...pw].length < 12) return setError("La nuova master password deve avere almeno 12 caratteri.");
    if (pw !== pw2) return setError("Le due password non coincidono.");
    setBusy(true);
    setError(null);
    try {
      await engine.call("changePassword", cur, pw, code.trim());
      app.toast("Master password cambiata: le altre sessioni sono state chiuse");
      app.pop();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <View style={{ flex: 1 }}>
      <Header title="Cambia la master password" back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }} keyboardShouldPersistTaps="handled">
        <Field label="Master password attuale" value={cur} onChangeText={setCur} secureTextEntry />
        <Field label="Nuova master password" value={pw} onChangeText={setPw} secureTextEntry />
        <Field label="Ripeti la nuova master password" value={pw2} onChangeText={setPw2} secureTextEntry />
        <Field label="Codice MFA o di riserva" value={code} onChangeText={setCode} autoComplete="one-time-code" />
        {error && <Notice kind="error">{error}</Notice>}
        <Button title={busy ? "Cifratura delle chiavi…" : "Cambia password"} onPress={submit} busy={busy} disabled={!cur || !pw || !code || engine.offline} />
        <Text style={st.sub}>Cambiandola vengono revocati anche i dispositivi attendibili.</Text>
      </ScrollView>
    </View>
  );
}

export function BackupCodesScreen() {
  const engine = useEngine();
  const [code, setCode] = useState("");
  const [left, setLeft] = useState<number | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { engine.call<{ backupCodesRemaining: number }>("mfaStatus").then((r) => setLeft(r.backupCodesRemaining)).catch(() => undefined); }, []);
  return (
    <View style={{ flex: 1 }}>
      <Header title="Codici di riserva" subtitle={left === null ? undefined : `${left} ancora disponibili`} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
        {codes ? (
          <>
            <Notice kind="warn">I codici precedenti non valgono più. Salva questi fuori da StartCredentials: non verranno mostrati di nuovo.</Notice>
            <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
              {codes.map((c) => <Text key={c} selectable style={st.code}>{c}</Text>)}
            </View>
          </>
        ) : (
          <>
            <Field label="Codice dall'app di autenticazione" value={code} onChangeText={setCode} keyboardType="number-pad" />
            {error && <Notice kind="error">{error}</Notice>}
            <Button title="Genera nuovi codici" busy={busy} disabled={!code.trim() || engine.offline} onPress={async () => {
              setBusy(true);
              setError(null);
              try { setCodes(await engine.call<string[]>("regenerateBackupCodes", code.trim())); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
            }} />
          </>
        )}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ registrazione da invito

export function RegisterScreen() {
  const engine = useEngine();
  const app = useApp();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if ([...pw].length < 12) return setError("La master password deve avere almeno 12 caratteri: meglio una frase lunga.");
    if (pw !== pw2) return setError("Le due password non coincidono.");
    setBusy(true);
    setError(null);
    try {
      await engine.call("init", app.settings.serverUrl!, "");
      await engine.call("register", app.inviteToken.current, pw);
      app.inviteToken.current = null;
      app.pendingPassword.current = pw;
      app.setPhase("mfaSetup");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <ScrollView contentContainerStyle={{ padding: 20, gap: 20, paddingTop: 48, backgroundColor: color.ground, flexGrow: 1 }} keyboardShouldPersistTaps="handled">
      <Brand />
      <Card>
        <Text style={{ fontSize: 22, fontWeight: "700", color: color.ink }}>Attiva il tuo account</Text>
        <Text style={{ color: color.muted }}>Scegli la master password: la conosci solo tu, nessuno può recuperarla al posto tuo senza la procedura con gli amministratori.</Text>
        <Field label="Master password" value={pw} onChangeText={setPw} secureTextEntry />
        <Field label="Ripeti la master password" value={pw2} onChangeText={setPw2} secureTextEntry />
        {error && <Notice kind="error">{error}</Notice>}
        <Button title={busy ? "Creazione delle chiavi…" : "Crea l'account"} onPress={submit} busy={busy} disabled={!pw || !pw2} />
        <Button title="Annulla" kind="ghost" onPress={() => { app.inviteToken.current = null; app.setPhase("login"); }} />
      </Card>
    </ScrollView>
  );
}

const st = StyleSheet.create({
  h: { fontWeight: "700", color: color.ink },
  row: { flexDirection: "row", alignItems: "center", gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: color.line },
  name: { fontSize: 15, fontWeight: "600", color: color.ink },
  sub: { fontSize: 13, color: color.muted },
  small: { minHeight: 38, paddingHorizontal: 12 },
  code: { fontFamily: mono, fontSize: 16, padding: 8, borderWidth: 1, borderColor: color.line, borderRadius: 8, width: "47%", textAlign: "center", color: color.ink },
});

export type { Me };
