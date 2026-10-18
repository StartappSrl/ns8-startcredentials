import { useEffect, useRef, useState } from "react";
import { Alert, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import type { Folder, Item, ItemData } from "@startcredentials/client";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { Button, Field, Notice, OtpView } from "../ui/kit";
import { Header } from "./Vault";
import { color } from "../theme";

/** Lettore di QR code: accetta solo link otpauth://, ignora gli altri. */
function QrScanner({ onResult, onCancel }: { onResult: (uri: string) => void; onCancel: () => void }) {
  const [perm, request] = useCameraPermissions();
  const done = useRef(false);
  const [hint, setHint] = useState("Inquadra il QR code mostrato dal servizio quando attivi l'autenticazione a due fattori.");
  useEffect(() => { if (perm && !perm.granted && perm.canAskAgain) void request(); }, [perm]);
  if (!perm) return null;
  if (!perm.granted) {
    return (
      <View style={{ padding: 16, gap: 12 }}>
        <Notice kind="warn">Serve il permesso di usare la fotocamera per leggere il QR code. In alternativa incolla la chiave.</Notice>
        <Button title="Consenti la fotocamera" onPress={() => void request()} />
        <Button title="Annulla" kind="ghost" onPress={onCancel} />
      </View>
    );
  }
  return (
    <View style={{ gap: 12 }}>
      <View style={{ height: 320, borderRadius: 14, overflow: "hidden", backgroundColor: "#000" }}>
        <CameraView
          style={{ flex: 1 }}
          facing="back"
          barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
          onBarcodeScanned={({ data }) => {
            if (done.current) return;
            if (/^otpauth:\/\//i.test(data)) {
              done.current = true;
              onResult(data);
            } else setHint("Questo QR code non contiene un codice OTP.");
          }}
        />
      </View>
      <Text style={{ color: color.muted, textAlign: "center" }}>{hint}</Text>
      <Button title="Annulla" kind="ghost" onPress={onCancel} />
    </View>
  );
}

export function EditScreen({ containerId, containerTitle, item }: { containerId: string; containerTitle: string; item?: Item }) {
  const engine = useEngine();
  const app = useApp();
  const d = item?.data;
  const [type, setType] = useState<ItemData["type"]>(item?.type ?? "login");
  const [name, setName] = useState(d?.name ?? "");
  const [username, setUsername] = useState(d?.username ?? "");
  const [password, setPassword] = useState(d?.password ?? "");
  const [showPw, setShowPw] = useState(!item);
  const [url, setUrl] = useState(d?.urls?.[0] ?? "");
  const [notes, setNotes] = useState(d?.notes ?? "");
  const [folders, setFolders] = useState<Folder[]>([]);
  const [folderId, setFolderId] = useState<string | null>(item?.folderId ?? null);
  const [newFolder, setNewFolder] = useState("");
  const [totpUri, setTotpUri] = useState<string | null>(d?.totpUri ?? null);
  const [otpMode, setOtpMode] = useState<"none" | "scan" | "paste">("none");
  const [otpInput, setOtpInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { engine.call<{ folders: Folder[] }>("container", containerId).then((c) => setFolders(c.folders)).catch(() => undefined); }, [containerId]);
  const path = (id: string | null): string => {
    const f = folders.find((x) => x.id === id);
    return f ? (f.parentId ? `${path(f.parentId)} / ${f.name}` : f.name) : "";
  };

  const attachOtp = async (input: string) => {
    setError(null);
    try {
      const r = await engine.call<{ uri: string; code: string }>("parseTotp", input, name || "StartCredentials");
      setTotpUri(r.uri);
      setOtpMode("none");
      setOtpInput("");
      app.toast("OTP agganciato: confronta il codice con quello del servizio, poi salva");
    } catch (e) {
      setError(errorText(e));
    }
  };

  const save = async () => {
    if (!name.trim()) return setError("Il nome è obbligatorio.");
    setBusy(true);
    setError(null);
    try {
      let target = folderId;
      if (newFolder.trim()) target = await engine.call<string>("createFolder", containerId, newFolder.trim(), folderId);
      const urls = url.trim() ? [url.trim(), ...(d?.urls ?? []).slice(1)] : (d?.urls ?? []).slice(1);
      const data: ItemData = {
        ...(d ?? {}), type, name: name.trim(),
        username: type === "login" ? username.trim() || undefined : undefined,
        password: type === "login" ? password || undefined : undefined,
        urls: type === "login" ? urls : undefined,
        notes: notes.trim() || undefined,
        totpUri: totpUri ?? undefined,
      };
      if (item) await engine.call("updateItem", item.id, data, target);
      else await engine.call("createItem", containerId, data, target);
      app.toast(item ? "Modifiche salvate" : "Elemento creato");
      // Torna al cliente, che si ricarica.
      app.back(item ? 2 : 1);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (engine.offline) {
    return (
      <View style={{ flex: 1 }}>
        <Header title={item ? "Modifica" : "Nuovo elemento"} back />
        <View style={{ padding: 16 }}><Notice kind="warn">Senza rete le modifiche non sono possibili: i dati offline sono in sola lettura.</Notice></View>
      </View>
    );
  }

  return (
    <View style={{ flex: 1 }}>
      <Header title={item ? "Modifica" : "Nuovo elemento"} subtitle={containerTitle} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }} keyboardShouldPersistTaps="handled">
        {!item && (
          <View style={{ flexDirection: "row", gap: 8 }}>
            {(["login", "note"] as const).map((t) => (
              <Button key={t} title={t === "login" ? "Password" : "Nota"} kind={type === t ? "primary" : "secondary"} onPress={() => setType(t)} style={{ flex: 1 }} />
            ))}
          </View>
        )}
        <Field label="Nome" value={name} onChangeText={setName} placeholder="Microsoft 365 – amministratore" autoCapitalize="sentences" />
        {type === "login" && (
          <>
            <Field label="Nome utente" value={username} onChangeText={setUsername} />
            <Field label="Password" value={password} onChangeText={setPassword} secureTextEntry={!showPw} style={{ fontFamily: "monospace" }} />
            <View style={{ flexDirection: "row", gap: 8 }}>
              <Button title={showPw ? "Nascondi" : "Mostra"} kind="secondary" onPress={() => setShowPw(!showPw)} style={{ flex: 1 }} />
              <Button title="Genera" kind="secondary" style={{ flex: 1 }} onPress={async () => { setPassword(await engine.call<string>("generatePassword", 20, true)); setShowPw(true); }} />
            </View>
            <Field label="Sito" value={url} onChangeText={setUrl} keyboardType="url" placeholder="https://portale.cliente.it" />

            <View style={st.box}>
              <Text style={st.boxTitle}>Codice OTP</Text>
              {totpUri ? (
                <>
                  <OtpView uri={totpUri} toast={app.toast} />
                  <Button title="Rimuovi l'OTP" kind="danger" onPress={() => setTotpUri(null)} />
                </>
              ) : (
                <Text style={{ color: color.muted }}>Nessun OTP. Aggancialo quando attivi l'autenticazione a due fattori sul servizio.</Text>
              )}
              {otpMode === "scan" && <QrScanner onResult={(u) => void attachOtp(u)} onCancel={() => setOtpMode("none")} />}
              {otpMode === "paste" && (
                <View style={{ gap: 8 }}>
                  <Field label="Chiave segreta o link otpauth://" value={otpInput} onChangeText={setOtpInput} placeholder="JBSW Y3DP EHPK 3PXP…" />
                  <View style={{ flexDirection: "row", gap: 8 }}>
                    <Button title="Aggancia" onPress={() => void attachOtp(otpInput)} disabled={!otpInput.trim()} style={{ flex: 1 }} />
                    <Button title="Annulla" kind="ghost" onPress={() => setOtpMode("none")} style={{ flex: 1 }} />
                  </View>
                </View>
              )}
              {otpMode === "none" && (
                <View style={{ flexDirection: "row", gap: 8 }}>
                  <Button title="Scansiona QR" kind="secondary" onPress={() => setOtpMode("scan")} style={{ flex: 1 }} />
                  <Button title="Incolla chiave" kind="secondary" onPress={() => setOtpMode("paste")} style={{ flex: 1 }} />
                </View>
              )}
            </View>
          </>
        )}
        <Field label="Note" value={notes} onChangeText={setNotes} multiline style={{ minHeight: 90, textAlignVertical: "top", paddingTop: 10 }} autoCapitalize="sentences" />

        <View style={st.box}>
          <Text style={st.boxTitle}>Cartella</Text>
          {[null, ...folders.map((f) => f.id)].sort((a, b) => path(a).localeCompare(path(b), "it")).map((id) => (
            <Pressable key={id ?? "root"} accessibilityRole="radio" accessibilityState={{ checked: folderId === id }} onPress={() => setFolderId(id)} style={st.radio}>
              <View style={[st.dot, folderId === id && st.dotOn]} />
              <Text style={{ color: color.ink, flex: 1 }}>{id ? path(id) : "Nessuna cartella"}</Text>
            </Pressable>
          ))}
          <Field label={folderId ? `Nuova sottocartella di «${path(folderId)}» (facoltativa)` : "Nuova cartella (facoltativa)"} value={newFolder} onChangeText={setNewFolder} autoCapitalize="sentences" />
        </View>

        {error && <Notice kind="error">{error}</Notice>}
        <Button title={busy ? "Cifratura…" : item ? "Salva le modifiche" : "Crea"} onPress={save} busy={busy} />
        {item && (
          <Button title="Elimina" kind="danger" onPress={() => Alert.alert("Spostare nel cestino?", "Resta recuperabile dall'estensione per 30 giorni.", [
            { text: "Annulla", style: "cancel" },
            { text: "Elimina", style: "destructive", onPress: async () => {
              try { await engine.call("deleteItem", item.id); app.toast("Elemento spostato nel cestino"); app.back(2); } catch (e) { setError(errorText(e)); }
            } },
          ])} />
        )}
      </ScrollView>
    </View>
  );
}

const st = StyleSheet.create({
  box: { gap: 10, backgroundColor: color.surface, borderRadius: 12, borderWidth: 1, borderColor: color.line, padding: 12 },
  boxTitle: { fontWeight: "700", color: color.ink },
  radio: { flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 },
  dot: { width: 18, height: 18, borderRadius: 9, borderWidth: 2, borderColor: color.line },
  dotOn: { borderColor: color.accent, backgroundColor: color.accent },
});
