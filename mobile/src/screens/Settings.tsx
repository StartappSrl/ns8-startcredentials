import { useEffect, useState } from "react";
import { Alert, ScrollView, Switch, Text, View } from "react-native";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { biometricAvailable, clearBiometricSession, clearDeviceTrust, saveBiometricSession } from "../state/storage";
import { Button, Card, Notice } from "../ui/kit";
import { Header } from "./Vault";
import { AppState } from "react-native";
import { Autofill } from "../../modules/sc-autofill";
import { color, mono } from "../theme";

const LOCKS = [0, 1, 5, 15];

export function SettingsScreen() {
  const engine = useEngine();
  const app = useApp();
  const [devices, setDevices] = useState<{ id: string; name: string; expiresAt: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [autofillOn, setAutofillOn] = useState(Autofill.isEnabled());
  // Al ritorno dalle impostazioni di Android si aggiorna lo stato.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (st) => { if (st === "active") setAutofillOn(Autofill.isEnabled()); });
    return () => sub.remove();
  }, []);
  const loadDevices = () => engine.call<{ devices: { id: string; name: string; expiresAt: string }[] }>("devices").then((r) => setDevices(r.devices)).catch(() => undefined);
  useEffect(() => { void loadDevices(); }, []);

  const toggleBio = async (on: boolean) => {
    setError(null);
    try {
      if (on) await saveBiometricSession(await engine.call("serialize"));
      else await clearBiometricSession();
      await app.updateSettings({ biometric: on });
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <View style={{ flex: 1 }}>
      <Header title="Impostazioni" subtitle={app.me?.email} />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 16 }}>
        <Card>
          <Text style={{ fontWeight: "700", color: color.ink }}>Impronta della tua chiave</Text>
          <Text style={{ color: color.muted }}>Leggila a voce all'amministratore quando deve certificare la tua chiave.</Text>
          <Text style={{ fontFamily: mono, fontSize: 16, color: color.ink }} selectable>{app.fingerprint}</Text>
        </Card>
        <Card>
          <Text style={{ fontWeight: "700", color: color.ink }}>Sicurezza</Text>
          {biometricAvailable() && (
            <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
              <Text style={{ flex: 1, color: color.ink2 }}>Sblocco con l'impronta</Text>
              <Switch value={!!app.settings.biometric} onValueChange={toggleBio} trackColor={{ true: color.accent }} accessibilityLabel="Sblocco con l'impronta" />
            </View>
          )}
          <Text style={{ color: color.muted }}>Blocco automatico dopo che l'app passa in secondo piano:</Text>
          <View style={{ flexDirection: "row", gap: 8, flexWrap: "wrap" }}>
            {LOCKS.map((m) => (
              <Button key={m} kind={app.settings.autoLockMinutes === m ? "primary" : "secondary"} title={m === 0 ? "Subito" : `${m} min`}
                onPress={() => void app.updateSettings({ autoLockMinutes: m })} style={{ minHeight: 40, paddingHorizontal: 14 }} />
            ))}
          </View>
        </Card>
        {Autofill.isSupported() && (
          <Card>
            <Text style={{ fontWeight: "700", color: color.ink }}>Compilazione automatica</Text>
            <Text style={{ color: color.muted }}>
              {autofillOn ? "StartCredentials compila utente, password e OTP nelle app e nei siti." : "Scegli StartCredentials come servizio di compilazione automatica di Android."}
            </Text>
            {!autofillOn && <Button title="Attiva nelle impostazioni di Android" onPress={() => Autofill.openSettings()} />}
            <Text style={{ color: color.muted, fontSize: 13 }}>In Chrome attiva anche Impostazioni → Compilazione automatica → «Compila automaticamente utilizzando un altro servizio».</Text>
          </Card>
        )}
        <Card>
          <Text style={{ fontWeight: "700", color: color.ink }}>Uso offline</Text>
          <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
            <Text style={{ flex: 1, color: color.ink2 }}>Disponibile senza rete (sola lettura)</Text>
            <Switch value={app.settings.offline !== false} trackColor={{ true: color.accent }} accessibilityLabel="Disponibile senza rete"
              onValueChange={async (on) => {
                engine.setOfflineEnabled(on);
                if (!on) engine.wipeOffline();
                await app.updateSettings({ offline: on });
                if (on) void engine.syncForOffline();
              }} />
          </View>
          <Text style={{ color: color.muted }}>
            Sul telefono restano solo i dati cifrati, come sul server: servono comunque la master password o l'impronta.
            {engine.lastSync ? ` Ultima sincronizzazione: ${new Date(engine.lastSync).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" })}.` : ""}
          </Text>
          {app.settings.offline !== false && (
            <View style={{ flexDirection: "row", gap: 8 }}>
              <Button title={syncing ? "Sincronizzazione…" : "Sincronizza ora"} kind="secondary" busy={syncing} disabled={engine.offline} style={{ flex: 1 }}
                onPress={async () => { setSyncing(true); const ok = await engine.syncForOffline(); setSyncing(false); app.toast(ok ? "Dati offline aggiornati" : "Sincronizzazione non riuscita"); }} />
              <Button title="Elimina dati offline" kind="danger" style={{ flex: 1 }} onPress={() => { engine.wipeOffline(); app.toast("Dati offline eliminati"); }} />
            </View>
          )}
        </Card>
        <Card>
          <Text style={{ fontWeight: "700", color: color.ink }}>Dispositivi attendibili</Text>
          <Text style={{ color: color.muted }}>Da questi dispositivi l'accesso chiede solo la master password, senza codice MFA.</Text>
          {devices.length === 0 && <Text style={{ color: color.muted }}>Nessuno.</Text>}
          {devices.map((d) => (
            <View key={d.id} style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
              <Text style={{ flex: 1, color: color.ink }}>{d.name} · scade il {new Date(d.expiresAt).toLocaleDateString("it-IT")}</Text>
              <Button kind="danger" title="Revoca" onPress={async () => { await engine.call("revokeDevice", d.id).catch(() => undefined); void loadDevices(); }} style={{ minHeight: 40, paddingHorizontal: 12 }} />
            </View>
          ))}
        </Card>
        <Card>
          <Text style={{ fontWeight: "700", color: color.ink }}>Account</Text>
          <Button title="Salute delle password" kind="secondary" onPress={() => app.push({ name: "health" })} />
          <Button title="Cambia la master password" kind="secondary" disabled={engine.offline} onPress={() => app.push({ name: "changePassword" })} />
          <Button title="Codici di riserva MFA" kind="secondary" disabled={engine.offline} onPress={() => app.push({ name: "backupCodes" })} />
        </Card>
        {error && <Notice kind="error">{error}</Notice>}
        <Button title="Blocca ora" kind="secondary" onPress={() => void app.lock()} />
        <Button title="Esci dall'account" kind="danger" onPress={() => Alert.alert("Uscire dall'account?", "Al prossimo accesso servirà la master password e, se il telefono non è attendibile, il codice MFA.", [
          { text: "Annulla", style: "cancel" },
          { text: "Esci", style: "destructive", onPress: async () => { await clearDeviceTrust(); await app.logout(); } },
        ])} />
        <Text style={{ color: color.muted, fontSize: 13 }}>Server: {app.settings.serverUrl}</Text>
      </ScrollView>
    </View>
  );
}
