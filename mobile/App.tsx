import { StatusBar } from "expo-status-bar";
import { Pressable, Text, View } from "react-native";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";
import { usePreventScreenCapture } from "expo-screen-capture";
import { EngineProvider, useEngine } from "./src/engine/Engine";
import { AppProvider, Route, useApp } from "./src/state/App";
import { LoginScreen, MfaScreen, MfaSetupScreen, SetupScreen } from "./src/screens/Auth";
import { ClientsScreen, ContainerScreen, ItemScreen, SearchScreen, SharedScreen } from "./src/screens/Vault";
import { SettingsScreen } from "./src/screens/Settings";
import { color } from "./src/theme";

const TABS: { route: Route; label: string }[] = [
  { route: { name: "clients" }, label: "Clienti" },
  { route: { name: "search" }, label: "Cerca" },
  { route: { name: "shared" }, label: "Condivise" },
  { route: { name: "settings" }, label: "Impostazioni" },
];

function Main() {
  const app = useApp();
  const engine = useEngine();
  // Nessuno screenshot né anteprima nelle app recenti mentre la cassaforte è aperta.
  usePreventScreenCapture();
  if (app.phase === "boot") return <View style={{ flex: 1, backgroundColor: color.ground }} />;
  if (app.phase === "setup") return <SetupScreen />;
  if (app.phase === "login") return <LoginScreen />;
  if (app.phase === "mfa") return <MfaScreen />;
  if (app.phase === "mfaSetup") return <MfaSetupScreen />;
  const r = app.route;
  const screen =
    r.name === "clients" ? <ClientsScreen /> :
    r.name === "search" ? <SearchScreen /> :
    r.name === "shared" ? <SharedScreen /> :
    r.name === "settings" ? <SettingsScreen /> :
    r.name === "container" ? <ContainerScreen key={r.id} id={r.id} title={r.title} /> :
    <ItemScreen key={r.item.id} item={r.item} whereName={r.where} />;
  const active = ["clients", "container", "item"].includes(r.name) ? "clients" : r.name;
  return (
    <View style={{ flex: 1, backgroundColor: color.ground }}>
      {engine.offline && (
        <View style={{ backgroundColor: color.warnSoft, paddingVertical: 6, paddingHorizontal: 12 }} accessibilityLiveRegion="polite">
          <Text style={{ color: color.warnInk, fontSize: 13, textAlign: "center" }}>
            Offline · sola lettura{engine.lastSync ? ` · dati del ${new Date(engine.lastSync).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" })}` : ""}
          </Text>
        </View>
      )}
      <View style={{ flex: 1 }}>{screen}</View>
      <View style={{ flexDirection: "row", borderTopWidth: 1, borderTopColor: color.line, backgroundColor: color.surface }} accessibilityRole="tablist">
        {TABS.map((t) => {
          const on = active === t.route.name;
          return (
            <Pressable key={t.label} accessibilityRole="tab" accessibilityState={{ selected: on }} onPress={() => app.tab(t.route)}
              style={{ flex: 1, minHeight: 56, alignItems: "center", justifyContent: "center", borderTopWidth: 2, borderTopColor: on ? color.accent : "transparent" }}>
              <Text style={{ color: on ? color.accent : color.muted, fontWeight: on ? "700" : "500", fontSize: 13 }}>{t.label}</Text>
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <SafeAreaView style={{ flex: 1, backgroundColor: color.surface }} edges={["top", "bottom"]}>
        <EngineProvider>
          <AppProvider>
            <Main />
          </AppProvider>
        </EngineProvider>
        <StatusBar style="dark" />
      </SafeAreaView>
    </SafeAreaProvider>
  );
}
