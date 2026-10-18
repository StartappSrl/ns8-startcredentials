import { ReactNode, useEffect, useState } from "react";
import { ActivityIndicator, Image, Pressable, StyleSheet, Text, TextInput, TextInputProps, View, ViewStyle } from "react-native";
import * as Clipboard from "expo-clipboard";
import { color, isDark, mono, radius } from "../theme";
import { useEngine } from "../engine/Engine";

export function Brand({ small }: { small?: boolean }) {
  return (
    <View style={{ gap: 4 }}>
      <View style={isDark ? { backgroundColor: "#FFFFFF", borderRadius: 8, padding: 6, alignSelf: "flex-start" } : undefined}>
        <Image source={require("../../assets/startapp-logo.png")} style={{ height: small ? 22 : 34, width: small ? 94 : 145 }} resizeMode="contain" accessibilityLabel="StartApp" />
      </View>
      <Text style={[s.brandName, small && { fontSize: 10 }]}>CREDENTIALS</Text>
    </View>
  );
}

export function Button({ title, onPress, kind = "primary", disabled, busy, style }: {
  title: string; onPress: () => void; kind?: "primary" | "secondary" | "danger" | "ghost"; disabled?: boolean; busy?: boolean; style?: ViewStyle;
}) {
  return (
    <Pressable accessibilityRole="button" accessibilityState={{ disabled: !!disabled || !!busy }} onPress={onPress} disabled={disabled || busy}
      style={({ pressed }) => [s.btn, kind === "primary" ? s.btnPrimary : kind === "danger" ? s.btnDanger : kind === "ghost" ? s.btnGhost : s.btnSecondary,
        (disabled || busy) && { opacity: 0.55 }, pressed && { opacity: 0.8 }, style]}>
      {busy ? <ActivityIndicator color={kind === "primary" ? "#fff" : color.accent} /> :
        <Text style={[s.btnText, kind === "primary" && { color: "#fff" }, kind === "danger" && { color: color.danger }]}>{title}</Text>}
    </Pressable>
  );
}

export function Field({ label, ...props }: TextInputProps & { label: string }) {
  return (
    <View style={{ gap: 6 }}>
      <Text style={s.label}>{label}</Text>
      <TextInput placeholderTextColor={color.muted} autoCapitalize="none" autoCorrect={false} {...props} style={[s.input, props.style]} accessibilityLabel={label} />
    </View>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "error" | "warn" | "ok"; children: ReactNode }) {
  const bg = { info: color.accentSoft, error: color.dangerSoft, warn: color.warnSoft, ok: "#ECFDF3" }[kind];
  const fg = { info: color.accentDark, error: color.danger, warn: color.warnInk, ok: color.ok }[kind];
  return <View style={[s.notice, { backgroundColor: bg }]}><Text style={{ color: fg, fontSize: 14, lineHeight: 20 }}>{children}</Text></View>;
}

export function Card({ children, style }: { children: ReactNode; style?: ViewStyle }) {
  return <View style={[s.card, style]}>{children}</View>;
}

/** Copia e svuota gli appunti dopo 30 secondi (se il contenuto è ancora quello copiato). */
export async function copySecret(text: string): Promise<void> {
  await Clipboard.setStringAsync(text);
  setTimeout(async () => {
    try {
      if ((await Clipboard.getStringAsync()) === text) await Clipboard.setStringAsync("");
    } catch {
      /* app in secondo piano */
    }
  }, 30_000);
}

export function CopyButton({ value, label = "Copia", onCopied, toast }: { value: string; label?: string; onCopied?: () => void; toast: (m: string) => void }) {
  return <Button kind="secondary" title={label} onPress={async () => { await copySecret(value); onCopied?.(); toast("Copiato: gli appunti si svuotano tra 30 secondi"); }} style={{ minHeight: 40, paddingHorizontal: 12 }} />;
}

export function OtpView({ uri, onCopy, toast }: { uri: string; onCopy?: () => void; toast: (m: string) => void }) {
  const engine = useEngine();
  const [st, setSt] = useState<{ code: string; secondsLeft: number; period: number } | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = () => engine.call<{ code: string; secondsLeft: number; period: number }>("totp", uri).then((r) => alive && setSt(r)).catch(() => undefined);
    tick();
    const t = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(t); };
  }, [uri]);
  if (!st) return null;
  const low = st.secondsLeft <= 5;
  return (
    <View style={s.otp}>
      <View style={{ flex: 1 }}>
        <Text style={s.label}>Codice OTP · {st.secondsLeft} s</Text>
        <Text style={[s.otpCode, low && { color: color.danger }]} accessibilityLabel={`Codice OTP ${st.code.split("").join(" ")}`}>{st.code.slice(0, 3)} {st.code.slice(3)}</Text>
        <View style={s.bar}><View style={[s.barFill, { width: `${(st.secondsLeft / st.period) * 100}%`, backgroundColor: low ? color.danger : color.accent }]} /></View>
      </View>
      <CopyButton value={st.code} onCopied={onCopy} toast={toast} />
    </View>
  );
}

export const s = StyleSheet.create({
  brandName: { fontSize: 12, fontWeight: "700", letterSpacing: 1.6, color: color.accent },
  btn: { minHeight: 46, paddingHorizontal: 18, borderRadius: radius, alignItems: "center", justifyContent: "center", borderWidth: 1 },
  btnPrimary: { backgroundColor: color.accent, borderColor: color.accent },
  btnSecondary: { backgroundColor: color.surface, borderColor: color.line },
  btnDanger: { backgroundColor: color.surface, borderColor: color.line },
  btnGhost: { backgroundColor: "transparent", borderColor: "transparent" },
  btnText: { fontSize: 15, fontWeight: "600", color: color.ink },
  label: { fontSize: 13, color: color.muted },
  input: { minHeight: 48, borderWidth: 1, borderColor: color.line, borderRadius: 8, paddingHorizontal: 12, fontSize: 16, color: color.ink, backgroundColor: color.surface },
  notice: { padding: 12, borderRadius: radius },
  card: { backgroundColor: color.surface, borderRadius: 14, borderWidth: 1, borderColor: color.line, padding: 16, gap: 12 },
  otp: { flexDirection: "row", alignItems: "center", gap: 12, padding: 14, borderRadius: 12, backgroundColor: color.accentSoft, borderWidth: 1, borderColor: color.accentLine },
  otpCode: { fontFamily: mono, fontSize: 28, letterSpacing: 3, color: color.ink, fontWeight: "600" },
  bar: { height: 4, borderRadius: 2, backgroundColor: color.accentLine, marginTop: 6 },
  barFill: { height: 4, borderRadius: 2 },
});
