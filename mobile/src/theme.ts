import { Appearance } from "react-native";

/**
 * Colori StartApp: blu #0068CF su bianco (contrasto 5,1:1). Il tema scuro segue
 * l'impostazione di sistema all'avvio dell'app.
 */
export const isDark = Appearance.getColorScheme() === "dark";

const light = {
  accent: "#0068CF",
  accentDark: "#00519F",
  accentSoft: "#E8F2FC",
  accentLine: "#B4D4F4",
  ground: "#F4F8FD",
  surface: "#FFFFFF",
  line: "#E1E9F3",
  ink: "#0B1B2E",
  ink2: "#33475E",
  muted: "#536780",
  danger: "#B42318",
  dangerSoft: "#FEF3F2",
  warnSoft: "#FBF3E6",
  warnInk: "#5C3507",
  ok: "#027A48",
};

// Su fondo scuro: blu dei pulsanti con testo bianco ancora leggibile (circa 5:1).
const dark: typeof light = {
  accent: "#1F6FC5",
  accentDark: "#A9D2FF",
  accentSoft: "#10325A",
  accentLine: "#24548A",
  ground: "#08172A",
  surface: "#0F223A",
  line: "#1E3654",
  ink: "#EEF4FB",
  ink2: "#C6D5E6",
  muted: "#93A8C0",
  danger: "#FF8A80",
  dangerSoft: "#3A1418",
  warnSoft: "#3A2A10",
  warnInk: "#F5C77E",
  ok: "#6CE9A6",
};

export const color = isDark ? dark : light;
export const radius = 10;
export const mono = "monospace";
