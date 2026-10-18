// Build dell'estensione: bundle con esbuild, copia dei file statici e dei font, archivio zip.
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { zipSync } from "fflate";
import { nodeStubs } from "./node-stubs.mjs";

const out = "dist";

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "fonts"), { recursive: true });

await build({
  entryPoints: { background: "src/background.ts", popup: "src/popup.tsx", app: "src/app.tsx", offscreen: "src/offscreen.ts", "inline-menu": "src/inline-menu.tsx" },
  outdir: out,
  bundle: true,
  format: "esm",
  target: "chrome127",
  minify: true,
  sourcemap: false,
  legalComments: "external",
  jsx: "automatic",
  jsxImportSource: "preact",
  define: { "process.env.NODE_ENV": '"production"' },
  // Alcune librerie (kdbxweb, libsodium) chiedono moduli di Node all'avvio
  // ma nel browser usano WebCrypto: li sostituiamo con moduli vuoti.
  plugins: [nodeStubs],
  logLevel: "warning",
});

// Lo script delle pagine non può essere un modulo: build separata in IIFE.
await build({
  entryPoints: { inline: "src/inline.ts", site: "src/site.ts" }, outdir: out, bundle: true, format: "iife",
  target: "chrome127", minify: true, logLevel: "warning",
});

cpSync("static", out, { recursive: true });
const fonts = {
  "jakarta-400.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-400-normal.woff2",
  "jakarta-500.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-500-normal.woff2",
  "jakarta-600.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-600-normal.woff2",
  "jakarta-700.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-700-normal.woff2",
  "mono-400.woff2": "jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2",
  "mono-500.woff2": "jetbrains-mono/files/jetbrains-mono-latin-500-normal.woff2",
};
for (const [dst, src] of Object.entries(fonts)) cpSync(join("..", "node_modules", "@fontsource", src), join(out, "fonts", dst));

const files = {};
const walk = (d) => {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else files[relative(out, p)] = readFileSync(p);
  }
};
walk(out);
const zip = zipSync(files, { level: 9 });
writeFileSync("startcredentials-extension.zip", zip);
writeFileSync(join("..", "app", "public", "startcredentials-extension.zip"), zip);
console.log(`Estensione: ${Object.keys(files).length} file, ${(zip.length / 1024).toFixed(0)} KB`);
