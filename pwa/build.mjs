// Build della PWA: bundle con esbuild + copia dei file statici in dist/.
// L'app è un modulo ESM; il service worker è classico (IIFE) per la massima compatibilità.
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

// libsodium/kdbxweb chiedono moduli di Node all'avvio ma nel browser usano WebCrypto:
// li sostituiamo con moduli vuoti (come fa extension/node-stubs.mjs).
const NODE_BUILTINS = ["crypto", "fs", "path", "url", "worker_threads"];
const nodeStubs = {
  name: "node-stubs",
  setup(b) {
    const filter = new RegExp(`^(node:)?(${NODE_BUILTINS.join("|")})$`);
    b.onResolve({ filter }, (args) => ({ path: args.path, namespace: "node-stub" }));
    b.onLoad({ filter: /.*/, namespace: "node-stub" }, () => ({ contents: "module.exports = {};", loader: "js" }));
  },
};

const out = "dist";
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

await build({
  entryPoints: { app: "src/app.tsx" },
  outdir: out,
  bundle: true,
  format: "esm",
  target: "safari16",
  minify: true,
  sourcemap: false,
  jsx: "automatic",
  jsxImportSource: "preact",
  define: { "process.env.NODE_ENV": '"production"' },
  plugins: [nodeStubs],
  logLevel: "warning",
});

await build({
  entryPoints: { sw: "src/sw.ts" },
  outdir: out,
  bundle: true,
  format: "iife",
  target: "safari16",
  minify: true,
  logLevel: "warning",
});

cpSync("static", out, { recursive: true });

// Caratteri self-hosted (stesso stile dell'app): copiati da @fontsource come fa l'estensione.
const fonts = {
  "jakarta-400.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-400-normal.woff2",
  "jakarta-500.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-500-normal.woff2",
  "jakarta-600.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-600-normal.woff2",
  "jakarta-700.woff2": "plus-jakarta-sans/files/plus-jakarta-sans-latin-700-normal.woff2",
  "mono-400.woff2": "jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2",
  "mono-500.woff2": "jetbrains-mono/files/jetbrains-mono-latin-500-normal.woff2",
};
mkdirSync(join(out, "fonts"), { recursive: true });
for (const [dst, src] of Object.entries(fonts)) {
  cpSync(join("..", "node_modules", "@fontsource", src), join(out, "fonts", dst));
}

// Copia anche in app/public/m: è da lì che il backend serve la PWA sotto /m/
// (stesso schema con cui l'estensione scrive il suo zip in app/public).
const served = join("..", "app", "public", "m");
rmSync(served, { recursive: true, force: true });
mkdirSync(served, { recursive: true });
cpSync(out, served, { recursive: true });

console.log(`PWA costruita in ${join(process.cwd(), out)} e copiata in ${served}`);
