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
console.log(`PWA costruita in ${join(process.cwd(), out)}`);
