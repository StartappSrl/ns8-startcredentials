// Impacchetta il motore (SDK + libsodium + OPAQUE) in un'unica pagina HTML per la WebView.
// Si esegue dalla radice del monorepo: node mobile/scripts/build-engine.mjs
import { build } from "esbuild";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { nodeStubs } from "../../extension/node-stubs.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const r = await build({
  entryPoints: [join(here, "../engine/engine.ts")],
  bundle: true, write: false, format: "iife", platform: "browser", target: "chrome100",
  minify: true, legalComments: "none", plugins: [nodeStubs], logLevel: "warning",
});
const js = r.outputFiles[0].text.replaceAll("</script", "<\\/script");
// Nessuna rete diretta (connect-src assente): le richieste passano dall'app nativa.
const csp = "default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'";
const html = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}"></head><body><script>${js}</script></body></html>`;
const out = join(here, "../src/engine/engineHtml.ts");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `// File generato da scripts/build-engine.mjs: non modificare.\nexport const ENGINE_HTML = ${JSON.stringify(html)};\n`);
console.log(`Motore: ${(html.length / 1024).toFixed(0)} KB`);
