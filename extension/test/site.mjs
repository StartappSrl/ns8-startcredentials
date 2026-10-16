/** Script di riconoscimento sulla pagina iniziale del server. */
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const html = readFileSync("../app/public/index.html", "utf8").replaceAll("__VERSION__", "test");
const script = readFileSync("dist/site.js", "utf8");

function open(hash) {
  const dom = new JSDOM(html, { url: `https://secures.example.it/${hash}`, runScripts: "outside-only" });
  const w = dom.window;
  const sent = [];
  w.chrome = { runtime: { sendMessage: (m) => { sent.push(JSON.parse(JSON.stringify(m))); return Promise.resolve(); } } };
  w.eval(script);
  const $ = (id) => w.document.getElementById(id);
  return { w, $, sent };
}

// Senza estensione la pagina mostra le istruzioni (sezione «installata» nascosta di partenza).
{
  const dom = new JSDOM(html);
  assert.ok(dom.window.document.getElementById("sc-installed").hasAttribute("hidden"));
  assert.ok(!dom.window.document.getElementById("sc-install").hasAttribute("hidden"));
}
// Con l'estensione: istruzioni nascoste, pulsante per aprirla.
{
  const p = open("");
  assert.ok(p.$("sc-install").hasAttribute("hidden"));
  assert.ok(!p.$("sc-installed").hasAttribute("hidden"));
  assert.ok(p.$("sc-accept").hasAttribute("hidden"), "nessun invito da attivare");
  p.$("sc-open").dispatchEvent(new p.w.MouseEvent("click", { bubbles: true }));
  assert.deepEqual(p.sent, [{ type: "open-app", hash: "" }]);
}
// Collegamento di invito: si completa nell'estensione.
{
  const p = open("#invite=AbCdEf0123456789_-xyz");
  assert.ok(!p.$("sc-accept").hasAttribute("hidden"));
  assert.equal(p.$("sc-accept").textContent, "Attiva l'invito nell'estensione");
  p.$("sc-accept").dispatchEvent(new p.w.MouseEvent("click", { bubbles: true }));
  assert.deepEqual(p.sent, [{ type: "open-app", hash: "#invite=AbCdEf0123456789_-xyz" }]);
}
// Codice alterato (caratteri non ammessi): ignorato.
{
  const p = open("#invite=<script>alert(1)</script>");
  assert.ok(p.$("sc-accept").hasAttribute("hidden"));
}
console.log("✓ pagina del server: estensione riconosciuta, invito apribile nell'estensione, codici alterati ignorati");
