/** Verifica lo script delle pagine: compare sui campi di accesso, non altrove, e apre il popup. */
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const dom = new JSDOM(`<!doctype html><body>
  <form id="login"><input id="u" name="username"><input id="p" type="password"></form>
  <input id="search" type="search" name="q">
  <form id="news"><input id="email" name="newsletter_email" type="email"></form>
</body>`, { url: "https://portale.cliente.it/login", runScripts: "outside-only" });
const w = dom.window;
// jsdom non calcola il layout: dimensioni finte, e shadow DOM aperto per poterlo ispezionare.
w.HTMLElement.prototype.getBoundingClientRect = () => ({ width: 200, height: 32, top: 10, left: 10, right: 210, bottom: 42 });
const attach = w.Element.prototype.attachShadow;
let shadow = null;
w.Element.prototype.attachShadow = function () { shadow = attach.call(this, { mode: "open" }); return shadow; };
const sent = [];
w.chrome = { runtime: { sendMessage: (m) => { sent.push(m); return Promise.resolve(); } } };

w.eval(readFileSync("dist/inline.js", "utf8"));
const focus = (id) => w.document.getElementById(id).dispatchEvent(new w.FocusEvent("focusin", { bubbles: true }));
const btn = () => shadow?.querySelector("button");

focus("search");
assert.equal(btn(), undefined, "nessuna icona nei campi di ricerca");
focus("email");
assert.equal(btn(), undefined, "nessuna icona in un modulo senza password");
focus("u");
assert.ok(btn(), "icona sul campo utente di un modulo di accesso");
assert.equal(btn().style.display, "block");
focus("p");
assert.equal(btn().style.display, "block");
btn().dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
assert.equal(JSON.stringify(sent), JSON.stringify([{ type: "open-popup" }]));
// Lo script non deve mai inviare il contenuto dei campi.
w.document.getElementById("p").value = "segreto";
btn().dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
assert.ok(!JSON.stringify(sent).includes("segreto"));
// Eseguito due volte (es. reiniezione) non duplica l'interfaccia.
w.eval(readFileSync("dist/inline.js", "utf8"));
assert.equal(w.document.querySelectorAll("body ~ div, html > div").length, 1);
console.log("✓ icona nei campi: solo moduli di accesso, apre il popup, non trasmette dati");
