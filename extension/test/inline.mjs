/** Script delle pagine: icona sui campi di accesso e OTP, menu sotto il campo, cattura all'invio. */
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const dom = new JSDOM(`<!doctype html><body>
  <form id="login"><input id="u" name="username"><input id="p" type="password"></form>
  <input id="search" type="search" name="q">
  <form id="news"><input id="email" name="newsletter_email" type="email"></form>
  <form id="mfa"><input id="otp" name="code" autocomplete="one-time-code" inputmode="numeric"></form>
</body>`, { url: "https://portale.cliente.it/login", runScripts: "outside-only" });
const w = dom.window;
w.HTMLElement.prototype.getBoundingClientRect = () => ({ width: 200, height: 32, top: 10, left: 10, right: 210, bottom: 42 });
const attach = w.Element.prototype.attachShadow;
let shadow = null;
w.Element.prototype.attachShadow = function () { shadow = attach.call(this, { mode: "open" }); return shadow; };
const sent = [];
w.chrome = { runtime: { sendMessage: (m) => { sent.push(m); return Promise.resolve(); }, getURL: (p) => `chrome-extension://abcdef/${p}` } };

const script = readFileSync("dist/inline.js", "utf8");
w.eval(script);
const focus = (id) => w.document.getElementById(id).dispatchEvent(new w.FocusEvent("focusin", { bubbles: true }));
const btn = () => shadow?.querySelector("button");
const frame = () => shadow?.querySelector("iframe");
const click = (el) => el.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));

focus("search");
assert.equal(btn(), undefined, "nessuna icona nei campi di ricerca");
focus("email");
assert.equal(btn(), undefined, "nessuna icona in un modulo senza password");
focus("u");
assert.equal(btn().style.display, "block", "icona sul campo utente di un modulo di accesso");
click(btn());
assert.equal(frame().style.display, "block");
assert.equal(frame().getAttribute("src"), "chrome-extension://abcdef/inline-menu.html#field=login");
click(btn());
assert.equal(frame().style.display, "none", "secondo clic: menu chiuso");
console.log("✓ icona sul campo di accesso: menu dell'estensione sotto il campo");

focus("otp");
assert.equal(btn().style.display, "block", "icona sul campo del codice OTP");
click(btn());
assert.equal(frame().getAttribute("src"), "chrome-extension://abcdef/inline-menu.html#field=otp");
w.document.body.dispatchEvent(new w.MouseEvent("mousedown", { bubbles: true }));
assert.equal(frame().style.display, "none", "clic fuori: menu chiuso");
console.log("✓ campo OTP riconosciuto: menu con i codici; si chiude cliccando fuori");

// Nessun dato della pagina viene inviato aprendo il menu.
w.document.getElementById("p").value = "segreto";
click(btn());
assert.ok(!JSON.stringify(sent).includes("segreto"));

// Invio del modulo di accesso: utente e password vanno solo al service worker.
w.document.getElementById("u").value = "mario";
w.document.getElementById("p").value = "Password-Nuova-1";
w.document.getElementById("login").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
const cap = () => JSON.parse(JSON.stringify(sent)).filter((m) => m.type === "login-captured");
assert.equal(cap().length, 1);
assert.equal(cap()[0].username, "mario");
assert.equal(cap()[0].password, "Password-Nuova-1");
w.document.getElementById("login").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
w.document.getElementById("news").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
assert.equal(cap().length, 1);
console.log("✓ invio del modulo: accesso inviato una sola volta al service worker, niente dai moduli senza password");

w.eval(script);
assert.equal(w.document.querySelectorAll("html > div").length, 1, "nessuna interfaccia duplicata");
