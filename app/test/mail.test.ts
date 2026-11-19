/**
 * Invio reale con Nodemailer verso un server SMTP minimo: autenticazione,
 * mittente, destinatario, testo, e rifiuto degli indirizzi costruiti ad arte.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createMailer } from "../src/mail.js";

function fakeSmtp() {
  const got = { auth: "", from: "", rcpt: [] as string[], data: "" };
  const server = net.createServer((s) => {
    let inData = false;
    let buf = "";
    const say = (l: string) => s.write(l + "\r\n");
    say("220 prova ESMTP");
    s.on("data", (chunk) => {
      buf += chunk.toString();
      let i;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === ".") { inData = false; say("250 OK"); } else got.data += line + "\n";
          continue;
        }
        const u = line.toUpperCase();
        if (u.startsWith("EHLO")) s.write("250-prova\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n");
        else if (u.startsWith("AUTH PLAIN")) { got.auth = Buffer.from(line.split(" ")[2]!, "base64").toString().split("\0").slice(1).join(":"); say("235 OK"); }
        else if (u.startsWith("MAIL FROM")) { got.from = line; say("250 OK"); }
        else if (u.startsWith("RCPT TO")) { got.rcpt.push(line); say("250 OK"); }
        else if (u === "DATA") { inData = true; say("354 avanti"); }
        else if (u === "QUIT") { say("221 ciao"); s.end(); }
        else say("250 OK");
      }
    });
  });
  return { server, got };
}

const decodeQp = (raw: string) => raw.split("\n\n").slice(1).join("\n\n").replace(/=\n/g, "")
  .replace(/(=[0-9A-F]{2})+/g, (m) => Buffer.from(m.replace(/=/g, ""), "hex").toString("utf8"));

test("invio email: Nodemailer verso lo smarthost, e indirizzi costruiti ad arte rifiutati", async () => {
  const { server, got } = fakeSmtp();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as net.AddressInfo).port;
  const errors: unknown[] = [];
  const mailer = createMailer({
    smtp: { host: "127.0.0.1", port, user: "smarthost", pass: "segreto", encryption: "none", tlsVerify: false, from: "credenziali@startappitalia.it" },
  } as never, (e) => errors.push(e));
  try {
    assert.equal(await mailer.send("sara.personale@example.org", "Recupero del tuo account", "Collegamento: https://x/#recover=ABC\nperò"), true);
    assert.equal(got.auth, "smarthost:segreto");
    assert.match(got.from, /credenziali@startappitalia\.it/);
    assert.deepEqual(got.rcpt.map((r) => r.match(/<(.+)>/)![1]), ["sara.personale@example.org"]);
    assert.match(got.data, /Subject: Recupero del tuo account/);
    assert.match(decodeQp(got.data), /recover=ABC\nperò/);

    got.rcpt = [];
    for (const bad of [
      "vittima@example.org\r\nRCPT TO:<intruso@example.org>",
      "Vittima <intruso@example.org>",
      "a@example.org, intruso@example.org",
      "a@example.org;intruso@example.org",
      "(commento)intruso@example.org",
    ]) assert.equal(await mailer.send(bad, "x", "y"), false, bad);
    assert.deepEqual(got.rcpt, [], "nessun destinatario raggiunto");
    assert.equal(errors.length, 5);
  } finally {
    server.close();
  }
});
