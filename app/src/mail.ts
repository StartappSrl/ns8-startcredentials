import nodemailer from "nodemailer";
import { Config } from "./core.js";

export interface Mailer {
  enabled: boolean;
  send(to: string, subject: string, text: string): Promise<boolean>;
}

/** Usa lo smarthost del cluster NethServer quando configurato. */
const SIMPLE_ADDRESS = /^[^\s@<>()[\],;:"\\]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

export function createMailer(cfg: Config, onError: (e: unknown) => void = () => undefined): Mailer {
  if (!cfg.smtp) return { enabled: false, send: async () => false };
  const t = nodemailer.createTransport({
    host: cfg.smtp.host,
    port: cfg.smtp.port,
    secure: cfg.smtp.encryption === "tls",
    requireTLS: cfg.smtp.encryption === "starttls",
    ignoreTLS: cfg.smtp.encryption === "none",
    tls: { rejectUnauthorized: cfg.smtp.tlsVerify },
    auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.pass } : undefined,
  });
  return {
    enabled: true,
    async send(to, subject, text) {
      // Un solo indirizzo semplice: niente elenchi, nomi, commenti, a capo o parentesi angolari.
      // Gli indirizzi arrivano già validati; questa è una seconda difesa contro i dirottamenti.
      if (!SIMPLE_ADDRESS.test(to) || to.length > 254) {
        onError(new Error("Indirizzo email non valido"));
        return false;
      }
      try {
        await t.sendMail({ from: cfg.smtp!.from, to: { name: "", address: to }, subject, text });
        return true;
      } catch (e) {
        onError(e);
        return false;
      }
    },
  };
}
