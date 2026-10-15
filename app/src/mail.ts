import nodemailer from "nodemailer";
import { Config } from "./core.js";

export interface Mailer {
  enabled: boolean;
  send(to: string, subject: string, text: string): Promise<boolean>;
}

/** Usa lo smarthost del cluster NethServer quando configurato. */
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
      try {
        await t.sendMail({ from: cfg.smtp!.from, to, subject, text });
        return true;
      } catch (e) {
        onError(e);
        return false;
      }
    },
  };
}
