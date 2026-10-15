-- Codici MFA di riserva (solo HMAC, monouso) e rotazione delle chiavi in sospeso.

ALTER TABLE users ADD COLUMN mfa_backup_codes jsonb;

-- Impostato quando un membro perde l'accesso (revoca o uscita dall'azienda):
-- il primo gestore che apre la cassaforte ruota la chiave del contenitore.
ALTER TABLE containers ADD COLUMN rotation_required boolean NOT NULL DEFAULT false;
