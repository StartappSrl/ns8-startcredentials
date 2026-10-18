-- Dispositivi attendibili: per un periodo limitato evitano il codice MFA allo stesso
-- dispositivo, che deve comunque conoscere la master password (OPAQUE).
CREATE TABLE trusted_devices (
  id            uuid PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    text NOT NULL UNIQUE,
  name          text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz,
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);
CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id);
