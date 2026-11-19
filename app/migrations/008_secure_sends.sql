-- Invii sicuri di credenziali a destinatari anche esterni. Il server conserva
-- solo il pacchetto cifrato (chiave derivata dal codice di accesso, che il
-- server non riceve mai) e lo distrugge dopo l'ultima apertura o alla scadenza.
CREATE TABLE secure_sends (
  id               uuid PRIMARY KEY,
  token_hash       text NOT NULL UNIQUE,
  created_by       uuid NOT NULL REFERENCES users(id),
  container_id     uuid REFERENCES containers(id) ON DELETE SET NULL,
  item_id          uuid REFERENCES items(id) ON DELETE SET NULL,
  recipient_email  text NOT NULL,
  envelope         text,
  expires_at       timestamptz NOT NULL,
  max_views        integer NOT NULL,
  views            integer NOT NULL DEFAULT 0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_opened_at   timestamptz,
  revoked_at       timestamptz
);
CREATE INDEX secure_sends_creator_idx ON secure_sends (created_by);
CREATE INDEX secure_sends_expiry_idx ON secure_sends (expires_at) WHERE envelope IS NOT NULL;
