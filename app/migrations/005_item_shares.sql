-- Condivisione di singoli elementi (sola lettura). La versione della chiave
-- dell'elemento cambia a ogni revoca: le consegne precedenti non valgono più.
ALTER TABLE items ADD COLUMN ik_version integer NOT NULL DEFAULT 1;
ALTER TABLE items ADD COLUMN rekey_required boolean NOT NULL DEFAULT false;

CREATE TABLE item_shares (
  item_id     uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ik_version  integer NOT NULL,
  sealed_key  text NOT NULL,
  granted_by  uuid NOT NULL REFERENCES users(id),
  signature   text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (item_id, user_id)
);
CREATE INDEX item_shares_user_idx ON item_shares (user_id);
