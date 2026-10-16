-- Rotazione della chiave dell'organizzazione: ogni passaggio è firmato dalla chiave precedente,
-- così i client che hanno fissato una chiave possono seguire la catena in sicurezza.
ALTER TABLE org ADD COLUMN key_version integer NOT NULL DEFAULT 1;

CREATE TABLE org_rotations (
  version              integer PRIMARY KEY,
  old_sign_public      text NOT NULL,
  new_sign_public      text NOT NULL,
  new_recovery_public  text NOT NULL,
  signature            text NOT NULL,
  rotated_by           uuid NOT NULL REFERENCES users(id),
  created_at           timestamptz NOT NULL DEFAULT now()
);
