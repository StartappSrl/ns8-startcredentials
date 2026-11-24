-- Accesso d'emergenza a un cliente. Un gestore designa un collega e prepara in
-- anticipo la consegna della chiave del cliente, cifrata per quel collega e
-- firmata da chi la concede. Il server la custodisce senza poterla leggere e la
-- rende effettiva solo se il collega la chiede e nessun gestore la rifiuta entro
-- il tempo di attesa (o se un gestore la approva prima).
CREATE TABLE emergency_access (
  id                  uuid PRIMARY KEY,
  container_id        uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Consegna già firmata, trattenuta finché l'accesso non diventa effettivo.
  key_version         integer NOT NULL,
  recipient_key_version integer NOT NULL,
  permission          text NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
  sealed_key          text NOT NULL,
  granted_by          uuid NOT NULL REFERENCES users(id),
  signature           text NOT NULL,
  -- Nome del cliente sigillato per il designato (il server non lo conosce).
  label_enc           text NOT NULL,
  wait_hours          integer NOT NULL CHECK (wait_hours BETWEEN 1 AND 720),
  created_by          uuid NOT NULL REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  requested_at        timestamptz,
  rejected_at         timestamptz,
  rejected_by         uuid REFERENCES users(id),
  UNIQUE (container_id, user_id)
);
CREATE INDEX emergency_access_user_idx ON emergency_access (user_id);
