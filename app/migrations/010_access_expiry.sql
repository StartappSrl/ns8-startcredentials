-- Accessi a tempo: una condivisione diretta (sola lettura o modifica) può avere
-- una scadenza. Alla scadenza l'accesso viene tolto e la chiave del cliente
-- va ruotata (la completa il primo gestore che apre la cassaforte).
ALTER TABLE container_keys ADD COLUMN expires_at timestamptz;
CREATE INDEX container_keys_expiry_idx ON container_keys (expires_at) WHERE expires_at IS NOT NULL;
