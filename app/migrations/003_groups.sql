-- Gruppi: coppia di chiavi X25519 certificata dall'organizzazione.
CREATE TABLE groups (
  id                 uuid PRIMARY KEY,
  name               text NOT NULL,
  key_version        integer NOT NULL DEFAULT 1,
  box_public         text NOT NULL,
  certification      text NOT NULL,
  rotation_required  boolean NOT NULL DEFAULT false,
  created_by         uuid NOT NULL REFERENCES users(id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);

-- Chiave privata del gruppo consegnata a ciascun membro.
CREATE TABLE group_members (
  group_id     uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  key_version  integer NOT NULL,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role         text NOT NULL CHECK (role IN ('member', 'manager')),
  sealed_key   text NOT NULL,
  granted_by   uuid NOT NULL REFERENCES users(id),
  signature    text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, key_version, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

-- Chiave di un contenitore sigillata per la chiave pubblica di un gruppo.
CREATE TABLE container_group_keys (
  container_id       uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  key_version        integer NOT NULL,
  group_id           uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  group_key_version  integer NOT NULL,
  permission         text NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
  sealed_key         text NOT NULL,
  granted_by         uuid NOT NULL REFERENCES users(id),
  signature          text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (container_id, key_version, group_id)
);
CREATE INDEX container_group_keys_group_idx ON container_group_keys (group_id);
