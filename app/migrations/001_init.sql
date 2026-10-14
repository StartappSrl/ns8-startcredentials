-- StartCredentials: schema iniziale.
-- Tutte le colonne *_enc contengono buste AEAD prodotte dal client:
-- il server non possiede le chiavi per decifrarle.

CREATE TABLE settings (
  key   text PRIMARY KEY,
  value text NOT NULL
);

CREATE TABLE users (
  id                  uuid PRIMARY KEY,
  email               text NOT NULL,
  display_name        text NOT NULL,
  role                text NOT NULL CHECK (role IN ('admin', 'user')),
  status              text NOT NULL CHECK (status IN ('invited', 'active', 'suspended')),
  opaque_record       text,
  key_version         integer NOT NULL DEFAULT 0,
  mfa_secret_enc      text,
  mfa_enabled         boolean NOT NULL DEFAULT false,
  mfa_last_counter    bigint NOT NULL DEFAULT 0,
  invite_token_hash   text,
  invite_expires_at   timestamptz,
  recovery_token_hash text,
  recovery_blob       jsonb,
  recovery_expires_at timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_idx ON users (lower(email));

CREATE TABLE user_keys (
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version        integer NOT NULL,
  box_public     text NOT NULL,
  sign_public    text NOT NULL,
  private_enc    text NOT NULL,
  kdf_params     jsonb NOT NULL,
  recovery_enc   text,
  certification  text,
  certified_by   uuid REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, version)
);

CREATE TABLE sessions (
  id           uuid PRIMARY KEY,
  token_hash   text NOT NULL UNIQUE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state        text NOT NULL CHECK (state IN ('mfa_setup', 'mfa_pending', 'active')),
  ip           text,
  user_agent   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE org (
  id                  integer PRIMARY KEY CHECK (id = 1),
  sign_public         text NOT NULL,
  recovery_public     text NOT NULL,
  recovery_threshold  integer NOT NULL,
  recovery_shares     integer NOT NULL,
  container_id        uuid NOT NULL,
  created_by          uuid NOT NULL REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE containers (
  id            uuid PRIMARY KEY,
  kind          text NOT NULL CHECK (kind IN ('client', 'personal', 'org')),
  meta_key_enc  text NOT NULL,
  meta_enc      text NOT NULL,
  key_version   integer NOT NULL DEFAULT 1,
  created_by    uuid NOT NULL REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz
);

CREATE TABLE container_keys (
  container_id  uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  key_version   integer NOT NULL,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sealed_key    text NOT NULL,
  permission    text NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
  granted_by    uuid NOT NULL REFERENCES users(id),
  signature     text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (container_id, key_version, user_id)
);
CREATE INDEX container_keys_user_idx ON container_keys (user_id);

CREATE TABLE folders (
  id            uuid PRIMARY KEY,
  container_id  uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  parent_id     uuid REFERENCES folders(id) ON DELETE CASCADE,
  meta_enc      text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE items (
  id             uuid PRIMARY KEY,
  container_id   uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  folder_id      uuid REFERENCES folders(id) ON DELETE SET NULL,
  type           text NOT NULL CHECK (type IN ('login', 'totp', 'note', 'file', 'ssh_key')),
  ik_enc         text NOT NULL,
  ik_key_version integer NOT NULL,
  data_enc       text NOT NULL,
  host_hashes    text[] NOT NULL DEFAULT '{}',
  revision       integer NOT NULL DEFAULT 1,
  created_by     uuid NOT NULL REFERENCES users(id),
  updated_by     uuid NOT NULL REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz
);
CREATE INDEX items_container_idx ON items (container_id);
CREATE INDEX items_host_hashes_idx ON items USING gin (host_hashes);

CREATE TABLE item_versions (
  item_id     uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  revision    integer NOT NULL,
  data_enc    text NOT NULL,
  created_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (item_id, revision)
);

CREATE TABLE attachments (
  id            uuid PRIMARY KEY,
  item_id       uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  container_id  uuid NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  fk_enc        text NOT NULL,
  meta_enc      text NOT NULL,
  header        text NOT NULL,
  size          bigint NOT NULL,
  chunk_count   integer NOT NULL,
  status        text NOT NULL CHECK (status IN ('uploading', 'ready')),
  created_by    uuid NOT NULL REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attachments_item_idx ON attachments (item_id);

CREATE TABLE audit_log (
  id           bigserial PRIMARY KEY,
  at           timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid,
  action       text NOT NULL,
  target_type  text,
  target_id    text,
  container_id uuid,
  ip           text,
  details      jsonb NOT NULL DEFAULT '{}',
  prev_hash    text NOT NULL,
  hash         text NOT NULL
);
CREATE INDEX audit_container_idx ON audit_log (container_id);
CREATE INDEX audit_actor_idx ON audit_log (actor_id);
