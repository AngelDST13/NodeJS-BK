-- Esquema inicial de SecureVault.
-- Las invariantes viven en la BD (CHECK, UNIQUE, FK), no solo en la aplicación.

CREATE TABLE users (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email               text NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  password_hash       text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  role                text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  -- Dato sensible de perfil cifrado con AES-256-GCM (formato v<n>.iv.tag.data)
  phone_enc           text,
  phone_key_version   smallint,
  failed_login_count  integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  locked_until        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CHECK ((phone_enc IS NULL) = (phone_key_version IS NULL))
);
CREATE UNIQUE INDEX users_email_key ON users (email);

CREATE TABLE notes (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  title_enc        text NOT NULL,
  body_enc         text NOT NULL,
  enc_key_version  smallint NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notes_owner_id_idx ON notes (owner_id, created_at DESC);

-- Solo se guarda el SHA-256 del token, nunca el token (RF-06).
CREATE TABLE password_reset_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash  text NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX password_reset_tokens_hash_key ON password_reset_tokens (token_hash);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens (user_id);

-- Bitácora de seguridad (A09). Cada fila lleva un HMAC-SHA256 para detectar alteraciones.
CREATE TABLE audit_events (
  id           bigserial PRIMARY KEY,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  event_type   text NOT NULL,
  actor_id     uuid REFERENCES users (id) ON DELETE SET NULL,
  target_id    uuid,
  ip           text,
  details      jsonb NOT NULL DEFAULT '{}'::jsonb,
  hmac         text NOT NULL
);
CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at DESC);

-- Tabla de sesiones usada por connect-pg-simple.
CREATE TABLE session (
  sid     varchar NOT NULL PRIMARY KEY,
  sess    json NOT NULL,
  expire  timestamp(6) NOT NULL
);
CREATE INDEX session_expire_idx ON session (expire);
