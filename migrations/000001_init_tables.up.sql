BEGIN;

CREATE TABLE IF NOT EXISTS accounts (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login VARCHAR NOT NULL UNIQUE,
    hashed_password VARCHAR NOT NULL,
    hashed_master_password VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account_id ON sessions.account_uuid;

CREATE TABLE IF NOT EXISTS secrets (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    encrypted_content VARCHAR NOT NULL,
    encrypted_meta VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS secrets_owner_id ON secrets.owner_uuid;

COMMIT;
