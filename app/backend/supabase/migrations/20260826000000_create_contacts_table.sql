CREATE TABLE contacts (
  id                UUID          NOT NULL DEFAULT gen_random_uuid(),
  owner_public_key  TEXT          NOT NULL,
  address           TEXT          NOT NULL,
  nickname          TEXT          NOT NULL DEFAULT '',
  tags              TEXT[]        NOT NULL DEFAULT '{}',
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  PRIMARY KEY (id, owner_public_key)
);

CREATE INDEX contacts_owner_updated_idx
  ON contacts (owner_public_key, updated_at DESC);

CREATE UNIQUE INDEX contacts_owner_address_unique
  ON contacts (owner_public_key, lower(address));
