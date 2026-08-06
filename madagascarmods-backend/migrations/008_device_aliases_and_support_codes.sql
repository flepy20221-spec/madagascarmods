-- CashPix 1.7.1 - identidade operacional e aliases de dispositivo
--
-- ANDROID_ID muda quando a chave de assinatura do aplicativo muda. A conta nao
-- pode depender de uma unica chave mutavel. Esta migracao separa:
--   * support_code: identificador curto, humano e permanente para atendimento;
--   * device_account_aliases: todas as chaves tecnicas que apontam para a conta;
--   * merged_into_user_id: rastreabilidade de contas duplicadas reconciliadas.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS support_code VARCHAR(17),
  ADD COLUMN IF NOT EXISTS support_label VARCHAR(120),
  ADD COLUMN IF NOT EXISTS merged_into_user_id UUID REFERENCES users(id),
  ADD COLUMN IF NOT EXISTS merged_at TIMESTAMP WITH TIME ZONE;

CREATE OR REPLACE FUNCTION cashpix_support_code(user_id UUID)
RETURNS VARCHAR(17)
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
  SELECT 'CP-'
      || upper(substr(replace(user_id::text, '-', ''), 1, 4)) || '-'
      || upper(substr(replace(user_id::text, '-', ''), 5, 4)) || '-'
      || upper(substr(replace(user_id::text, '-', ''), 9, 4));
$$;

UPDATE users
   SET support_code = cashpix_support_code(id)
 WHERE support_code IS NULL OR btrim(support_code) = '';

CREATE OR REPLACE FUNCTION assign_cashpix_support_code()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.support_code IS NULL OR btrim(NEW.support_code) = '' THEN
    NEW.support_code := cashpix_support_code(NEW.id);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_users_support_code ON users;
CREATE TRIGGER trg_users_support_code
BEFORE INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION assign_cashpix_support_code();

ALTER TABLE users
  ALTER COLUMN support_code SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_support_code_unique
  ON users(support_code);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'users_merged_not_self'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_merged_not_self
      CHECK (merged_into_user_id IS NULL OR merged_into_user_id <> id) NOT VALID;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS device_account_aliases (
  device_account_key VARCHAR(64) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source VARCHAR(40) NOT NULL DEFAULT 'primary',
  first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by_admin UUID REFERENCES admin_users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT device_account_aliases_key_format
    CHECK (device_account_key ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_device_account_aliases_user_id
  ON device_account_aliases(user_id);

-- Toda chave primaria existente passa a ser um alias resolvivel.
INSERT INTO device_account_aliases (device_account_key, user_id, source)
SELECT device_account_key, id, 'backfill_device_account_key'
  FROM users
 WHERE device_account_key IS NOT NULL
ON CONFLICT (device_account_key) DO NOTHING;

-- Algumas contas antigas mantem a chave somente em device_id.
INSERT INTO device_account_aliases (device_account_key, user_id, source)
SELECT lower(device_id), id, 'backfill_device_id'
  FROM users
 WHERE device_id ~ '^[A-Fa-f0-9]{64}$'
ON CONFLICT (device_account_key) DO NOTHING;
