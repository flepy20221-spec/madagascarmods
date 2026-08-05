-- CashPix 1.6.0 - conta unica por dispositivo
--
-- device_account_key recebe somente o SHA-256 do identificador Android com escopo
-- do aplicativo. O identificador bruto do sistema nao e armazenado no servidor.
-- Contas existentes permanecem validas e recebem a chave no primeiro acesso da
-- nova versao, usando o refresh token ou o device_id legado como prova de vinculo.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS device_account_key VARCHAR(64);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'users_device_account_key_format'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_device_account_key_format
      CHECK (
        device_account_key IS NULL
        OR device_account_key ~ '^[a-f0-9]{64}$'
      ) NOT VALID;
  END IF;
END
$$;

-- A restricao parcial permite a migracao gradual das contas antigas, mas impede
-- atomicamente que a mesma chave de aparelho seja vinculada a duas contas.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_account_key_unique
  ON users(device_account_key)
  WHERE device_account_key IS NOT NULL;

-- Fecha o mesmo desvio para clientes antigos que ainda usam device_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_id_unique
  ON users(device_id)
  WHERE device_id IS NOT NULL AND btrim(device_id) <> '';
