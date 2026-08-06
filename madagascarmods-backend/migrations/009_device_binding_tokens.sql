-- ============================================================================
-- 009 — Token de vinculo de dispositivo
--
-- Problema que esta migracao resolve
-- ----------------------------------
-- A prova de posse aceita ate agora pela rota /auth/device eram o
-- `migration_refresh_token` e o `legacy_device_id`. Ambos sao frageis:
--
--   * o refresh token e rotacionado a cada login e sobrescrito em
--     `users.refresh_token`, portanto o valor guardado no aparelho fica invalido
--     assim que outra sessao renova o token;
--   * o `legacy_device_id` so existe em instalacoes que vieram da versao 1.6.0.
--
-- Consequencia observada em producao: apos a troca da chave de assinatura do
-- APK, o ANDROID_ID do mesmo aparelho mudou, nenhuma das duas provas estava
-- disponivel, e o servidor criou uma conta nova com saldo zero.
--
-- Solucao
-- -------
-- Um token de vinculo dedicado, de longa duracao, emitido no primeiro acesso e
-- reapresentado em cada bootstrap. Nao participa do ciclo de sessao e por isso
-- sobrevive a rotacoes de access/refresh token.
--
-- Decisoes de seguranca
-- ---------------------
--   * SOMENTE o SHA-256 do token e persistido. Um vazamento do banco nao permite
--     reassociar dispositivos, do mesmo modo que um hash de senha nao permite
--     autenticar.
--   * O hash e unico: um token nunca vale para duas contas.
--   * `device_binding_token_issued_at` permite expirar ou rotacionar tokens no
--     futuro sem outra migracao.
--
-- Esta migracao e puramente aditiva. Nenhuma conta, saldo, alias ou codigo de
-- suporte existente e alterado.
-- ============================================================================

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS device_binding_token_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS device_binding_token_issued_at TIMESTAMP WITH TIME ZONE;

-- Um hash de token de vinculo nunca pode apontar para duas contas. O indice
-- parcial ignora as linhas sem token, que sao a maioria imediatamente apos a
-- migracao.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_binding_token_hash
  ON users(device_binding_token_hash)
  WHERE device_binding_token_hash IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'users_device_binding_token_hash_format'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_device_binding_token_hash_format
      CHECK (
        device_binding_token_hash IS NULL
        OR device_binding_token_hash ~ '^[a-f0-9]{64}$'
      ) NOT VALID;
  END IF;
END
$$;

-- Origem do alias registrada quando a reassociacao acontece pelo token de
-- vinculo. Documenta a coluna existente; nao ha alteracao de tipo.
COMMENT ON COLUMN users.device_binding_token_hash IS
  'SHA-256 do token de vinculo do dispositivo. Prova de posse independente do ciclo de sessao.';
COMMENT ON COLUMN users.device_binding_token_issued_at IS
  'Momento da emissao do token de vinculo vigente.';
