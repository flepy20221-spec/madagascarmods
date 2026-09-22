-- ============================================================================
-- 023 — Override de nível para contas de teste
--
-- Permite elevar contas de teste sem fabricar centenas de eventos de anúncio ou
-- alterar o saldo. Quando NULL, o nível continua sendo calculado normalmente.
-- ============================================================================

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS level_override INTEGER;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'users_level_override_nonnegative'
       AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_level_override_nonnegative
      CHECK (level_override IS NULL OR level_override >= 0);
  END IF;
END
$$;
