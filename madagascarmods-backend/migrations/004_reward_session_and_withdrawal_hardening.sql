-- ============================================================================
-- Migracao 004 — Correlacao SSV por sessao e reforco de saque
--
-- Permite que o aplicativo consulte somente a recompensa referente ao anuncio
-- que acabou de assistir, sem consumir um evento antigo nem depender de polling
-- generico. A coluna e opcional para manter compatibilidade com APKs anteriores,
-- cujo custom_data continha apenas o UUID do usuario.
-- ============================================================================

ALTER TABLE reward_events
  ADD COLUMN IF NOT EXISTS reward_session_id UUID;

-- Uma sessao de anuncio pode produzir no maximo um credito, mesmo sob callbacks
-- duplicados ou concorrentes. O filtro preserva eventos antigos sem sessao.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_events_session_unique
  ON reward_events(reward_session_id)
  WHERE reward_session_id IS NOT NULL;

-- Consulta do endpoint /points/reward-status/:sessionId sempre inclui o usuario.
CREATE INDEX IF NOT EXISTS idx_reward_events_user_session
  ON reward_events(user_id, reward_session_id)
  WHERE reward_session_id IS NOT NULL;

-- Idempotency keys vazias sao equivalentes a ausentes e nunca devem ser aceitas.
-- A aplicacao valida UUID estrito; esta constraint protege gravacoes futuras feitas
-- fora do fluxo HTTP sem invalidar registros historicos legados.
ALTER TABLE withdrawals
  DROP CONSTRAINT IF EXISTS withdrawals_idempotency_key_not_blank;

ALTER TABLE withdrawals
  ADD CONSTRAINT withdrawals_idempotency_key_not_blank
  CHECK (idempotency_key IS NULL OR btrim(idempotency_key) <> '') NOT VALID;
