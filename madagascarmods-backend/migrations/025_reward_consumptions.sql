-- Consumo único de anúncios rewarded para bônus que dependem de anúncio.
-- A recompensa base do SSV continua em reward_events; esta tabela impede que
-- o mesmo anúncio confirmado seja reutilizado em check-in, indicação ou missão.
CREATE TABLE IF NOT EXISTS reward_consumptions (
  id UUID PRIMARY KEY,
  reward_event_id UUID NOT NULL REFERENCES reward_events(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose VARCHAR(80) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (reward_event_id),
  UNIQUE (user_id, purpose, reward_event_id)
);

CREATE INDEX IF NOT EXISTS idx_reward_consumptions_user_created
  ON reward_consumptions (user_id, created_at DESC);
