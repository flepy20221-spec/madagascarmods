-- Telemetria técnica para saber qual fonte de mediação carregou o anúncio.
-- Não participa de saldo, recompensas ou SSV; eventos do cliente são apenas analíticos.
CREATE TABLE IF NOT EXISTS ad_observations (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type VARCHAR(24) NOT NULL,
  ad_format VARCHAR(24) NOT NULL,
  adapter VARCHAR(180),
  ad_unit_id VARCHAR(180),
  app_version VARCHAR(32),
  error_code VARCHAR(64),
  error_message TEXT,
  value_micros BIGINT,
  currency VARCHAR(8),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ad_observations_created ON ad_observations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ad_observations_adapter_created ON ad_observations (adapter, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ad_observations_user_created ON ad_observations (user_id, created_at DESC);
