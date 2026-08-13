-- Tabela de log das limpezas automaticas de tokens push mortos
CREATE TABLE IF NOT EXISTS push_token_cleanup_log (
  id SERIAL PRIMARY KEY,
  scanned INTEGER NOT NULL DEFAULT 0,
  deactivated INTEGER NOT NULL DEFAULT 0,
  still_valid INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_push_cleanup_log_created_at
  ON push_token_cleanup_log (created_at DESC);
