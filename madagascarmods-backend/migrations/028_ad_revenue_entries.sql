-- Receita informada pelo administrador para calcular margem por dia.
-- Não altera saldo nem pagamentos; é um registro analítico separado.
CREATE TABLE IF NOT EXISTS ad_revenue_entries (
  id UUID PRIMARY KEY,
  report_date DATE NOT NULL,
  source VARCHAR(32) NOT NULL,
  revenue_brl NUMERIC(12,2) NOT NULL CHECK (revenue_brl >= 0),
  notes TEXT,
  created_by VARCHAR(180),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (report_date, source)
);
CREATE INDEX IF NOT EXISTS idx_ad_revenue_entries_date ON ad_revenue_entries (report_date DESC);
