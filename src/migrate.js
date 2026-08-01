require('dotenv').config();
const db = require('./models/db');

const migrations = `
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  token VARCHAR(512),
  refresh_token VARCHAR(512),
  device_id VARCHAR(255),
  device_model VARCHAR(255),
  ip_address VARCHAR(45),
  app_version VARCHAR(20),
  is_active BOOLEAN DEFAULT true,
  is_banned BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_login_at TIMESTAMP WITH TIME ZONE
);

-- Points ledger (append-only)
CREATE TABLE IF NOT EXISTS points_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  amount BIGINT NOT NULL,
  transaction_type VARCHAR(50) NOT NULL,
  reference_id UUID,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_points_ledger_user_id ON points_ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_points_ledger_created_at ON points_ledger(created_at);

-- Payout destinations (FaucetPay emails)
CREATE TABLE IF NOT EXISTS payout_destinations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  type VARCHAR(50) DEFAULT 'FAUCETPAY_EMAIL',
  value_encrypted TEXT NOT NULL,
  value_masked VARCHAR(255) NOT NULL,
  value_hash VARCHAR(255) NOT NULL,
  status VARCHAR(20) DEFAULT 'PENDING',
  version INTEGER DEFAULT 1,
  is_active BOOLEAN DEFAULT true,
  submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  reviewed_at TIMESTAMP WITH TIME ZONE,
  reviewed_by UUID,
  rejection_reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payout_dest_user_id ON payout_destinations(user_id);
CREATE INDEX IF NOT EXISTS idx_payout_dest_status ON payout_destinations(status);

-- Withdrawals
CREATE TABLE IF NOT EXISTS withdrawals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  payout_destination_id UUID REFERENCES payout_destinations(id),
  amount DECIMAL(12,2) NOT NULL,
  points_debited BIGINT NOT NULL,
  payment_method VARCHAR(50) DEFAULT 'faucetpay',
  crypto_address TEXT,
  crypto_amount DECIMAL(18,8),
  crypto_currency VARCHAR(10) DEFAULT 'LTC',
  exchange_rate DECIMAL(18,8),
  status VARCHAR(20) DEFAULT 'PENDING',
  idempotency_key VARCHAR(255) UNIQUE,
  ledger_reservation_id UUID REFERENCES points_ledger(id),
  tx_hash VARCHAR(255),
  gateway_response JSONB,
  receipt_url TEXT,
  processed_at TIMESTAMP WITH TIME ZONE,
  approved_by UUID,
  approved_at TIMESTAMP WITH TIME ZONE,
  rejection_reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id ON withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);
CREATE INDEX IF NOT EXISTS idx_withdrawals_created_at ON withdrawals(created_at);

-- Reward events (ad impressions validated)
CREATE TABLE IF NOT EXISTS reward_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  ad_type VARCHAR(50) NOT NULL,
  ad_network VARCHAR(50) DEFAULT 'admob',
  ad_unit_id VARCHAR(255),
  points_awarded BIGINT NOT NULL,
  ssv_token VARCHAR(512),
  ssv_verified BOOLEAN DEFAULT false,
  device_id VARCHAR(255),
  ip_address VARCHAR(45),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reward_events_user_id ON reward_events(user_id);

-- Admin users
CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  role VARCHAR(50) DEFAULT 'admin',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID,
  actor_type VARCHAR(20),
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(50),
  target_id UUID,
  old_value JSONB,
  new_value JSONB,
  ip_address VARCHAR(45),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- System config
CREATE TABLE IF NOT EXISTS system_config (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default config
INSERT INTO system_config (key, value) VALUES
  ('withdrawal_min_points', '2000'),
  ('points_per_real', '2000'),
  ('withdrawal_min_amount', '1.00'),
  ('withdrawal_max_amount', '1000.00'),
  ('withdrawal_methods', '["faucetpay"]'),
  ('withdrawal_crypto_currency', '"LTC"'),
  ('quick_values', '[1, 2, 5, 10, 20, 50]'),
  ('daily_ad_limit_rewarded', '50'),
  ('daily_ad_limit_other', '30'),
  ('reward_points_multiplier', '1'),
  ('reward_point_values', '[1, 2, 4, 8, 12, 16, 20, 30, 40, 60, 80, 100, 200, 300, 400]'),
  ('reward_points_interstitial', '0'),
  ('reward_points_banner', '0'),
  ('app_version', '"1.3.2"')
ON CONFLICT (key) DO NOTHING;

-- Remove a configuracao antiga de valor fixo por anuncio premiado.
-- A pontuacao agora e sorteada pelo servidor com probabilidade ponderada
-- (ver src/utils/pointsRandom.js), reproduzindo a logica original do app.
DELETE FROM system_config WHERE key = 'reward_points_rewarded';
`;

async function runMigrations() {
  try {
    console.log('Running migrations...');
    await db.query(migrations);
    console.log('Migrations completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

runMigrations();
