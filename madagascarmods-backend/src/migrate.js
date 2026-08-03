require('dotenv').config();
const fs = require('fs');
const path = require('path');
const db = require('./models/db');

// ============================================================================
// Bootstrap do schema base.
//
// Executado sempre, de forma idempotente (CREATE TABLE IF NOT EXISTS). Define o
// estado minimo do banco sobre o qual as migracoes versionadas em migrations/
// sao aplicadas em seguida.
// ============================================================================
const baseSchema = `
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

// ============================================================================
// Controle de versao das migracoes.
//
// Antes desta correcao o script aplicava apenas o schema base acima e ignorava
// por completo a pasta migrations/. Como consequencia, as colunas
// reward_events.ssv_transaction_id (migracao 003) e
// reward_events.reward_session_id (migracao 004) nunca chegavam ao banco de
// producao. A rota SSV (src/routes/ssv.js) faz INSERT nessas colunas: o
// PostgreSQL respondia 42703 undefined_column, a transacao sofria ROLLBACK e o
// usuario nunca recebia os pontos do anuncio que assistiu.
//
// O runner abaixo aplica cada arquivo .sql de migrations/ em ordem
// lexicografica, uma unica vez, registrando o que foi aplicado em
// schema_migrations.
// ============================================================================
const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');

// A migracao 002 remove reward_events e points_ledger cujo valor seja 500.
// Isso fazia sentido apenas no momento historico em que a recompensa fixa de
// 500 pontos foi substituida pelo sorteio ponderado. Aplicada hoje, destruiria
// creditos legitimos de 500 pontos sorteados e o saldo de usuarios reais. O
// efeito util dela (chaves de system_config e remocao de
// reward_points_rewarded) ja faz parte do schema base acima, portanto ela e
// registrada como aplicada sem ser executada.
const BASELINE_ONLY = new Set(['002_fix_fixed_reward_points.sql']);

const SCHEMA_MIGRATIONS_TABLE = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename    VARCHAR(255) PRIMARY KEY,
  applied_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  skipped     BOOLEAN DEFAULT false
);
`;

function listMigrationFiles() {
  if (!fs.existsSync(MIGRATIONS_DIR)) {
    console.warn(`[migrate] Migrations directory not found: ${MIGRATIONS_DIR}`);
    return [];
  }

  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith('.sql'))
    .sort();
}

async function appliedMigrations() {
  const result = await db.query('SELECT filename FROM schema_migrations');
  return new Set(result.rows.map((row) => row.filename));
}

// Arquivos escritos para execucao manual no psql podem conter BEGIN/COMMIT
// explicitos. O runner ja envolve cada arquivo em sua propria transacao, e um
// COMMIT no meio encerraria essa transacao antes do tempo, deixando o restante
// do arquivo fora do controle de atomicidade.
function stripExplicitTransactionControl(sql) {
  return sql
    .split('\n')
    .filter((line) => !/^\s*(BEGIN|COMMIT|END)\s*;\s*$/i.test(line))
    .join('\n');
}

async function applyMigration(filename) {
  const fullPath = path.join(MIGRATIONS_DIR, filename);
  const sql = stripExplicitTransactionControl(fs.readFileSync(fullPath, 'utf8'));

  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query(
      'INSERT INTO schema_migrations (filename, skipped) VALUES ($1, false) ' +
      'ON CONFLICT (filename) DO NOTHING',
      [filename]
    );
    await client.query('COMMIT');
    console.log(`[migrate] Applied ${filename}`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw new Error(`Migration ${filename} failed: ${error.message}`);
  } finally {
    client.release();
  }
}

async function markBaseline(filename) {
  await db.query(
    'INSERT INTO schema_migrations (filename, skipped) VALUES ($1, true) ' +
    'ON CONFLICT (filename) DO NOTHING',
    [filename]
  );
  console.log(`[migrate] Baseline, not executed: ${filename}`);
}

// Verificacao final de sanidade: as colunas exigidas pela rota SSV precisam
// existir, caso contrario o credito de pontos volta a falhar em producao.
async function assertSsvSchema() {
  const result = await db.query(
    `SELECT column_name
       FROM information_schema.columns
      WHERE table_name = 'reward_events'
        AND column_name IN ('ssv_transaction_id', 'reward_session_id')`
  );

  const present = new Set(result.rows.map((row) => row.column_name));
  const missing = ['ssv_transaction_id', 'reward_session_id']
    .filter((column) => !present.has(column));

  if (missing.length > 0) {
    throw new Error(
      `reward_events is missing required SSV columns: ${missing.join(', ')}`
    );
  }

  console.log('[migrate] SSV schema verified: ssv_transaction_id, reward_session_id');
}

async function runMigrations() {
  try {
    console.log('[migrate] Applying base schema...');
    await db.query(baseSchema);

    await db.query(SCHEMA_MIGRATIONS_TABLE);

    const files = listMigrationFiles();
    const already = await appliedMigrations();

    for (const filename of files) {
      if (already.has(filename)) {
        console.log(`[migrate] Already applied, skipping: ${filename}`);
        continue;
      }

      if (BASELINE_ONLY.has(filename)) {
        await markBaseline(filename);
        continue;
      }

      await applyMigration(filename);
    }

    await assertSsvSchema();

    console.log('[migrate] Migrations completed successfully.');
    process.exit(0);
  } catch (error) {
    // Falhas de conexao do driver pg chegam com message vazia. Sem o code e o
    // stack o log do Railway nao diz nada util sobre por que o deploy caiu.
    const detail = error.message || error.code || 'unknown error';
    console.error(`[migrate] Migration failed: ${detail}`);
    if (error.code) console.error(`[migrate] SQLSTATE/errno: ${error.code}`);
    if (error.stack) console.error(error.stack);
    process.exit(1);
  }
}

runMigrations();
