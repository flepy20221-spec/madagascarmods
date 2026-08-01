-- ============================================================
-- CashPix v1.5.0 - Migration Script
-- Adiciona suporte a PIX, ban de usuários e edição de dados
-- ============================================================

-- 1. Tabela de contas PIX (separada de payout_destinations para clareza)
CREATE TABLE IF NOT EXISTS pix_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  cpf VARCHAR(14) NOT NULL,
  cpf_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  pix_key_type VARCHAR(20) NOT NULL CHECK (pix_key_type IN ('cpf', 'email')),
  pix_key_value TEXT NOT NULL,
  pix_key_masked VARCHAR(255) NOT NULL,
  status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED')),
  is_active BOOLEAN DEFAULT true,
  submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  reviewed_at TIMESTAMP WITH TIME ZONE,
  reviewed_by UUID,
  rejection_reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índice único para CPF (1 conta por CPF)
CREATE UNIQUE INDEX IF NOT EXISTS idx_pix_accounts_cpf_hash_active 
  ON pix_accounts(cpf_hash) WHERE is_active = true AND status IN ('PENDING', 'APPROVED');

CREATE INDEX IF NOT EXISTS idx_pix_accounts_user_id ON pix_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_pix_accounts_status ON pix_accounts(status);

-- 2. Adicionar campo ban_reason na tabela users
ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_by UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS fraud_score INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_fraud_at TIMESTAMP WITH TIME ZONE;

-- 3. Atualizar métodos de saque para incluir PIX
UPDATE system_config SET value = '["faucetpay", "pix"]', updated_at = NOW() WHERE key = 'withdrawal_methods';

-- 4. Configuração de saque PIX
INSERT INTO system_config (key, value, updated_at) VALUES ('pix_withdrawal_enabled', 'true', NOW())
ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = NOW();

-- 5. Adicionar coluna ssv_transaction_id na tabela reward_events para anti-replay
ALTER TABLE reward_events ADD COLUMN IF NOT EXISTS ssv_transaction_id VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_events_ssv_tx ON reward_events(ssv_transaction_id) WHERE ssv_transaction_id IS NOT NULL;

-- Verificação
SELECT key, value FROM system_config WHERE key IN (
  'withdrawal_methods', 'pix_withdrawal_enabled'
) ORDER BY key;
