-- ============================================================
-- CashPix v1.4.0 - Migration Script
-- Atualiza configurações existentes no banco de produção
-- ============================================================

-- 1. Atualizar valor mínimo de saque: 2000 pontos = R$ 1,00
UPDATE system_config SET value = '2000', updated_at = NOW() WHERE key = 'withdrawal_min_points';
UPDATE system_config SET value = '2000', updated_at = NOW() WHERE key = 'points_per_real';

-- 2. Definir moeda como LTC
INSERT INTO system_config (key, value, updated_at) VALUES ('withdrawal_crypto_currency', '"LTC"', NOW())
ON CONFLICT (key) DO UPDATE SET value = '"LTC"', updated_at = NOW();

-- 3. Métodos de saque: apenas FaucetPay
UPDATE system_config SET value = '["faucetpay"]', updated_at = NOW() WHERE key = 'withdrawal_methods';

-- 4. Limites diários de anúncios
INSERT INTO system_config (key, value, updated_at) VALUES ('daily_ad_limit_rewarded', '50', NOW())
ON CONFLICT (key) DO UPDATE SET value = '50', updated_at = NOW();

INSERT INTO system_config (key, value, updated_at) VALUES ('daily_ad_limit_other', '30', NOW())
ON CONFLICT (key) DO UPDATE SET value = '30', updated_at = NOW();

-- 5. Alterar default da coluna crypto_currency na tabela withdrawals
ALTER TABLE withdrawals ALTER COLUMN crypto_currency SET DEFAULT 'LTC';

-- Verificação
SELECT key, value FROM system_config WHERE key IN (
  'withdrawal_min_points', 'points_per_real', 'withdrawal_crypto_currency',
  'withdrawal_methods', 'daily_ad_limit_rewarded', 'daily_ad_limit_other'
) ORDER BY key;
