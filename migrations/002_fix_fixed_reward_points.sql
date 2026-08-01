-- =============================================================================
-- Correcao: remove a pontuacao fixa de 500 pontos por anuncio premiado.
--
-- A pontuacao passa a ser sorteada pelo servidor com probabilidade ponderada
-- (ver src/utils/pointsRandom.js), reproduzindo a logica original do app:
--   70,0% -> [1, 1, 1, 2, 2, 4]
--   20,0% -> [8, 8, 12, 16]
--    8,0% -> [20, 30, 40, 60]
--    1,8% -> [80, 100, 200]
--    0,2% -> [300, 400]
-- =============================================================================

BEGIN;

-- 1. Remove a chave de configuracao que fixava a recompensa em 500 pontos.
DELETE FROM system_config WHERE key = 'reward_points_rewarded';

-- 2. Insere as novas chaves de configuracao.
INSERT INTO system_config (key, value) VALUES
  ('reward_points_multiplier', '1'),
  ('reward_point_values', '[1, 2, 4, 8, 12, 16, 20, 30, 40, 60, 80, 100, 200, 300, 400]')
ON CONFLICT (key) DO NOTHING;

-- 3. Atualiza a versao do app divulgada pela API.
UPDATE system_config SET value = '"1.3.2"', updated_at = NOW()
WHERE key = 'app_version';

-- 4. Remove os creditos indevidos de 500 pontos gerados pelo valor fixo.
--    Os eventos de recompensa correspondentes tambem sao removidos para manter
--    a integridade do historico.
DELETE FROM reward_events
WHERE points_awarded = 500 AND ad_type = 'rewarded';

DELETE FROM points_ledger
WHERE amount = 500 AND transaction_type = 'REWARD';

COMMIT;

-- Verificacao
SELECT key, value FROM system_config ORDER BY key;
SELECT amount, transaction_type, COUNT(*) FROM points_ledger
GROUP BY amount, transaction_type ORDER BY amount DESC;
