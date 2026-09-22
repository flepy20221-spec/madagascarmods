-- ============================================================================
-- 021 — Missões de nível em múltiplos de 10
--
-- O painel precisa enxergar as primeiras metas para que o administrador possa
-- definir suas recompensas. A progressão continua ilimitada: quando o usuário
-- alcançar uma faixa ainda não cadastrada, a API cria a próxima sob demanda.
-- ============================================================================

-- Missões antigas fora do novo intervalo (por exemplo, nível 3) deixam de ser
-- exibidas. O histórico de resgates permanece preservado no banco.
UPDATE missions
   SET is_active = false,
       updated_at = NOW()
 WHERE type = 'reach_level'
   AND target_value % 10 <> 0;

INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order, verification_mode, requires_ad,
  min_seconds_before_claim
)
SELECT
  'Alcançar nível ' || level_value,
  'Chegue ao nível ' || level_value || ' assistindo anúncios',
  'reach_level',
  level_value,
  100,
  'emoji_events',
  true,
  false,
  COALESCE((SELECT MAX(sort_order) + 1 FROM missions), 0),
  'auto',
  true,
  0
FROM (VALUES (10), (20), (30)) AS seed(level_value)
WHERE NOT EXISTS (
  SELECT 1 FROM missions m
   WHERE m.type = 'reach_level'
     AND m.target_value = seed.level_value
);
