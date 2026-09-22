-- ============================================================================
-- 022 — Configuração única da recompensa dos níveis 30+
--
-- O painel mostra uma única linha "Level 30+ — 2000 pontos fixos". Ela controla
-- as missões concretas 30, 40, 50 e todos os próximos múltiplos de 10 exibidos
-- no aplicativo. Os níveis anteriores permanecem inalterados.
-- ============================================================================

INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order, verification_mode, requires_ad,
  min_seconds_before_claim, slug
)
SELECT
  'Level 30+ — 2000 pontos fixos',
  'Recompensa aplicada aos níveis 30, 40, 50 e a todos os próximos múltiplos de 10.',
  'level_30_plus_config',
  30,
  2000,
  'emoji_events',
  true,
  false,
  COALESCE((SELECT MAX(sort_order) + 1 FROM missions), 0),
  'auto',
  true,
  0,
  'level-30-plus-config'
WHERE NOT EXISTS (
  SELECT 1 FROM missions WHERE slug = 'level-30-plus-config'
);

-- Missões 30+ já existentes passam a usar o valor inicial da configuração.
-- A API lê a recompensa da linha de configuração em cada listagem/resgate,
-- então alterações futuras no painel valem para as metas 30, 40, 50...
UPDATE missions
   SET reward_points = 2000,
       slug = COALESCE(slug, 'level-30-plus-' || target_value::text),
       updated_at = NOW()
 WHERE type = 'reach_level'
   AND target_value >= 30;

COMMENT ON COLUMN missions.reward_points IS
  'Recompensa em pontos. Para type=reach_level com target_value>=30, o valor '
  'vigente é controlado pela missão type=level_30_plus_config.';
