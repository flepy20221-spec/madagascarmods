-- ============================================================================
-- 020 — Missões externas e progressão ilimitada de níveis
--
-- Missões externas são autodeclaradas: o servidor registra a abertura do
-- destino, aguarda o intervalo mínimo e libera um único resgate. A API não
-- afirma que a Play Store instalou um app nem que o Instagram confirmou um
-- follow, pois essas plataformas não fornecem essa confirmação ao CashPix.
-- ============================================================================

-- YoungMoney é o primeiro app parceiro com URL conhecida. MachinePix e
-- Instagram ficam disponíveis para criação/edição no painel assim que os links
-- oficiais forem informados.
INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order, verification_mode, action_url,
  requires_ad, cooldown_days, min_seconds_before_claim
)
SELECT
  'Baixe o YoungMoney',
  'Abra a Play Store, instale o YoungMoney e aguarde 30 segundos para liberar a recompensa.',
  'app_download',
  1,
  100,
  'download',
  true,
  false,
  COALESCE((SELECT MAX(sort_order) + 1 FROM missions), 0),
  'self_declared',
  'https://play.google.com/store/apps/details?id=com.youngmoney2',
  false,
  NULL,
  30
WHERE NOT EXISTS (
  SELECT 1 FROM missions
   WHERE type = 'app_download'
     AND action_url = 'https://play.google.com/store/apps/details?id=com.youngmoney2'
);

-- Placeholder inativo para o MachinePix. O administrador adiciona o link
-- oficial no campo de ação e ativa a missão quando o aplicativo estiver na loja.
INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order, verification_mode, action_url,
  requires_ad, cooldown_days, min_seconds_before_claim
)
SELECT
  'Baixe o MachinePix',
  'O link será configurado pelo administrador quando o MachinePix estiver disponível.',
  'app_download',
  1,
  100,
  'download',
  false,
  false,
  COALESCE((SELECT MAX(sort_order) + 1 FROM missions), 0),
  'self_declared',
  NULL,
  false,
  NULL,
  30
WHERE NOT EXISTS (
  SELECT 1 FROM missions
   WHERE type = 'app_download' AND title = 'Baixe o MachinePix'
);

COMMENT ON COLUMN missions.type IS
  'watch_ads, checkin, referral, reach_level, app_review, app_download, '
  'instagram_follow, manus_proof ou custom';
