-- ============================================================================
-- 015 — Missao Manus com comprovacao manual por captura de tela
--
-- A API publica do Manus nao informa ao CashPix quem concluiu o login pelo link
-- de convite. Esta migracao cria um fluxo auditavel: o usuario envia evidencia,
-- um administrador decide e somente a aprovacao completa a missao. A imagem
-- permanece no PostgreSQL e nunca recebe URL publica.
-- ============================================================================

ALTER TABLE missions
  ADD COLUMN IF NOT EXISTS slug VARCHAR(80),
  ADD COLUMN IF NOT EXISTS evidence_required BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS minimum_external_credits INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS instructions JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE UNIQUE INDEX IF NOT EXISTS idx_missions_slug_unique
  ON missions(slug)
  WHERE slug IS NOT NULL;

ALTER TABLE missions
  DROP CONSTRAINT IF EXISTS missions_verification_mode_valid;

ALTER TABLE missions
  ADD CONSTRAINT missions_verification_mode_valid
  CHECK (verification_mode IN ('auto', 'self_declared', 'manual_evidence'));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'missions_minimum_external_credits_nonnegative'
       AND conrelid = 'missions'::regclass
  ) THEN
    ALTER TABLE missions
      ADD CONSTRAINT missions_minimum_external_credits_nonnegative
      CHECK (minimum_external_credits >= 0);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS mission_evidence_submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  public_protocol VARCHAR(32) NOT NULL UNIQUE,
  mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  evidence_data BYTEA NOT NULL,
  evidence_sha256 CHAR(64) NOT NULL,
  evidence_mime VARCHAR(40) NOT NULL,
  evidence_size INTEGER NOT NULL,
  original_filename VARCHAR(255),
  attestation_accepted BOOLEAN NOT NULL DEFAULT false,
  submitted_ip VARCHAR(45),
  reviewer_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
  rejection_reason TEXT,
  submitted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT mission_evidence_status_valid
    CHECK (status IN ('pending', 'approved', 'rejected')),
  CONSTRAINT mission_evidence_size_valid
    CHECK (evidence_size > 0 AND evidence_size <= 8388608),
  CONSTRAINT mission_evidence_hash_format
    CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mission_evidence_hash_unique
  ON mission_evidence_submissions(evidence_sha256);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mission_evidence_one_open_per_user
  ON mission_evidence_submissions(user_id, mission_id)
  WHERE status IN ('pending', 'approved');

CREATE INDEX IF NOT EXISTS idx_mission_evidence_review_queue
  ON mission_evidence_submissions(mission_id, status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_mission_evidence_user_history
  ON mission_evidence_submissions(user_id, mission_id, submitted_at DESC);

COMMENT ON TABLE mission_evidence_submissions IS
  'Capturas privadas enviadas para comprovacao manual de missoes externas.';
COMMENT ON COLUMN mission_evidence_submissions.evidence_data IS
  'Imagem binaria privada. Disponivel somente em rota administrativa autenticada.';
COMMENT ON COLUMN mission_evidence_submissions.evidence_sha256 IS
  'SHA-256 unico para bloquear reutilizacao byte a byte da mesma captura.';

-- Criada inativa: o administrador revisa o portal e ativa depois do deploy.
INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order,
  verification_mode, action_url, requires_ad, cooldown_days,
  min_seconds_before_claim, slug, evidence_required,
  minimum_external_credits, instructions
)
SELECT
  'Cadastre-se no Manus',
  'Entre no Manus pelo convite, envie uma captura da conta com 1.800 creditos e aguarde a aprovacao.',
  'manus_proof',
  1,
  500,
  'verified_user',
  false,
  false,
  COALESCE((SELECT MAX(sort_order) + 1 FROM missions), 0),
  'manual_evidence',
  'https://cashpix-manus-proof-production.up.railway.app/',
  false,
  NULL,
  0,
  'manus-account-proof',
  true,
  1800,
  jsonb_build_object(
    'title', 'Como concluir esta missao',
    'steps', jsonb_build_array(
      'Abra o site da missao e toque em Abrir Manus.',
      'Entre ou crie uma conta pelo convite.',
      'Tire uma captura com a conta conectada e pelo menos 1.800 creditos.',
      'Volte ao portal, envie a imagem e aguarde a aprovacao.',
      'Depois de aprovada, volte ao CashPix e resgate 500 pontos.'
    )
  )
WHERE NOT EXISTS (
  SELECT 1 FROM missions
   WHERE slug = 'manus-account-proof' OR type = 'manus_proof'
);
