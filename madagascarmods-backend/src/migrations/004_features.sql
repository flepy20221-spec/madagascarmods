-- ============================================================
-- MIGRAÇÃO 004: Check-in Diário, Referral, Push, Missões
-- ============================================================

-- ============ CHECK-IN DIÁRIO ============
CREATE TABLE IF NOT EXISTS daily_checkins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  checkin_date DATE NOT NULL DEFAULT CURRENT_DATE,
  streak_day INT NOT NULL DEFAULT 1,
  points_awarded INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, checkin_date)
);

CREATE INDEX IF NOT EXISTS idx_checkins_user_date ON daily_checkins(user_id, checkin_date DESC);

-- ============ SISTEMA DE REFERRAL ============
-- Adicionar código de referral ao usuário
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(10) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by UUID REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_count INT DEFAULT 0;

CREATE TABLE IF NOT EXISTS referral_rewards (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  referrer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  referred_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reward_type VARCHAR(20) NOT NULL DEFAULT 'signup', -- signup, milestone
  points_awarded INT NOT NULL DEFAULT 0,
  milestone_name VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(referrer_id, referred_id, reward_type, milestone_name)
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referral_rewards(referrer_id);

-- ============ PUSH NOTIFICATIONS ============
-- Tokens FCM dos dispositivos
CREATE TABLE IF NOT EXISTS push_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
  platform VARCHAR(10) DEFAULT 'android', -- android, ios
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, token)
);

CREATE INDEX IF NOT EXISTS idx_push_tokens_active ON push_tokens(is_active) WHERE is_active = true;

-- Histórico de notificações enviadas pelo admin
CREATE TABLE IF NOT EXISTS push_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(100) NOT NULL,
  body TEXT NOT NULL,
  image_url TEXT,
  target_type VARCHAR(20) NOT NULL DEFAULT 'all', -- all, specific, segment
  target_users UUID[] DEFAULT '{}',
  sent_count INT DEFAULT 0,
  success_count INT DEFAULT 0,
  failure_count INT DEFAULT 0,
  sent_by UUID,
  created_at TIMESTAMP DEFAULT NOW()
);

-- ============ MISSÕES/TAREFAS DIÁRIAS ============
-- Definição das missões (gerenciadas pelo admin)
CREATE TABLE IF NOT EXISTS missions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(100) NOT NULL,
  description TEXT,
  type VARCHAR(30) NOT NULL, -- watch_ads, checkin, referral, reach_level, custom
  target_value INT NOT NULL DEFAULT 1, -- ex: assistir 10 anúncios
  reward_points INT NOT NULL DEFAULT 50,
  icon VARCHAR(50) DEFAULT 'star',
  is_active BOOLEAN DEFAULT true,
  is_daily BOOLEAN DEFAULT true, -- reseta todo dia ou é permanente
  sort_order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Progresso do usuário nas missões
CREATE TABLE IF NOT EXISTS mission_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  current_value INT DEFAULT 0,
  is_completed BOOLEAN DEFAULT false,
  is_claimed BOOLEAN DEFAULT false, -- se já resgatou a recompensa
  completed_at TIMESTAMP,
  claimed_at TIMESTAMP,
  reset_date DATE DEFAULT CURRENT_DATE, -- para missões diárias
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, mission_id, reset_date)
);

CREATE INDEX IF NOT EXISTS idx_mission_progress_user ON mission_progress(user_id, reset_date);

-- ============ CONFIGURAÇÕES PADRÃO ============
INSERT INTO system_config (key, value, updated_at) VALUES
  ('checkin_base_points', '10', NOW()),
  ('checkin_streak_multiplier', '5', NOW()),
  ('checkin_max_streak_bonus', '100', NOW()),
  ('referral_signup_bonus_referrer', '200', NOW()),
  ('referral_signup_bonus_referred', '100', NOW()),
  ('referral_milestone_50ads', '500', NOW())
ON CONFLICT (key) DO NOTHING;

-- Missões padrão
INSERT INTO missions (title, description, type, target_value, reward_points, icon, is_active, is_daily, sort_order) VALUES
  ('Assistir 5 anúncios', 'Assista 5 anúncios rewarded hoje', 'watch_ads', 5, 30, 'play_circle', true, true, 1),
  ('Assistir 15 anúncios', 'Assista 15 anúncios rewarded hoje', 'watch_ads', 15, 80, 'play_circle', true, true, 2),
  ('Assistir 30 anúncios', 'Assista 30 anúncios rewarded hoje', 'watch_ads', 30, 200, 'local_fire_department', true, true, 3),
  ('Check-in diário', 'Faça seu check-in de hoje', 'checkin', 1, 20, 'calendar_today', true, true, 4),
  ('Convidar 1 amigo', 'Convide um amigo para o CashPix', 'referral', 1, 300, 'person_add', true, false, 5),
  ('Alcançar nível 3', 'Chegue ao nível 3 assistindo anúncios', 'reach_level', 3, 500, 'emoji_events', true, false, 6)
ON CONFLICT DO NOTHING;
