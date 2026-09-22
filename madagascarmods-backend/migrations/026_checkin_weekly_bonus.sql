-- Bônus configurável para sequência semanal de check-in.
-- O painel pode alterar o valor sem novo APK.
INSERT INTO system_config (key, value, updated_at)
VALUES
  ('checkin_weekly_bonus_points', '100', NOW()),
  ('reward_ssv_required_for_bonus', 'false', NOW())
ON CONFLICT (key) DO NOTHING;
