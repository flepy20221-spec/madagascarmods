-- ============================================================
-- MIGRAÇÃO 007: Modo Manutenção e Atualização Forçada
-- Adiciona configurações para controle remoto do app.
-- ============================================================

INSERT INTO system_config (key, value, updated_at) VALUES
  ('maintenance_mode', 'false', NOW()),
  ('maintenance_message', '"Estamos em manutenção. Voltaremos em breve!"', NOW()),
  ('min_supported_version', '"1.0.0"', NOW()),
  ('force_update_message', '"Uma nova versão do CashPix está disponível. Atualize para continuar usando o app."', NOW()),
  ('play_store_url', '"https://play.google.com/store/apps/details?id=com.madagascarmods"', NOW())
ON CONFLICT (key) DO NOTHING;
