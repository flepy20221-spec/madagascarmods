-- ============================================================
-- MIGRAÇÃO 006: Tabela de Notificações Agendadas
-- Cria a tabela scheduled_notifications usada pelo scheduler
-- de push notifications automáticas.
-- ============================================================

CREATE TABLE IF NOT EXISTS scheduled_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(100) NOT NULL,
  body TEXT NOT NULL,
  image_url TEXT,
  target_type VARCHAR(20) NOT NULL DEFAULT 'all',
  schedule_time TIME NOT NULL,
  days_of_week INTEGER[] NOT NULL DEFAULT '{0,1,2,3,4,5,6}',
  is_active BOOLEAN DEFAULT true,
  last_sent_at TIMESTAMP WITH TIME ZONE,
  total_sent INTEGER DEFAULT 0,
  created_by UUID,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scheduled_notifications_active 
  ON scheduled_notifications(is_active, schedule_time) 
  WHERE is_active = true;
