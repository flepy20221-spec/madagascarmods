-- ============================================================================
-- Migracao 003 — Blindagem de seguranca
--
-- Aplica as estruturas de banco exigidas pelas correcoes de seguranca.
-- Idempotente: pode ser executada mais de uma vez sem efeito colateral.
--
-- Executar ANTES de subir a nova versao do backend, porque o middleware
-- antifraude depende da tabela request_nonces para o controle anti-replay.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. request_nonces — anti-replay das requisicoes assinadas (VULN-02)
--
-- O controle de nonce anterior vivia em memoria (Map), o que falha em dois
-- cenarios: reinicio do processo (o Railway reinicia a cada deploy) e mais de
-- uma instancia rodando (cada uma com seu proprio Map). Em ambos, um atacante
-- consegue reenviar a mesma requisicao assinada capturada com o HTTPCanary.
--
-- A PRIMARY KEY faz o trabalho de deduplicacao: o INSERT ... ON CONFLICT
-- DO NOTHING RETURNING devolve linha somente na primeira vez que o nonce
-- aparece. E atomico, sobrevive a reinicio e funciona com varias instancias.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_nonces (
  nonce      VARCHAR(128) PRIMARY KEY,
  user_id    UUID,
  path       VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indice para a limpeza periodica dos nonces vencidos.
CREATE INDEX IF NOT EXISTS idx_request_nonces_created_at
  ON request_nonces(created_at);

-- ----------------------------------------------------------------------------
-- 2. reward_events.ssv_transaction_id — impede reuso de comprovante (VULN-01)
--
-- Cada anuncio premiado validado pelo Google possui um transaction_id unico.
-- Sem uma restricao de unicidade, o mesmo comprovante valido pode ser reenviado
-- indefinidamente para creditar pontos repetidos. O indice UNIQUE transforma a
-- tentativa de reuso em erro de banco, mesmo sob requisicoes concorrentes.
-- ----------------------------------------------------------------------------
ALTER TABLE reward_events
  ADD COLUMN IF NOT EXISTS ssv_transaction_id VARCHAR(128);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_events_ssv_txid_unique
  ON reward_events(ssv_transaction_id)
  WHERE ssv_transaction_id IS NOT NULL;

-- Consultas de limite diario por usuario (usadas no controle de anuncios/dia).
CREATE INDEX IF NOT EXISTS idx_reward_events_user_created
  ON reward_events(user_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- 3. Indice para a checagem de refund duplicado no reject (VULN-07)
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_points_ledger_reference_type
  ON points_ledger(reference_id, transaction_type);

-- ----------------------------------------------------------------------------
-- 4. Roles administrativas (VULN-09)
--
-- O sistema tratava qualquer admin autenticado como onipotente. Agora as rotas
-- sensiveis exigem role especifica. Admins ja existentes recebem 'super_admin'
-- para nao perder acesso no deploy; o ajuste fino de permissoes deve ser feito
-- depois, manualmente, seguindo o principio do menor privilegio.
-- ----------------------------------------------------------------------------
UPDATE admin_users
   SET role = 'super_admin'
 WHERE role IS NULL OR role = 'admin';

-- ----------------------------------------------------------------------------
-- 5. Indice para localizar saques que exigem conferencia manual
--
-- O status PAYMENT_UNCONFIRMED e novo: marca saques cujo envio nao pode ser
-- confirmado (timeout/queda de conexao com a FaucetPay). Eles NAO voltam para a
-- fila automatica, justamente para nao serem pagos duas vezes, e precisam de
-- conferencia humana no extrato.
--
-- A coluna status e VARCHAR sem CHECK constraint no schema atual, portanto o
-- novo valor nao exige alteracao estrutural.
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_withdrawals_unconfirmed
  ON withdrawals(status, created_at DESC)
  WHERE status = 'PAYMENT_UNCONFIRMED';

-- ----------------------------------------------------------------------------
-- 6. Limpeza inicial de nonces antigos (seguranca de manutencao)
-- ----------------------------------------------------------------------------
DELETE FROM request_nonces WHERE created_at < NOW() - INTERVAL '1 day';

-- ----------------------------------------------------------------------------
-- 7. Colunas de controle de fraude e ban
--
-- Foram introduzidas na v1.5, mas sao repetidas aqui de forma idempotente para
-- garantir que o middleware antifraude nunca falhe por coluna ausente em um
-- ambiente que tenha pulado aquela migracao.
-- ----------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS fraud_score    INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_fraud_at  TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason     TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at      TIMESTAMP WITH TIME ZONE;

-- Consultas de fraude por IP dentro da ultima hora (rewardFraudDetection).
CREATE INDEX IF NOT EXISTS idx_reward_events_ip_created
  ON reward_events(ip_address, created_at DESC);

-- ----------------------------------------------------------------------------
-- 8. Vinculo de dispositivo (VULN-05)
--
-- O login do app pede apenas o e-mail, porque a tela do aplicativo nao possui campo de
-- senha. Enquanto essa interface nao mudar, a conta e protegida pelo vinculo ao aparelho:
-- um e-mail conhecido nao basta para entrar de outro dispositivo quando a conta tem saldo.
--
-- device_migration_allowed e a valvula de escape operacional: o suporte marca TRUE para
-- liberar uma troca de aparelho legitima. A flag e consumida no primeiro login seguinte
-- (volta a FALSE), evitando que uma liberacao esquecida fique valendo para sempre.
-- ----------------------------------------------------------------------------
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS device_migration_allowed BOOLEAN DEFAULT false;

-- Contagem de contas por aparelho (limite anti-farm no login/registro).
CREATE INDEX IF NOT EXISTS idx_users_device_id
  ON users(device_id);

-- Contagem de contas criadas por IP nas ultimas 24h (limite anti-farm).
CREATE INDEX IF NOT EXISTS idx_users_ip_created
  ON users(ip_address, created_at DESC);

-- ----------------------------------------------------------------------------
-- 9. Vinculo retroativo das contas existentes
--
-- Contas antigas ja possuem device_id preenchido pelo login anterior. Nada a fazer:
-- o vinculo passa a valer a partir do valor atual. Contas com device_id NULL (raras,
-- criadas antes do campo existir) recebem o vinculo no proximo login.
-- ----------------------------------------------------------------------------
