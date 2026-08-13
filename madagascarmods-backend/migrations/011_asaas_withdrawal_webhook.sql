-- =============================================================================
-- Fila de pendencias do webhook de validacao de saques da Asaas.
--
-- Quando o mecanismo "Validacao de saque via Webhook" esta habilitado na conta
-- Asaas, cada transferencia via API dispara um POST para /api/asaas/auth-webhook
-- ~5s apos a criacao. Este backend so aprova transferencias cujo ID consta aqui,
-- com conferencia de valor (cents) e chave PIX, impedindo que transferencias
-- estranhas ao fluxo sejam aprovadas.
-- =============================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS asaas_pending_transfers (
  id BIGSERIAL PRIMARY KEY,
  transfer_id UUID NOT NULL UNIQUE,          -- ID da transferencia retornado pela Asaas
  withdrawal_id UUID NOT NULL,               -- saque que originou a transferencia
  value_cents INTEGER NOT NULL,              -- valor em centavos (conferido contra o payload)
  pix_address_key VARCHAR(255),              -- chave PIX normalizada (conferencia opcional)
  used BOOLEAN NOT NULL DEFAULT false,       -- ja aprovada no webhook (idempotencia)
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asaas_pending_transfer_id ON asaas_pending_transfers(transfer_id);

-- Cleanup: registros mais antigos que 90 dias ja aprovados ou transferencias sem
-- saque associado nao tem mais utilidade para a validacao.
DELETE FROM asaas_pending_transfers
WHERE used = true AND created_at < NOW() - INTERVAL '90 days';

COMMIT;
