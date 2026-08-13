'use strict';

/**
 * Webhook de validação de saques da Asaas.
 *
 * Quando o mecanismo "Validação de saque via Webhook" está habilitado na conta Asaas,
 * cada transferência/saque solicitado via API dispara um POST para esta URL ~5s após
 * a criação. A resposta { status: "APPROVED" } substitui o token SMS/APP.
 *
 * Guia: https://docs.asaas.com/docs/mecanismo-para-validacao-de-saque-via-webhooks
 *
 * Segurança:
 * - Valida o header asaas-access-token quando ASAAS_AUTH_TOKEN estiver configurada.
 * - Só aprova transferências PIX cujo ID consta em asaas_pending_transfers (criadas
 *   pelo fluxo process-pix deste mesmo backend), com verificação de valor/chave.
 * - Duplicidade é tratada: a primeira aprovação bem-sucedida marca o registro como
 *   usado; reenvios subsequentes do Asaas re-aprovam o mesmo ID se ainda pendente.
 * - Requisições que falham 3x consecutivas fazem o Asaas cancelar a transferência.
 */
const express = require('express');

const db = require('../models/db');

const router = express.Router();

function validStatus(status) {
  return status === 'APPROVED' || status === 'REFUSED';
}

router.post('/asaas/auth-webhook', async (req, res) => {
  try {
    // ---------------------------------------------------------------------
    // Autenticação: token de autorização configurado no painel Asaas (opcional
    // no painel, mas sempre recomendado; o backend valida se estiver definido)
    // ---------------------------------------------------------------------
    const configuredToken = process.env.ASAAS_AUTH_TOKEN;
    const receivedToken =
      req.headers['asaas-access-token'] || req.headers['asaasaccesstoken'];

    if (configuredToken) {
      if (!receivedToken || receivedToken !== configuredToken) {
        // Sem status => o Asaas trata como falha e, após 3 falhas, cancela.
        return res.status(200).json({ status: 'REFUSED' });
      }
    }

    const payload = req.body || {};
    const { type, transfer } = payload;

    // Tipos suportados: somente transferências PIX (as demais saques/contas não
    // são criadas por este backend e, portanto, jamais são aprovadas aqui).
    if (type !== 'TRANSFER' || !transfer || !transfer.id) {
      return res.json({ status: 'REFUSED' });
    }

    // ---------------------------------------------------------------------
    // Verificação contra a fila de pendências criada pelo processo de saque
    // ---------------------------------------------------------------------
    const { rows: pending } = await db.query(
      `SELECT id, transfer_id, value_cents, pix_address_key
         FROM asaas_pending_transfers
        WHERE transfer_id = $1`,
      [transfer.id]
    );

    if (!pending.length) {
      // Transferência desconhecida pelo backend: recusar. O Asaas cancela.
      return res.json({ status: 'REFUSED' });
    }

    const record = pending[0];

    // Verificar correspondência do valor (cents vs BRL do payload)
    const payloadValue =
      typeof transfer.value === 'number'
        ? transfer.value
        : parseFloat(transfer.value) || 0;
    if (Math.abs(record.value_cents - Math.round(payloadValue * 100)) > 1) {
      return res.json({
        status: 'REFUSED',
        refuseReason: 'Valor da transferencia divergente'
      });
    }

    // Verificar correspondência da chave PIX, se registrada
    const payloadKey =
      transfer.pixAddressKey ||
      (transfer.bankAccount && transfer.bankAccount.pixAddressKey);
    if (
      record.pix_address_key &&
      payloadKey &&
      payloadKey.toLowerCase() !== record.pix_address_key.toLowerCase()
    ) {
      return res.json({
        status: 'REFUSED',
        refuseReason: 'Chave Pix divergente'
      });
    }

    // Registrar a aprovação e marcar o registro como usado (idempotente)
    await db.query(
      `UPDATE asaas_pending_transfers
          SET used = true, updated_at = now()
        WHERE transfer_id = $1`,
      [transfer.id]
    );

    return res.json({ status: 'APPROVED' });
  } catch (err) {
    // Qualquer exceção => falha para o Asaas (retry); nunca aprova por erro.
    console.error('[asaas-webhook] erro:', err?.message || err);
    return res.status(500).json({});
  }
});

module.exports = router;
