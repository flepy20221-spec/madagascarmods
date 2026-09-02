'use strict';

const db = require('../models/db');
const { decrypt } = require('../utils/crypto');
const { checkAddress } = require('../utils/faucetpay');

async function revalidatePendingFaucetPay({ limit = 60 } = {}) {
  const pending = await db.query(
    `SELECT id, user_id, value_encrypted, value_masked
       FROM payout_destinations
      WHERE status = 'PENDING' AND is_active = true
      ORDER BY submitted_at ASC
      LIMIT $1`,
    [Math.max(1, Math.min(Number(limit) || 60, 60))]
  );

  const result = { checked: 0, approved: 0, rejected: 0, deferred: 0 };
  for (const destination of pending.rows) {
    let email;
    try {
      email = decrypt(destination.value_encrypted);
    } catch (error) {
      console.error('[payout-auto-approval] falha ao decifrar destino pendente:', destination.id);
      result.deferred += 1;
      continue;
    }

    const verification = await checkAddress({ address: email, currency: 'LTC' });
    result.checked += 1;
    if (verification.temporary) {
      result.deferred += 1;
      if (/_(401|403|459)$/.test(verification.code) || verification.code === 'FAUCETPAY_KEY_MISSING') break;
      continue;
    }

    const status = verification.verified ? 'APPROVED' : 'REJECTED';
    const action = verification.verified
      ? 'PAYOUT_DESTINATION_AUTO_APPROVED_BACKLOG'
      : 'PAYOUT_DESTINATION_AUTO_REJECTED_BACKLOG';
    const rejectionReason = verification.verified
      ? null
      : 'Conta FaucetPay inexistente, suspensa ou não verificada.';
    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      const updated = await client.query(
        `UPDATE payout_destinations
            SET status = $1, reviewed_at = NOW(), reviewed_by = NULL,
                rejection_reason = $2, updated_at = NOW()
          WHERE id = $3 AND status = 'PENDING' AND is_active = true
          RETURNING id`,
        [status, rejectionReason, destination.id]
      );
      if (updated.rows.length > 0) {
        await client.query(
          `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value)
           VALUES ($1, 'system', $2, 'payout_destination', $3, $4, $5)`,
          [
            destination.user_id,
            action,
            destination.id,
            JSON.stringify({ status: 'PENDING' }),
            JSON.stringify({ status, masked_email: destination.value_masked, provider_check: 'faucetpay_checkaddress' })
          ]
        );
      }
      await client.query('COMMIT');
      if (updated.rows.length > 0) {
        if (verification.verified) result.approved += 1;
        else result.rejected += 1;
      }
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      result.deferred += 1;
      console.error('[payout-auto-approval] falha ao atualizar pendencia:', error.message);
    } finally {
      client.release();
    }
  }

  return result;
}

function runOnStartup() {
  const timer = setTimeout(async () => {
    try {
      const result = await revalidatePendingFaucetPay();
      console.log('[payout-auto-approval] revalidacao inicial concluida:', result);
    } catch (error) {
      console.error('[payout-auto-approval] revalidacao inicial falhou:', error.message);
    }
  }, 5000);
  timer.unref?.();
}

module.exports = { revalidatePendingFaucetPay, runOnStartup };
