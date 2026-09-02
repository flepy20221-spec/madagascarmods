const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware } = require('../middleware/antiFraud');
const { payoutSetupLimiter } = require('../middleware/rateLimits');
const { validatePayoutDestination } = require('../utils/payoutHelpers');
const { checkAddress } = require('../utils/faucetpay');

const router = express.Router();

// GET /api/payout-destinations/status - Get current payout destination status
router.get('/status', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, status, value_masked, version, submitted_at, reviewed_at, rejection_reason
       FROM payout_destinations 
       WHERE user_id = $1 AND is_active = true
       ORDER BY version DESC LIMIT 1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        success: true,
        hasDestination: false,
        destination: null
      });
    }

    const dest = result.rows[0];
    res.json({
      success: true,
      hasDestination: true,
      destination: {
        id: dest.id,
        status: dest.status,
        maskedEmail: dest.value_masked,
        version: dest.version,
        submittedAt: dest.submitted_at,
        reviewedAt: dest.reviewed_at,
        rejectionReason: dest.rejection_reason
      }
    });
  } catch (error) {
    console.error('Get payout status error:', error);
    res.status(500).json({ error: 'Failed to get payout destination status' });
  }
});

// POST /api/payout-destinations/submit - Validate and auto-approve FaucetPay email
// payoutSetupLimiter: 10 tentativas/hora por usuario. (auditoria VULN-10)
router.post('/submit', payoutSetupLimiter, authenticateToken, antifraudMiddleware, async (req, res) => {
  const validation = validatePayoutDestination(req.body?.email);
  if (!validation.ok) {
    return res.status(validation.status).json({ error: validation.error, code: validation.code });
  }

  const verification = await checkAddress({ address: validation.normalized, currency: 'LTC' });
  if (!verification.verified) {
    if (verification.temporary) {
      return res.status(503).json({
        error: 'Não foi possível validar sua conta FaucetPay agora. Tente novamente em alguns minutos.',
        code: 'FAUCETPAY_CHECK_TEMPORARY'
      });
    }
    return res.status(422).json({
      error: 'Este e-mail não pertence a uma conta FaucetPay ativa. Crie ou confirme sua conta na FaucetPay e tente novamente.',
      code: 'FAUCETPAY_ACCOUNT_NOT_PAYABLE'
    });
  }

  const userId = req.user.userId;
  let client;
  try {
    client = await db.getClient();
    await client.query('BEGIN');
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [validation.hash]);

    const unchanged = await client.query(
      `SELECT id, status, value_masked, version FROM payout_destinations
       WHERE value_hash = $1 AND user_id = $2 AND status = 'APPROVED' AND is_active = true
       ORDER BY version DESC LIMIT 1`,
      [validation.hash, userId]
    );
    if (unchanged.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.json({
        success: true,
        message: 'Esta conta FaucetPay já está aprovada.',
        destination: {
          id: unchanged.rows[0].id,
          status: unchanged.rows[0].status,
          maskedEmail: unchanged.rows[0].value_masked,
          version: unchanged.rows[0].version
        }
      });
    }

    const duplicateCheck = await client.query(
      `SELECT id FROM payout_destinations
       WHERE value_hash = $1 AND user_id != $2 AND status IN ('PENDING', 'APPROVED') AND is_active = true`,
      [validation.hash, userId]
    );
    if (duplicateCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este e-mail FaucetPay já está vinculado a outra conta.',
        code: 'EMAIL_ALREADY_USED'
      });
    }

    const versionResult = await client.query(
      'SELECT COALESCE(MAX(version), 0) AS max_version FROM payout_destinations WHERE user_id = $1',
      [userId]
    );
    const newVersion = Number(versionResult.rows[0].max_version) + 1;
    await client.query(
      'UPDATE payout_destinations SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );

    const destId = uuidv4();
    await client.query(
      `INSERT INTO payout_destinations
         (id, user_id, type, value_encrypted, value_masked, value_hash, status, version, is_active, submitted_at, reviewed_at, reviewed_by)
       VALUES ($1, $2, 'FAUCETPAY_EMAIL', $3, $4, $5, 'APPROVED', $6, true, NOW(), NOW(), NULL)`,
      [destId, userId, validation.encrypted, validation.masked, validation.hash, newVersion]
    );
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'system', 'PAYOUT_DESTINATION_AUTO_APPROVED', 'payout_destination', $2, $3)`,
      [userId, destId, JSON.stringify({ masked_email: validation.masked, version: newVersion, provider_check: 'faucetpay_checkaddress' })]
    );
    await client.query('COMMIT');

    return res.status(201).json({
      success: true,
      message: 'Conta FaucetPay validada e aprovada automaticamente.',
      destination: {
        id: destId,
        status: 'APPROVED',
        maskedEmail: validation.masked,
        version: newVersion
      }
    });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('Submit payout error:', error);
    res.status(500).json({ error: 'Failed to submit payout destination' });
  } finally {
    client?.release();
  }
});

module.exports = router;
