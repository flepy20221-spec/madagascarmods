const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware } = require('../middleware/antiFraud');
const { payoutSetupLimiter } = require('../middleware/rateLimits');
const { encrypt, hashValue, maskEmail } = require('../utils/crypto');

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

// POST /api/payout-destinations/submit - Submit FaucetPay email for approval
// payoutSetupLimiter: 10 tentativas/hora por usuario. (auditoria VULN-10)
router.post('/submit', payoutSetupLimiter, authenticateToken, antifraudMiddleware, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid FaucetPay email is required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const userId = req.user.userId;

    // Check if there's already a pending request from this user
    const existing = await db.query(
      `SELECT id, status FROM payout_destinations 
       WHERE user_id = $1 AND status = 'PENDING' AND is_active = true`,
      [userId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Você já tem uma solicitação de e-mail pendente',
        code: 'PENDING_EXISTS'
      });
    }

    // Check if this email is already registered by ANOTHER user (anti-fraud)
    const emailHash = hashValue(normalizedEmail);
    const duplicateCheck = await db.query(
      `SELECT id, user_id FROM payout_destinations 
       WHERE value_hash = $1 AND user_id != $2 AND status IN ('PENDING', 'APPROVED') AND is_active = true`,
      [emailHash, userId]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Este e-mail FaucetPay já está vinculado a outra conta.',
        code: 'EMAIL_ALREADY_USED'
      });
    }

    // Get current version
    const versionResult = await db.query(
      'SELECT COALESCE(MAX(version), 0) as max_version FROM payout_destinations WHERE user_id = $1',
      [userId]
    );
    const newVersion = parseInt(versionResult.rows[0].max_version) + 1;

    // Deactivate previous destinations
    await db.query(
      'UPDATE payout_destinations SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );

    // Create new destination
    const destId = uuidv4();
    const encryptedEmail = encrypt(normalizedEmail);
    // emailHash already computed above for duplicate check
    const masked = maskEmail(normalizedEmail);

    await db.query(
      `INSERT INTO payout_destinations (id, user_id, type, value_encrypted, value_masked, value_hash, status, version, is_active, submitted_at)
       VALUES ($1, $2, 'FAUCETPAY_EMAIL', $3, $4, $5, 'PENDING', $6, true, NOW())`,
      [destId, userId, encryptedEmail, masked, emailHash, newVersion]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'user', 'PAYOUT_DESTINATION_SUBMITTED', 'payout_destination', $2, $3)`,
      [userId, destId, JSON.stringify({ masked_email: masked, version: newVersion })]
    );

    res.status(201).json({
      success: true,
      message: 'FaucetPay email submitted for approval',
      destination: {
        id: destId,
        status: 'PENDING',
        maskedEmail: masked,
        version: newVersion
      }
    });
  } catch (error) {
    console.error('Submit payout error:', error);
    res.status(500).json({ error: 'Failed to submit payout destination' });
  }
});

module.exports = router;
