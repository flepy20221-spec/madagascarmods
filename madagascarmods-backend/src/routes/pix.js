const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware } = require('../middleware/antiFraud');
const { payoutSetupLimiter } = require('../middleware/rateLimits');
const { validatePixPayload } = require('../utils/payoutHelpers');
const { hashValue } = require('../utils/crypto');

const router = express.Router();

// Helpers
function maskCpf(cpf) {
  // 123.456.789-00 -> 123.***.***-00
  const clean = cpf.replace(/\D/g, '');
  if (clean.length !== 11) return '***.***.***-**';
  return `${clean.slice(0, 3)}.***.***-${clean.slice(9)}`;
}

function maskPixKey(type, value) {
  if (type === 'cpf') {
    return maskCpf(value);
  }
  // email
  if (value.includes('@')) {
    const [local, domain] = value.split('@');
    if (local.length <= 2) return `${local[0]}***@${domain}`;
    return `${local.slice(0, 2)}***${local.slice(-1)}@${domain}`;
  }
  return '***';
}

function validateCpf(cpf) {
  const clean = cpf.replace(/\D/g, '');
  if (clean.length !== 11) return false;
  // Check for all same digits
  if (/^(\d)\1{10}$/.test(clean)) return false;
  // Validate check digits
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(clean[i]) * (10 - i);
  let remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(clean[9])) return false;
  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(clean[i]) * (11 - i);
  remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(clean[10])) return false;
  return true;
}

// GET /api/pix/status - Get current PIX account status
router.get('/status', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, cpf, full_name, pix_key_type, pix_key_masked, status, 
              submitted_at, reviewed_at, rejection_reason
       FROM pix_accounts 
       WHERE user_id = $1 AND is_active = true
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        success: true,
        hasPixAccount: false,
        pixAccount: null
      });
    }

    const pix = result.rows[0];
    res.json({
      success: true,
      hasPixAccount: true,
      pixAccount: {
        id: pix.id,
        cpfMasked: maskCpf(pix.cpf),
        fullName: pix.full_name,
        pixKeyType: pix.pix_key_type,
        pixKeyMasked: pix.pix_key_masked,
        status: pix.status,
        submittedAt: pix.submitted_at,
        reviewedAt: pix.reviewed_at,
        rejectionReason: pix.rejection_reason
      }
    });
  } catch (error) {
    console.error('Get PIX status error:', error);
    res.status(500).json({ error: 'Falha ao obter status da conta PIX' });
  }
});

// POST /api/pix/submit - Validate and auto-approve PIX account
// payoutSetupLimiter: 10 tentativas/hora por usuario. Sem esse limite, o endpoint podia
// ser usado para testar CPFs em massa contra as validacoes do servidor. (auditoria VULN-10)
router.post('/submit', payoutSetupLimiter, authenticateToken, antifraudMiddleware, async (req, res) => {
  const validation = validatePixPayload(req.body || {});
  if (!validation.ok) {
    const status = Number.isInteger(validation.status) ? validation.status : 400;
    return res.status(status).json({ error: validation.error, code: validation.code });
  }

  const {
    cpf: cleanCpf,
    fullName,
    pixKeyType,
    pixKeyValue,
    pixKeyMasked,
  } = validation.data;
  const cpfHash = hashValue(cleanCpf);
  const userId = req.user.userId;
  let client;
  try {
    client = await db.getClient();
    await client.query('BEGIN');
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`pix:${pixKeyValue}`]);

    const unchanged = await client.query(
      `SELECT id, status, cpf, full_name, pix_key_type, pix_key_masked
       FROM pix_accounts
       WHERE user_id = $1 AND cpf_hash = $2 AND LOWER(pix_key_value) = LOWER($3)
         AND pix_key_type = $4 AND full_name = $5 AND status = 'APPROVED' AND is_active = true
       ORDER BY created_at DESC LIMIT 1`,
      [userId, cpfHash, pixKeyValue, pixKeyType, fullName]
    );
    if (unchanged.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.json({
        success: true,
        message: 'Esta chave PIX já está aprovada.',
        pixAccount: {
          id: unchanged.rows[0].id,
          status: unchanged.rows[0].status,
          cpfMasked: maskCpf(unchanged.rows[0].cpf),
          fullName: unchanged.rows[0].full_name,
          pixKeyType: unchanged.rows[0].pix_key_type,
          pixKeyMasked: unchanged.rows[0].pix_key_masked
        }
      });
    }

    const cpfCheck = await client.query(
      `SELECT id, user_id FROM pix_accounts 
       WHERE cpf_hash = $1 AND user_id != $2 AND is_active = true AND status IN ('PENDING', 'APPROVED')`,
      [cpfHash, userId]
    );

    if (cpfCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este CPF já está vinculado a outra conta.',
        code: 'CPF_ALREADY_USED'
      });
    }

    const keyCheck = await client.query(
      `SELECT id FROM pix_accounts
       WHERE LOWER(pix_key_value) = LOWER($1) AND user_id != $2
         AND is_active = true AND status IN ('PENDING', 'APPROVED')`,
      [pixKeyValue, userId]
    );
    if (keyCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Esta chave PIX já está vinculada a outra conta.',
        code: 'PIX_KEY_ALREADY_USED'
      });
    }

    await client.query(
      'UPDATE pix_accounts SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    const pixId = uuidv4();
    await client.query(
      `INSERT INTO pix_accounts
         (id, user_id, cpf, cpf_hash, full_name, pix_key_type, pix_key_value, pix_key_masked, status, is_active, submitted_at, reviewed_at, reviewed_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'APPROVED', true, NOW(), NOW(), NULL)`,
      [pixId, userId, cleanCpf, cpfHash, fullName, pixKeyType, pixKeyValue, pixKeyMasked]
    );
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'system', 'PIX_ACCOUNT_AUTO_APPROVED', 'pix_account', $2, $3)`,
      [userId, pixId, JSON.stringify({ cpf_masked: maskCpf(cleanCpf), pix_key_type: pixKeyType, pix_key_masked: pixKeyMasked, validation: 'local' })]
    );
    await client.query('COMMIT');

    return res.status(201).json({
      success: true,
      message: 'Chave PIX aprovada automaticamente.',
      pixAccount: {
        id: pixId,
        status: 'APPROVED',
        cpfMasked: maskCpf(cleanCpf),
        fullName,
        pixKeyType,
        pixKeyMasked: pixKeyMasked
      }
    });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('Submit PIX error:', error);
    if (error.code === '23505') {
      // Unique constraint violation (CPF already used)
      return res.status(409).json({
        error: 'Este CPF já está vinculado a outra conta.',
        code: 'CPF_ALREADY_USED'
      });
    }
    res.status(500).json({ error: 'Falha ao cadastrar conta PIX' });
  } finally {
    client?.release();
  }
});

module.exports = router;
