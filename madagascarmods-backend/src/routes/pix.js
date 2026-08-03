const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { payoutSetupLimiter } = require('../middleware/rateLimits');
const { encrypt, hashValue } = require('../utils/crypto');

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

// POST /api/pix/submit - Submit PIX account for approval
// payoutSetupLimiter: 10 tentativas/hora por usuario. Sem esse limite, o endpoint podia
// ser usado para testar CPFs em massa contra as validacoes do servidor. (auditoria VULN-10)
router.post('/submit', payoutSetupLimiter, authenticateToken, async (req, res) => {
  try {
    const { cpf, full_name, pix_key_type, pix_key_value } = req.body;
    const userId = req.user.userId;

    // Validations
    if (!cpf || !full_name || !pix_key_type || !pix_key_value) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios: CPF, nome completo, tipo de chave e valor da chave' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ error: 'CPF inválido', code: 'INVALID_CPF' });
    }

    if (full_name.trim().length < 5) {
      return res.status(400).json({ error: 'Nome completo deve ter pelo menos 5 caracteres' });
    }

    if (!['cpf', 'email'].includes(pix_key_type)) {
      return res.status(400).json({ error: 'Tipo de chave PIX deve ser "cpf" ou "email"' });
    }

    if (pix_key_type === 'email' && !pix_key_value.includes('@')) {
      return res.status(400).json({ error: 'E-mail da chave PIX inválido' });
    }

    if (pix_key_type === 'cpf') {
      const cleanPixKey = pix_key_value.replace(/\D/g, '');
      if (!validateCpf(cleanPixKey)) {
        return res.status(400).json({ error: 'CPF da chave PIX inválido' });
      }
    }

    // Check if user already has a pending PIX request
    const existing = await db.query(
      `SELECT id, status FROM pix_accounts 
       WHERE user_id = $1 AND status = 'PENDING' AND is_active = true`,
      [userId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: 'Você já tem uma solicitação PIX pendente',
        code: 'PENDING_EXISTS'
      });
    }

    // Check CPF uniqueness (1 account per CPF)
    const cpfHash = hashValue(cleanCpf);
    const cpfCheck = await db.query(
      `SELECT id, user_id FROM pix_accounts 
       WHERE cpf_hash = $1 AND user_id != $2 AND is_active = true AND status IN ('PENDING', 'APPROVED')`,
      [cpfHash, userId]
    );

    if (cpfCheck.rows.length > 0) {
      return res.status(409).json({
        error: 'Este CPF já está vinculado a outra conta.',
        code: 'CPF_ALREADY_USED'
      });
    }

    // Deactivate previous PIX accounts for this user
    await db.query(
      'UPDATE pix_accounts SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );

    // Create new PIX account
    const pixId = uuidv4();
    const pixKeyMasked = maskPixKey(pix_key_type, pix_key_value.trim());

    await db.query(
      `INSERT INTO pix_accounts (id, user_id, cpf, cpf_hash, full_name, pix_key_type, pix_key_value, pix_key_masked, status, is_active, submitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING', true, NOW())`,
      [pixId, userId, cleanCpf, cpfHash, full_name.trim(), pix_key_type, pix_key_value.trim().toLowerCase(), pixKeyMasked]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'user', 'PIX_ACCOUNT_SUBMITTED', 'pix_account', $2, $3)`,
      [userId, pixId, JSON.stringify({ cpf_masked: maskCpf(cleanCpf), pix_key_type, pix_key_masked: pixKeyMasked })]
    );

    res.status(201).json({
      success: true,
      message: 'Conta PIX enviada para aprovação',
      pixAccount: {
        id: pixId,
        status: 'PENDING',
        cpfMasked: maskCpf(cleanCpf),
        fullName: full_name.trim(),
        pixKeyType: pix_key_type,
        pixKeyMasked: pixKeyMasked
      }
    });
  } catch (error) {
    console.error('Submit PIX error:', error);
    if (error.code === '23505') {
      // Unique constraint violation (CPF already used)
      return res.status(409).json({
        error: 'Este CPF já está vinculado a outra conta.',
        code: 'CPF_ALREADY_USED'
      });
    }
    res.status(500).json({ error: 'Falha ao cadastrar conta PIX' });
  }
});

module.exports = router;
