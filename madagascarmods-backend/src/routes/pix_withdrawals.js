const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware } = require('../middleware/antiFraud');
const { withdrawalLimiter } = require('../middleware/rateLimits');

// Mesmo namespace usado em withdrawals.js (FaucetPay).
// Os dois fluxos debitam o mesmo saldo de pontos, portanto precisam compartilhar o lock:
// se cada um usasse um namespace proprio, um saque PIX e um saque FaucetPay simultaneos
// ainda poderiam gastar o mesmo saldo duas vezes.
const WITHDRAWAL_LOCK_NAMESPACE = 8471;

const router = express.Router();

// POST /api/pix-withdrawals/request - Request a PIX withdrawal (manual processing)
router.post('/request', withdrawalLimiter, authenticateToken, antifraudMiddleware, async (req, res) => {
  const client = await db.getClient();

  try {
    const { idempotency_key, points_amount } = req.body;
    const userId = req.user.userId;

    // Check idempotency
    if (idempotency_key) {
      const existingWithdrawal = await db.query(
        'SELECT id, status FROM withdrawals WHERE idempotency_key = $1',
        [idempotency_key]
      );
      if (existingWithdrawal.rows.length > 0) {
        return res.status(409).json({
          error: 'Solicitação de saque duplicada',
          code: 'DUPLICATE',
          withdrawal: existingWithdrawal.rows[0]
        });
      }
    }

    await client.query('BEGIN');

    // Trava de concorrencia por usuario (auditoria VULN-06). Ver explicacao detalhada
    // em src/routes/withdrawals.js. Sem ela, duas requisicoes simultaneas leem o mesmo
    // saldo, nenhuma ve o saque pendente da outra, e ambas criam a reserva negativa —
    // resultando em saque acima do saldo real.
    await client.query(
      'SELECT pg_advisory_xact_lock($1, hashtext($2))',
      [WITHDRAWAL_LOCK_NAMESPACE, userId]
    );

    // Revalidacao da idempotencia dentro do lock
    if (idempotency_key) {
      const raceCheck = await client.query(
        'SELECT id, status FROM withdrawals WHERE idempotency_key = $1',
        [idempotency_key]
      );
      if (raceCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Solicitacao de saque duplicada',
          code: 'DUPLICATE',
          withdrawal: raceCheck.rows[0]
        });
      }
    }

    // Get system config
    const configResult = await client.query(
      "SELECT key, value FROM system_config WHERE key IN ('withdrawal_min_points', 'points_per_real', 'pix_withdrawal_enabled')"
    );
    const config = {};
    configResult.rows.forEach(row => {
      try { config[row.key] = JSON.parse(row.value); } catch (e) { config[row.key] = row.value; }
    });

    if (!config.pix_withdrawal_enabled) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saque via PIX está desabilitado no momento', code: 'PIX_DISABLED' });
    }

    const minPoints = parseInt(config.withdrawal_min_points) || 2000;
    const pointsPerReal = parseInt(config.points_per_real) || 2000;

    // Get user balance
    const balanceResult = await client.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [userId]
    );
    const balance = parseInt(balanceResult.rows[0].balance);

    if (balance < minPoints) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Pontos insuficientes para saque',
        code: 'INSUFFICIENT_BALANCE',
        required: minPoints,
        current: balance
      });
    }

    // Check approved PIX account
    const pixResult = await client.query(
      `SELECT id, cpf, full_name, pix_key_type, pix_key_value, pix_key_masked FROM pix_accounts 
       WHERE user_id = $1 AND status = 'APPROVED' AND is_active = true
       ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );

    if (pixResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Nenhuma conta PIX aprovada encontrada. Cadastre sua conta PIX primeiro.',
        code: 'NO_APPROVED_PIX'
      });
    }

    const pixAccount = pixResult.rows[0];

    // Check for pending withdrawals
    const pendingCheck = await client.query(
      "SELECT id FROM withdrawals WHERE user_id = $1 AND status IN ('PENDING', 'PROCESSING')",
      [userId]
    );

    if (pendingCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Você já tem um saque pendente. Aguarde o processamento.',
        code: 'PENDING_WITHDRAWAL_EXISTS'
      });
    }

    // Calculate withdrawal amount
    let pointsToDebit;
    if (points_amount && Number.isFinite(Number(points_amount)) && Number(points_amount) >= minPoints) {
      pointsToDebit = Math.min(parseInt(points_amount), balance);
    } else if (points_amount && Number(points_amount) > 0 && Number(points_amount) < minPoints) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Mínimo para saque: ${minPoints} pontos`,
        code: 'BELOW_MINIMUM',
        required: minPoints,
        requested: Number(points_amount)
      });
    } else {
      pointsToDebit = balance;
    }

    // Guarda final: o fluxo PIX nao tinha esta verificacao (o FaucetPay tinha).
    // Protege contra qualquer caminho que resulte em debito acima do saldo.
    if (pointsToDebit > balance || pointsToDebit <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Saldo insuficiente para o valor solicitado',
        code: 'INSUFFICIENT_BALANCE',
        requested: pointsToDebit,
        current: balance
      });
    }

    const amountInReal = parseFloat((pointsToDebit / pointsPerReal).toFixed(2));

    // Create ledger reservation (debit)
    const reservationId = uuidv4();
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'WITHDRAWAL_RESERVE', 'Reserva para saque PIX')`,
      [reservationId, userId, -pointsToDebit]
    );

    // Create withdrawal record
    const withdrawalId = uuidv4();
    const idemKey = idempotency_key || uuidv4();

    await client.query(
      `INSERT INTO withdrawals (id, user_id, payout_destination_id, amount, points_debited, 
       payment_method, crypto_address, crypto_currency, status, idempotency_key, ledger_reservation_id, created_at)
       VALUES ($1, $2, $3, $4, $5, 'pix', $6, 'BRL', 'PENDING', $7, $8, NOW())`,
      [withdrawalId, userId, pixAccount.id, amountInReal, pointsToDebit,
       JSON.stringify({ cpf: pixAccount.cpf, full_name: pixAccount.full_name, pix_key_type: pixAccount.pix_key_type, pix_key_value: pixAccount.pix_key_value }),
       idemKey, reservationId]
    );

    // Audit log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'user', 'PIX_WITHDRAWAL_REQUESTED', 'withdrawal', $2, $3)`,
      [userId, withdrawalId, JSON.stringify({ amount: amountInReal, points: pointsToDebit, pix_key_masked: pixAccount.pix_key_masked })]
    );

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Saque PIX solicitado com sucesso! Aguarde aprovação.',
      withdrawal: {
        id: withdrawalId,
        amount: amountInReal,
        pointsDebited: pointsToDebit,
        status: 'PENDING',
        paymentMethod: 'pix',
        pixKeyMasked: pixAccount.pix_key_masked,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('PIX withdrawal request error:', error);
    res.status(500).json({ error: 'Falha ao processar solicitação de saque PIX' });
  } finally {
    client.release();
  }
});

// GET /api/pix-withdrawals/eligibility - Check if user can withdraw via PIX
router.get('/eligibility', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get config
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key IN ('withdrawal_min_points', 'points_per_real', 'pix_withdrawal_enabled')"
    );
    const config = {};
    configResult.rows.forEach(row => {
      try { config[row.key] = JSON.parse(row.value); } catch (e) { config[row.key] = row.value; }
    });

    const minPoints = parseInt(config.withdrawal_min_points) || 2000;
    const pointsPerReal = parseInt(config.points_per_real) || 2000;
    const pixEnabled = config.pix_withdrawal_enabled === true || config.pix_withdrawal_enabled === 'true';

    // Get balance
    const balanceResult = await db.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [userId]
    );
    const balance = parseInt(balanceResult.rows[0].balance);

    // Check PIX account
    const pixResult = await db.query(
      `SELECT id, status, pix_key_masked FROM pix_accounts 
       WHERE user_id = $1 AND is_active = true
       ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );

    // Check pending withdrawals
    const pendingCheck = await db.query(
      "SELECT id FROM withdrawals WHERE user_id = $1 AND status IN ('PENDING', 'PROCESSING')",
      [userId]
    );

    const hasApprovedPix = pixResult.rows.length > 0 && pixResult.rows[0].status === 'APPROVED';
    const hasSufficientBalance = balance >= minPoints;
    const hasNoPendingWithdrawal = pendingCheck.rows.length === 0;

    res.json({
      success: true,
      eligible: pixEnabled && hasApprovedPix && hasSufficientBalance && hasNoPendingWithdrawal,
      details: {
        balance,
        minPoints,
        pointsPerReal,
        pixEnabled,
        hasSufficientBalance,
        hasApprovedPix,
        hasNoPendingWithdrawal,
        pixStatus: pixResult.rows.length > 0 ? pixResult.rows[0].status : 'NONE',
        pixKeyMasked: pixResult.rows.length > 0 ? pixResult.rows[0].pix_key_masked : null
      }
    });
  } catch (error) {
    console.error('PIX eligibility check error:', error);
    res.status(500).json({ error: 'Falha ao verificar elegibilidade PIX' });
  }
});

module.exports = router;
