const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware } = require('../middleware/antiFraud');
const { withdrawalLimiter } = require('../middleware/rateLimits');
const { decrypt } = require('../utils/crypto');

// Namespace do advisory lock de saque. Precisa ser o MESMO valor usado em
// pix_withdrawals.js: os dois fluxos consomem o mesmo saldo de pontos e por isso
// precisam ser mutuamente exclusivos por usuario.
const WITHDRAWAL_LOCK_NAMESPACE = 8471;

const router = express.Router();

// GET /api/withdrawals - Get user's withdrawal history
router.get('/', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT id, amount, points_debited, payment_method, crypto_currency, status, 
              tx_hash, created_at, processed_at, rejection_reason
       FROM withdrawals 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
      [req.user.userId, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM withdrawals WHERE user_id = $1',
      [req.user.userId]
    );

    res.json({
      success: true,
      withdrawals: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json({ error: 'Failed to get withdrawals' });
  }
});

// POST /api/withdrawals/request - Request a withdrawal
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
          error: 'Duplicate withdrawal request',
          code: 'DUPLICATE',
          withdrawal: existingWithdrawal.rows[0]
        });
      }
    }

    await client.query('BEGIN');

    // ========================================================================
    // TRAVA DE CONCORRENCIA POR USUARIO (auditoria VULN-06)
    //
    // O fluxo original era: ler o saldo -> verificar se ha saque pendente ->
    // inserir a reserva negativa. Sem trava, duas requisicoes simultaneas leem o
    // MESMO saldo, e nenhuma das duas ve o saque pendente da outra (nenhuma commitou
    // ainda). As duas passam em todas as validacoes e as duas inserem a reserva.
    // Resultado: saldo final negativo e dois saques PENDING — ou seja, saque acima
    // do saldo real. Bastava disparar duas chamadas em paralelo com idempotency_key
    // diferentes (a constraint UNIQUE nao protege nesse caso).
    //
    // pg_advisory_xact_lock serializa por usuario: a segunda requisicao fica em espera
    // e so prossegue quando a primeira encerra a transacao, ja podendo enxergar a
    // reserva e o saque pendente criados. O lock e liberado automaticamente no
    // COMMIT ou ROLLBACK, sem risco de trava orfa.
    //
    // hashtext() converte o UUID do usuario em inteiro, formato exigido pela funcao.
    // O namespace fixo evita colisao com locks de outras finalidades.
    // ========================================================================
    await client.query(
      'SELECT pg_advisory_xact_lock($1, hashtext($2))',
      [WITHDRAWAL_LOCK_NAMESPACE, userId]
    );

    // Revalidacao dentro do lock: se outra requisicao acabou de criar um saque com esta
    // mesma chave, a checagem otimista feita antes do BEGIN pode ter passado.
    if (idempotency_key) {
      const raceCheck = await client.query(
        'SELECT id, status FROM withdrawals WHERE idempotency_key = $1',
        [idempotency_key]
      );
      if (raceCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Duplicate withdrawal request',
          code: 'DUPLICATE',
          withdrawal: raceCheck.rows[0]
        });
      }
    }

    // Get system config
    const configResult = await client.query(
      "SELECT key, value FROM system_config WHERE key IN ('withdrawal_min_points', 'points_per_real', 'withdrawal_min_amount', 'withdrawal_max_amount')"
    );
    const config = {};
    configResult.rows.forEach(row => {
      config[row.key] = JSON.parse(row.value);
    });

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

    // Check approved payout destination
    const destResult = await client.query(
      `SELECT id, value_encrypted, value_masked FROM payout_destinations 
       WHERE user_id = $1 AND status = 'APPROVED' AND is_active = true
       ORDER BY version DESC LIMIT 1`,
      [userId]
    );

    if (destResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'No approved FaucetPay email found. Please submit your email for approval first.',
        code: 'NO_APPROVED_DESTINATION'
      });
    }

    const destination = destResult.rows[0];

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
    // Se o usuário enviou points_amount, usa esse valor (permite valores quebrados)
    // Senão, saca tudo que tem disponível
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
      // Sem valor específico: saca tudo (sem arredondamento, aceita valores quebrados)
      pointsToDebit = balance;
    }

    if (pointsToDebit > balance) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Saldo insuficiente para o valor solicitado',
        code: 'INSUFFICIENT_BALANCE',
        requested: pointsToDebit,
        current: balance
      });
    }

    // Calcula o valor em reais (aceita valores quebrados, ex: 5000 pts = R$ 2.50)
    const amountInReal = parseFloat((pointsToDebit / pointsPerReal).toFixed(2));

    // Create ledger reservation (debit)
    const reservationId = uuidv4();
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'WITHDRAWAL_RESERVE', 'Reserva para saque')`,
      [reservationId, userId, -pointsToDebit]
    );

    // Decrypt email for crypto_address field
    const faucetPayEmail = decrypt(destination.value_encrypted);

    // Create withdrawal with LTC as crypto currency
    const withdrawalId = uuidv4();
    const idemKey = idempotency_key || uuidv4();

    await client.query(
      `INSERT INTO withdrawals (id, user_id, payout_destination_id, amount, points_debited, 
       payment_method, crypto_address, crypto_currency, status, idempotency_key, ledger_reservation_id, created_at)
       VALUES ($1, $2, $3, $4, $5, 'faucetpay', $6, 'LTC', 'PENDING', $7, $8, NOW())`,
      [withdrawalId, userId, destination.id, amountInReal, pointsToDebit, faucetPayEmail, idemKey, reservationId]
    );

    // Audit log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
       VALUES ($1, 'user', 'WITHDRAWAL_REQUESTED', 'withdrawal', $2, $3)`,
      [userId, withdrawalId, JSON.stringify({ amount: amountInReal, points: pointsToDebit, destination_masked: destination.value_masked })]
    );

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Withdrawal request submitted successfully',
      withdrawal: {
        id: withdrawalId,
        amount: amountInReal,
        pointsDebited: pointsToDebit,
        status: 'PENDING',
        destinationMasked: destination.value_masked,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Withdrawal request error:', error);
    res.status(500).json({ error: 'Failed to process withdrawal request' });
  } finally {
    client.release();
  }
});

// GET /api/withdrawals/eligibility - Check if user can withdraw
router.get('/eligibility', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get config
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key IN ('withdrawal_min_points', 'points_per_real')"
    );
    const config = {};
    configResult.rows.forEach(row => {
      config[row.key] = JSON.parse(row.value);
    });

    const minPoints = parseInt(config.withdrawal_min_points) || 2000;
    const pointsPerReal = parseInt(config.points_per_real) || 2000;

    // Get balance
    const balanceResult = await db.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [userId]
    );
    const balance = parseInt(balanceResult.rows[0].balance);

    // Check destination
    const destResult = await db.query(
      `SELECT id, status, value_masked FROM payout_destinations 
       WHERE user_id = $1 AND is_active = true
       ORDER BY version DESC LIMIT 1`,
      [userId]
    );

    // Check pending withdrawals
    const pendingCheck = await db.query(
      "SELECT id FROM withdrawals WHERE user_id = $1 AND status IN ('PENDING', 'PROCESSING')",
      [userId]
    );

    const hasApprovedDestination = destResult.rows.length > 0 && destResult.rows[0].status === 'APPROVED';
    const hasSufficientBalance = balance >= minPoints;
    const hasNoPendingWithdrawal = pendingCheck.rows.length === 0;

    res.json({
      success: true,
      eligible: hasApprovedDestination && hasSufficientBalance && hasNoPendingWithdrawal,
      details: {
        balance,
        minPoints,
        pointsPerReal,
        hasSufficientBalance,
        hasApprovedDestination,
        hasNoPendingWithdrawal,
        destinationStatus: destResult.rows.length > 0 ? destResult.rows[0].status : 'NONE',
        destinationMasked: destResult.rows.length > 0 ? destResult.rows[0].value_masked : null
      }
    });
  } catch (error) {
    console.error('Eligibility check error:', error);
    res.status(500).json({ error: 'Failed to check eligibility' });
  }
});

module.exports = router;
