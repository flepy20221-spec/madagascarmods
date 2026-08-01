const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateAdmin, JWT_SECRET } = require('../middleware/auth');
const { decrypt } = require('../utils/crypto');
const faucetpay = require('../utils/faucetpay');

const router = express.Router();

// POST /api/admin/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const admin = await db.query(
      'SELECT id, email, password_hash, name, role, is_active FROM admin_users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    if (admin.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const adminUser = admin.rows[0];

    if (!adminUser.is_active) {
      return res.status(403).json({ error: 'Admin account is inactive' });
    }

    const validPassword = await bcrypt.compare(password, adminUser.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: adminUser.id, email: adminUser.email, isAdmin: true, role: adminUser.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      token,
      admin: { id: adminUser.id, email: adminUser.email, name: adminUser.name, role: adminUser.role }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/admin/setup - Initial admin setup (only works if no admins exist)
router.post('/setup', async (req, res) => {
  try {
    const existing = await db.query('SELECT COUNT(*) as count FROM admin_users');
    if (parseInt(existing.rows[0].count) > 0) {
      return res.status(403).json({ error: 'Admin already configured' });
    }

    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const adminId = uuidv4();

    await db.query(
      'INSERT INTO admin_users (id, email, password_hash, name, role) VALUES ($1, $2, $3, $4, $5)',
      [adminId, email.toLowerCase().trim(), passwordHash, name || 'Admin', 'super_admin']
    );

    res.status(201).json({ success: true, message: 'Admin account created' });
  } catch (error) {
    console.error('Admin setup error:', error);
    res.status(500).json({ error: 'Setup failed' });
  }
});

// ============ PAYOUT DESTINATIONS MANAGEMENT ============

// GET /api/admin/payout-destinations - List payout destinations
router.get('/payout-destinations', authenticateAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'PENDING';
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT pd.id, pd.user_id, pd.value_masked, pd.status, pd.version, pd.submitted_at, pd.reviewed_at, pd.rejection_reason,
              u.email as user_email, u.device_id, u.ip_address, u.created_at as user_created_at
       FROM payout_destinations pd
       JOIN users u ON u.id = pd.user_id
       WHERE pd.status = $1 AND pd.is_active = true
       ORDER BY pd.submitted_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM payout_destinations WHERE status = $1 AND is_active = true',
      [status]
    );

    // Stats
    const stats = await db.query(
      `SELECT status, COUNT(*) as count FROM payout_destinations WHERE is_active = true GROUP BY status`
    );

    const statsObj = { PENDING: 0, APPROVED: 0, REJECTED: 0, REVOKED: 0 };
    stats.rows.forEach(row => { statsObj[row.status] = parseInt(row.count); });

    res.json({
      success: true,
      destinations: result.rows,
      stats: statsObj,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('List payout destinations error:', error);
    res.status(500).json({ error: 'Failed to list payout destinations' });
  }
});

// POST /api/admin/payout-destinations/:id/review - Approve or reject
router.post('/payout-destinations/:id/review', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, reason } = req.body; // action: 'approve' or 'reject'

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Action must be "approve" or "reject"' });
    }

    if (action === 'reject' && !reason) {
      return res.status(400).json({ error: 'Rejection reason is required' });
    }

    const dest = await db.query(
      'SELECT id, user_id, status, value_masked FROM payout_destinations WHERE id = $1',
      [id]
    );

    if (dest.rows.length === 0) {
      return res.status(404).json({ error: 'Payout destination not found' });
    }

    if (dest.rows[0].status !== 'PENDING') {
      return res.status(400).json({ error: `Cannot review a destination with status: ${dest.rows[0].status}` });
    }

    const newStatus = action === 'approve' ? 'APPROVED' : 'REJECTED';

    await db.query(
      `UPDATE payout_destinations SET status = $1, reviewed_at = NOW(), reviewed_by = $2, 
       rejection_reason = $3, updated_at = NOW() WHERE id = $4`,
      [newStatus, req.admin.id, action === 'reject' ? reason : null, id]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', $2, 'payout_destination', $3, $4, $5, $6)`,
      [
        req.admin.id,
        `PAYOUT_DESTINATION_${newStatus}`,
        id,
        JSON.stringify({ status: 'PENDING' }),
        JSON.stringify({ status: newStatus, reason: reason || null }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    res.json({
      success: true,
      message: `Payout destination ${action}d successfully`,
      destination: { id, status: newStatus }
    });
  } catch (error) {
    console.error('Review payout destination error:', error);
    res.status(500).json({ error: 'Failed to review payout destination' });
  }
});

// ============ WITHDRAWALS MANAGEMENT ============

// GET /api/admin/withdrawals - List withdrawals
router.get('/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'PENDING';
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT w.id, w.user_id, w.amount, w.points_debited, w.payment_method, w.crypto_address,
              w.crypto_amount, w.crypto_currency, w.status, w.tx_hash, w.created_at, w.processed_at,
              w.rejection_reason, u.email as user_email, pd.value_masked as destination_masked
       FROM withdrawals w
       JOIN users u ON u.id = w.user_id
       LEFT JOIN payout_destinations pd ON pd.id = w.payout_destination_id
       WHERE w.status = $1
       ORDER BY w.created_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM withdrawals WHERE status = $1',
      [status]
    );

    // Stats
    const stats = await db.query(
      `SELECT status, COUNT(*) as count, COALESCE(SUM(amount), 0) as total_amount FROM withdrawals GROUP BY status`
    );

    const statsObj = {};
    stats.rows.forEach(row => {
      statsObj[row.status] = { count: parseInt(row.count), totalAmount: parseFloat(row.total_amount) };
    });

    res.json({
      success: true,
      withdrawals: result.rows,
      stats: statsObj,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('List withdrawals error:', error);
    res.status(500).json({ error: 'Failed to list withdrawals' });
  }
});

// POST /api/admin/withdrawals/:id/approve - Approve withdrawal AND process FaucetPay payment
router.post('/withdrawals/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const withdrawal = await db.query(
      'SELECT id, user_id, status, amount, points_debited, crypto_address, crypto_currency FROM withdrawals WHERE id = $1',
      [id]
    );

    if (withdrawal.rows.length === 0) {
      return res.status(404).json({ error: 'Saque não encontrado' });
    }

    const w = withdrawal.rows[0];

    if (w.status !== 'PENDING') {
      return res.status(400).json({ error: `Não é possível aprovar saque com status: ${w.status}` });
    }

    // Mark as APPROVED first
    await db.query(
      `UPDATE withdrawals SET status = 'APPROVED', approved_by = $1, approved_at = NOW(), updated_at = NOW() WHERE id = $2`,
      [req.admin.id, id]
    );

    // Now process FaucetPay payment automatically
    const amountBRL = parseFloat(w.amount);
    let paymentResult = null;
    let finalStatus = 'APPROVED';

    try {
      // Mark as PROCESSING
      await db.query(
        `UPDATE withdrawals SET status = 'PROCESSING', updated_at = NOW() WHERE id = $1`,
        [id]
      );

      paymentResult = await faucetpay.sendPayment({
        to: w.crypto_address,
        amountBRL: amountBRL,
        referralId: id,
      });

      if (paymentResult.success) {
        // Payment successful - mark as PAID
        finalStatus = 'PAID';
        await db.query(
          `UPDATE withdrawals SET 
            status = 'PAID', 
            crypto_amount = $1, 
            exchange_rate = $2, 
            tx_hash = $3, 
            gateway_response = $4, 
            processed_at = NOW(), 
            updated_at = NOW() 
          WHERE id = $5`,
          [
            paymentResult.ltcAmount,
            paymentResult.exchangeRate,
            paymentResult.tx_hash || paymentResult.payout_hash || null,
            JSON.stringify(paymentResult),
            id
          ]
        );
      } else {
        // Payment failed - keep as APPROVED (admin can retry with process-faucetpay)
        finalStatus = 'APPROVED';
        await db.query(
          `UPDATE withdrawals SET status = 'APPROVED', gateway_response = $1, updated_at = NOW() WHERE id = $2`,
          [JSON.stringify(paymentResult), id]
        );
      }
    } catch (payErr) {
      // FaucetPay error - keep as APPROVED
      console.error('[Approve] FaucetPay payment error:', payErr.message);
      finalStatus = 'APPROVED';
      await db.query(
        `UPDATE withdrawals SET status = 'APPROVED', gateway_response = $1, updated_at = NOW() WHERE id = $2`,
        [JSON.stringify({ error: payErr.message }), id]
      );
    }

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'WITHDRAWAL_APPROVED', 'withdrawal', $2, $3, $4)`,
      [
        req.admin.id, id,
        JSON.stringify({
          amount: amountBRL,
          finalStatus,
          paymentSuccess: paymentResult ? paymentResult.success : false,
          ltcAmount: paymentResult ? paymentResult.ltcAmount : null,
          txHash: paymentResult ? (paymentResult.tx_hash || paymentResult.payout_hash) : null
        }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    if (finalStatus === 'PAID') {
      res.json({
        success: true,
        message: `Saque aprovado e pago! ${paymentResult.ltcAmount} LTC enviado.`,
        status: 'PAID',
        ltcAmount: paymentResult.ltcAmount,
        exchangeRate: paymentResult.exchangeRate,
        txHash: paymentResult.tx_hash || paymentResult.payout_hash
      });
    } else {
      res.json({
        success: true,
        message: `Saque aprovado, mas pagamento FaucetPay falhou: ${paymentResult ? paymentResult.message : 'Erro de conexão'}. Use "Enviar FaucetPay" para tentar novamente.`,
        status: 'APPROVED',
        paymentError: paymentResult ? paymentResult.message : 'Erro de conexão'
      });
    }
  } catch (error) {
    console.error('Approve withdrawal error:', error);
    res.status(500).json({ error: 'Falha ao aprovar saque' });
  }
});

// POST /api/admin/withdrawals/:id/reject - Reject withdrawal
router.post('/withdrawals/:id/reject', authenticateAdmin, async (req, res) => {
  const client = await db.getClient();
  
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ error: 'Rejection reason is required' });
    }

    await client.query('BEGIN');

    const withdrawal = await client.query(
      'SELECT id, user_id, status, points_debited, ledger_reservation_id FROM withdrawals WHERE id = $1 FOR UPDATE',
      [id]
    );

    if (withdrawal.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Withdrawal not found' });
    }

    if (withdrawal.rows[0].status !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Cannot reject withdrawal with status: ${withdrawal.rows[0].status}` });
    }

    // Refund points
    const refundId = uuidv4();
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
       VALUES ($1, $2, $3, 'WITHDRAWAL_REFUND', $4, 'Withdrawal rejected - points refunded')`,
      [refundId, withdrawal.rows[0].user_id, withdrawal.rows[0].points_debited, id]
    );

    // Update withdrawal status
    await client.query(
      `UPDATE withdrawals SET status = 'REJECTED', rejection_reason = $1, updated_at = NOW() WHERE id = $2`,
      [reason, id]
    );

    // Audit log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'WITHDRAWAL_REJECTED', 'withdrawal', $2, $3, $4)`,
      [req.admin.id, id, JSON.stringify({ reason, points_refunded: withdrawal.rows[0].points_debited }), req.headers['x-forwarded-for'] || req.socket.remoteAddress]
    );

    await client.query('COMMIT');

    res.json({ success: true, message: 'Withdrawal rejected and points refunded' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Reject withdrawal error:', error);
    res.status(500).json({ error: 'Failed to reject withdrawal' });
  } finally {
    client.release();
  }
});

// POST /api/admin/withdrawals/:id/process-faucetpay - Process FaucetPay payment (LTC)
router.post('/withdrawals/:id/process-faucetpay', authenticateAdmin, async (req, res) => {
  const client = await db.getClient();
  
  try {
    const { id } = req.params;

    await client.query('BEGIN');

    const withdrawal = await client.query(
      `SELECT w.id, w.user_id, w.status, w.amount, w.crypto_address, w.crypto_currency, w.idempotency_key, w.ledger_reservation_id
       FROM withdrawals w WHERE w.id = $1 FOR UPDATE`,
      [id]
    );

    if (withdrawal.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Saque não encontrado' });
    }

    const w = withdrawal.rows[0];

    if (!['PENDING', 'APPROVED'].includes(w.status)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Não é possível processar saque com status: ${w.status}` });
    }

    // Mark as processing
    await client.query(
      `UPDATE withdrawals SET status = 'PROCESSING', updated_at = NOW() WHERE id = $1`,
      [id]
    );

    await client.query('COMMIT');

    // Call FaucetPay API to send LTC payment
    const amountBRL = parseFloat(w.amount);
    const paymentResult = await faucetpay.sendPayment({
      to: w.crypto_address,
      amountBRL: amountBRL,
      referralId: w.id,
    });

    if (paymentResult.success) {
      // Payment successful - mark as PAID
      await db.query(
        `UPDATE withdrawals SET 
          status = 'PAID', 
          crypto_amount = $1, 
          exchange_rate = $2, 
          tx_hash = $3, 
          gateway_response = $4, 
          processed_at = NOW(), 
          updated_at = NOW() 
        WHERE id = $5`,
        [
          paymentResult.ltcAmount,
          paymentResult.exchangeRate,
          paymentResult.tx_hash || paymentResult.payout_hash || null,
          JSON.stringify(paymentResult),
          id
        ]
      );

      // Audit log
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'FAUCETPAY_PAYMENT_SUCCESS', 'withdrawal', $2, $3, $4)`,
        [
          req.admin.id, 
          id, 
          JSON.stringify({ 
            amount_brl: amountBRL, 
            ltc_amount: paymentResult.ltcAmount, 
            exchange_rate: paymentResult.exchangeRate,
            tx_hash: paymentResult.tx_hash 
          }),
          req.headers['x-forwarded-for'] || req.socket.remoteAddress
        ]
      );

      res.json({
        success: true,
        message: paymentResult.message,
        status: 'completed',
        tx_hash: paymentResult.tx_hash || paymentResult.payout_hash,
        payout_id: paymentResult.payout_id,
        balance_remaining: paymentResult.balance_remaining,
        ltc_amount: paymentResult.ltcAmount,
        exchange_rate: paymentResult.exchangeRate,
      });
    } else {
      // Payment failed - revert to PENDING
      await db.query(
        `UPDATE withdrawals SET status = 'PENDING', gateway_response = $1, updated_at = NOW() WHERE id = $2`,
        [JSON.stringify(paymentResult), id]
      );

      // Audit log
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'FAUCETPAY_PAYMENT_FAILED', 'withdrawal', $2, $3, $4)`,
        [
          req.admin.id, 
          id, 
          JSON.stringify({ error: paymentResult.message, errorCode: paymentResult.errorCode }),
          req.headers['x-forwarded-for'] || req.socket.remoteAddress
        ]
      );

      res.json({
        success: false,
        message: paymentResult.message || 'Falha no pagamento FaucetPay',
        status: 'failed',
      });
    }
  } catch (error) {
    // On any error, try to revert status to PENDING
    try {
      await db.query(
        `UPDATE withdrawals SET status = 'PENDING', updated_at = NOW() WHERE id = $1 AND status = 'PROCESSING'`,
        [req.params.id]
      );
    } catch (revertErr) {
      console.error('Failed to revert withdrawal status:', revertErr);
    }

    console.error('Process FaucetPay error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message || 'Falha ao processar pagamento FaucetPay',
      message: error.message || 'Erro de conexão com FaucetPay'
    });
  } finally {
    client.release();
  }
});

// GET /api/admin/faucetpay/balance - Check FaucetPay LTC balance
router.get('/faucetpay/balance', authenticateAdmin, async (req, res) => {
  try {
    const balance = await faucetpay.getBalance();
    const rate = await faucetpay.getLtcBrlRate();
    
    res.json({
      success: true,
      balance: balance.balance,
      balanceSatoshi: balance.balanceSatoshi,
      currency: 'LTC',
      ltcBrlRate: rate,
      balanceBRL: (balance.balance * rate).toFixed(2),
    });
  } catch (error) {
    console.error('FaucetPay balance error:', error);
    res.status(500).json({ error: error.message || 'Falha ao consultar saldo FaucetPay' });
  }
});

// GET /api/admin/faucetpay/rate - Get current LTC/BRL exchange rate
router.get('/faucetpay/rate', authenticateAdmin, async (req, res) => {
  try {
    const rate = await faucetpay.getLtcBrlRate();
    const ltcPerReal = 1 / rate;
    
    res.json({
      success: true,
      ltcBrlRate: rate,
      ltcPerReal: parseFloat(ltcPerReal.toFixed(8)),
      example: `R$ 1,00 = ${ltcPerReal.toFixed(8)} LTC`,
    });
  } catch (error) {
    console.error('LTC rate error:', error);
    res.status(500).json({ error: error.message || 'Falha ao obter cotação' });
  }
});

// GET /api/admin/stats - Dashboard stats
router.get('/stats', authenticateAdmin, async (req, res) => {
  try {
    const userCount = await db.query('SELECT COUNT(*) as count FROM users WHERE is_active = true');
    const withdrawalStats = await db.query(
      `SELECT status, COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM withdrawals GROUP BY status`
    );
    const destStats = await db.query(
      `SELECT status, COUNT(*) as count FROM payout_destinations WHERE is_active = true GROUP BY status`
    );
    const todayRewards = await db.query(
      `SELECT COUNT(*) as count, COALESCE(SUM(points_awarded), 0) as total 
       FROM reward_events WHERE created_at > NOW() - INTERVAL '24 hours'`
    );

    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(userCount.rows[0].count),
        withdrawals: withdrawalStats.rows,
        payoutDestinations: destStats.rows,
        todayRewards: {
          count: parseInt(todayRewards.rows[0].count),
          totalPoints: parseInt(todayRewards.rows[0].total)
        }
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// GET /api/admin/users - List users
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;
    const search = req.query.search || '';

    let query = `SELECT u.id, u.email, u.device_id, u.ip_address, u.app_version, u.is_active, u.is_banned, 
                        u.created_at, u.last_login_at, u.fraud_score, u.last_fraud_at, u.ban_reason,
                        COALESCE(SUM(pl.amount), 0) as balance
                 FROM users u
                 LEFT JOIN points_ledger pl ON pl.user_id = u.id`;
    
    const params = [];
    if (search) {
      query += ` WHERE u.email ILIKE $1`;
      params.push(`%${search}%`);
    }
    
    query += ` GROUP BY u.id ORDER BY u.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await db.query(query, params);

    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// POST /api/admin/users/:id/points - Update user points (add, subtract, or set)
router.post('/users/:id/points', authenticateAdmin, async (req, res) => {
  const client = await db.getClient();
  
  try {
    const { id } = req.params;
    const { amount, operation, reason } = req.body;
    // operation: 'add', 'subtract', 'set'
    // amount: number of points
    // reason: optional description

    if (!amount || !Number.isFinite(Number(amount)) || Number(amount) < 0) {
      return res.status(400).json({ error: 'Valor de pontos inválido' });
    }

    const op = operation || 'set';
    if (!['add', 'subtract', 'set'].includes(op)) {
      return res.status(400).json({ error: 'Operação deve ser: add, subtract ou set' });
    }

    // Verify user exists
    const userResult = await db.query('SELECT id, email FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    await client.query('BEGIN');

    // Get current balance
    const balanceResult = await client.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [id]
    );
    const currentBalance = parseInt(balanceResult.rows[0].balance);

    let pointsToCredit = 0;
    let description = '';

    switch (op) {
      case 'add':
        pointsToCredit = Number(amount);
        description = reason || `Admin: +${pointsToCredit} pontos adicionados`;
        break;
      case 'subtract':
        pointsToCredit = -Number(amount);
        description = reason || `Admin: -${Math.abs(pointsToCredit)} pontos removidos`;
        break;
      case 'set':
        pointsToCredit = Number(amount) - currentBalance;
        description = reason || `Admin: saldo definido para ${Number(amount)} pontos`;
        break;
    }

    if (pointsToCredit !== 0) {
      const ledgerId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
         VALUES ($1, $2, $3, 'ADMIN_ADJUSTMENT', $4)`,
        [ledgerId, id, pointsToCredit, description]
      );
    }

    // Get new balance
    const newBalanceResult = await client.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [id]
    );
    const newBalance = parseInt(newBalanceResult.rows[0].balance);

    // Audit log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', 'UPDATE_USER_POINTS', 'user', $2, $3, $4, $5)`,
      [
        req.admin.id,
        id,
        JSON.stringify({ balance: currentBalance }),
        JSON.stringify({ balance: newBalance, operation: op, amount: Number(amount), reason }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: `Pontos atualizados com sucesso`,
      user: {
        id: user.id,
        email: user.email,
        previousBalance: currentBalance,
        newBalance,
        operation: op,
        amount: Number(amount)
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Update user points error:', error);
    res.status(500).json({ error: 'Falha ao atualizar pontos do usuário' });
  } finally {
    client.release();
  }
});

// POST /api/admin/users/:id/ban - Ban/unban user
router.post('/users/:id/ban', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { banned, reason } = req.body;

    const userResult = await db.query('SELECT id, email, is_banned FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    if (banned) {
      await db.query(
        'UPDATE users SET is_banned = true, ban_reason = $1, banned_at = NOW(), banned_by = $2, updated_at = NOW() WHERE id = $3',
        [reason || null, req.admin.id, id]
      );
      // Invalidate tokens so user is forced to re-login (and will be blocked)
      await db.query('UPDATE users SET token = NULL, refresh_token = NULL WHERE id = $1', [id]);
    } else {
      await db.query(
        'UPDATE users SET is_banned = false, ban_reason = NULL, banned_at = NULL, banned_by = NULL, updated_at = NOW() WHERE id = $1',
        [id]
      );
    }

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', $2, 'user', $3, $4, $5)`,
      [
        req.admin.id,
        banned ? 'USER_BANNED' : 'USER_UNBANNED',
        id,
        JSON.stringify({ banned: !!banned, reason }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    res.json({ success: true, message: banned ? 'Usuário banido' : 'Usuário desbanido' });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ error: 'Falha ao banir/desbanir usuário' });
  }
});

// ============ PIX ACCOUNTS MANAGEMENT ============

// GET /api/admin/pix-accounts - List PIX accounts
router.get('/pix-accounts', authenticateAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'PENDING';
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT pa.id, pa.user_id, pa.cpf, pa.full_name, pa.pix_key_type, pa.pix_key_value, pa.pix_key_masked,
              pa.status, pa.submitted_at, pa.reviewed_at, pa.rejection_reason,
              u.email as user_email, u.device_id, u.ip_address, u.created_at as user_created_at
       FROM pix_accounts pa
       JOIN users u ON u.id = pa.user_id
       WHERE pa.status = $1 AND pa.is_active = true
       ORDER BY pa.submitted_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM pix_accounts WHERE status = $1 AND is_active = true',
      [status]
    );

    // Stats
    const stats = await db.query(
      `SELECT status, COUNT(*) as count FROM pix_accounts WHERE is_active = true GROUP BY status`
    );

    const statsObj = { PENDING: 0, APPROVED: 0, REJECTED: 0, REVOKED: 0 };
    stats.rows.forEach(row => { statsObj[row.status] = parseInt(row.count); });

    res.json({
      success: true,
      accounts: result.rows,
      stats: statsObj,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('List PIX accounts error:', error);
    res.status(500).json({ error: 'Falha ao listar contas PIX' });
  }
});

// POST /api/admin/pix-accounts/:id/review - Approve or reject PIX account
router.post('/pix-accounts/:id/review', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, reason } = req.body;

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Ação deve ser "approve" ou "reject"' });
    }

    if (action === 'reject' && !reason) {
      return res.status(400).json({ error: 'Motivo da rejeição é obrigatório' });
    }

    const pix = await db.query(
      'SELECT id, user_id, status, pix_key_masked FROM pix_accounts WHERE id = $1',
      [id]
    );

    if (pix.rows.length === 0) {
      return res.status(404).json({ error: 'Conta PIX não encontrada' });
    }

    if (pix.rows[0].status !== 'PENDING') {
      return res.status(400).json({ error: `Não é possível revisar conta com status: ${pix.rows[0].status}` });
    }

    const newStatus = action === 'approve' ? 'APPROVED' : 'REJECTED';

    await db.query(
      `UPDATE pix_accounts SET status = $1, reviewed_at = NOW(), reviewed_by = $2, 
       rejection_reason = $3, updated_at = NOW() WHERE id = $4`,
      [newStatus, req.admin.id, action === 'reject' ? reason : null, id]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', $2, 'pix_account', $3, $4, $5, $6)`,
      [
        req.admin.id,
        `PIX_ACCOUNT_${newStatus}`,
        id,
        JSON.stringify({ status: 'PENDING' }),
        JSON.stringify({ status: newStatus, reason: reason || null }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    res.json({
      success: true,
      message: `Conta PIX ${action === 'approve' ? 'aprovada' : 'rejeitada'} com sucesso`,
      account: { id, status: newStatus }
    });
  } catch (error) {
    console.error('Review PIX account error:', error);
    res.status(500).json({ error: 'Falha ao revisar conta PIX' });
  }
});

// ============ PIX WITHDRAWALS (MANUAL) ============

// POST /api/admin/withdrawals/:id/mark-paid - Mark PIX withdrawal as paid (manual)
router.post('/withdrawals/:id/mark-paid', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { tx_reference } = req.body;

    const withdrawal = await db.query(
      'SELECT id, user_id, status, amount, payment_method FROM withdrawals WHERE id = $1',
      [id]
    );

    if (withdrawal.rows.length === 0) {
      return res.status(404).json({ error: 'Saque não encontrado' });
    }

    const w = withdrawal.rows[0];

    if (!['PENDING', 'APPROVED'].includes(w.status)) {
      return res.status(400).json({ error: `Não é possível marcar como pago saque com status: ${w.status}` });
    }

    await db.query(
      `UPDATE withdrawals SET status = 'PAID', tx_hash = $1, processed_at = NOW(), 
       approved_by = $2, approved_at = NOW(), updated_at = NOW() WHERE id = $3`,
      [tx_reference || 'PIX_MANUAL', req.admin.id, id]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'WITHDRAWAL_MARKED_PAID', 'withdrawal', $2, $3, $4)`,
      [
        req.admin.id, id,
        JSON.stringify({ amount: w.amount, payment_method: w.payment_method, tx_reference }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    res.json({
      success: true,
      message: 'Saque marcado como pago com sucesso'
    });
  } catch (error) {
    console.error('Mark paid error:', error);
    res.status(500).json({ error: 'Falha ao marcar saque como pago' });
  }
});

// ============ USER MANAGEMENT (EDIT DATA) ============

// PUT /api/admin/users/:id - Edit user data
router.put('/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, is_active } = req.body;

    const userResult = await db.query('SELECT id, email, is_active FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const oldData = userResult.rows[0];
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (email !== undefined && email !== oldData.email) {
      updates.push(`email = $${paramIndex}`);
      values.push(email.toLowerCase().trim());
      paramIndex++;
    }

    if (is_active !== undefined && is_active !== oldData.is_active) {
      updates.push(`is_active = $${paramIndex}`);
      values.push(!!is_active);
      paramIndex++;
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nenhuma alteração fornecida' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    await db.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
      values
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', 'USER_DATA_UPDATED', 'user', $2, $3, $4, $5)`,
      [
        req.admin.id,
        id,
        JSON.stringify({ email: oldData.email, is_active: oldData.is_active }),
        JSON.stringify({ email: email || oldData.email, is_active: is_active !== undefined ? is_active : oldData.is_active }),
        req.headers['x-forwarded-for'] || req.socket.remoteAddress
      ]
    );

    res.json({
      success: true,
      message: 'Dados do usuário atualizados com sucesso'
    });
  } catch (error) {
    console.error('Edit user error:', error);
    if (error.code === '23505') {
      return res.status(409).json({ error: 'E-mail já está em uso por outro usuário' });
    }
    res.status(500).json({ error: 'Falha ao editar dados do usuário' });
  }
});

module.exports = router;
