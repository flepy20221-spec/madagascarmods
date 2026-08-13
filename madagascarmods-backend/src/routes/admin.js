const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateAdmin, requireRole, JWT_SECRET } = require('../middleware/auth');
const { adminLoginLimiter } = require('../middleware/rateLimits');
const { decrypt } = require('../utils/crypto');
const faucetpay = require('../utils/faucetpay');
const asaas = require('../utils/asaas');
const { UserMergeError, mergeUserAccounts } = require('../services/userMerge');
// IP real do cliente atras do proxy. Padroniza o registro em audit_log: antes cada
// ponto usava req.headers['x-forwarded-for'] diretamente, gravando a lista inteira
// ("ip1, ip2, ip3") quando havia mais de um salto, o que inutiliza o campo para
// investigacao e para qualquer filtro por IP no painel.
const { clientIp } = require('../middleware/antiFraud');

const router = express.Router();

/**
 * Extrai os dados da chave PIX do snapshot gravado em w.crypto_address.
 * Saques PIX gravam um JSON: { pix_account_id, cpf, full_name, pix_key_type, pix_key_value }.
 * Saques legados ou FaucetPay usam o campo como endereco de carteira (string).
 */
function parsePixData(cryptoAddress) {
  if (!cryptoAddress) return null;
  let parsed = null;
  try {
    parsed = typeof cryptoAddress === 'string' ? JSON.parse(cryptoAddress) : cryptoAddress;
  } catch (e) {
    return null; // nao e um snapshot PIX: e endereco de carteira FaucetPay
  }
  if (!parsed || !parsed.pix_key_value || !parsed.pix_key_type) return null;
  return {
    pixKeyValue: parsed.pix_key_value,
    pixKeyType: parsed.pix_key_type,
    holderName: parsed.full_name || null,
  };
}

// Registra tentativas de acesso administrativo negadas, para investigacao posterior.
async function logSecurityEvent(action, detail, req) {
  try {
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
       VALUES (NULL, 'system', $1, 'security', $2, $3)`,
      [action, JSON.stringify(detail), clientIp(req)]
    );
  } catch (e) {
    console.error('[Security] Falha ao registrar evento:', e.message);
  }
}

// POST /api/admin/login
// adminLoginLimiter: 5 tentativas por 15 min, contando apenas as que falham
// (skipSuccessfulRequests), para barrar forca bruta na senha do painel sem atrapalhar
// o admin legitimo. (auditoria VULN-10)
router.post('/login', adminLoginLimiter, async (req, res) => {
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
      await logSecurityEvent('ADMIN_LOGIN_FAILED', { email: adminUser.email }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: adminUser.id, email: adminUser.email, isAdmin: true, role: adminUser.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await logSecurityEvent('ADMIN_LOGIN_SUCCESS', { email: adminUser.email, role: adminUser.role }, req);

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

// POST /api/admin/setup - Initial admin setup
//
// ==========================================================================================
// CORRECAO DE SETUP ABERTO (auditoria VULN-08)
//
// A rota era publica e a unica barreira era "nenhum admin existe ainda". Isso cria uma
// corrida perigosa: em um banco novo, em um reset, ou se a tabela admin_users for esvaziada
// por qualquer motivo, o primeiro a chamar esta rota se torna super_admin do sistema —
// com poder de aprovar saques e ler CPF e chaves PIX.
//
// Agora exige o segredo ADMIN_SETUP_TOKEN, comparado em tempo constante. Se a variavel
// nao estiver definida, a rota fica permanentemente desativada (fail-closed): melhor
// exigir um deploy com a variavel do que deixar uma porta aberta.
// ==========================================================================================
router.post('/setup', adminLoginLimiter, async (req, res) => {
  try {
    const setupToken = process.env.ADMIN_SETUP_TOKEN;

    if (!setupToken || setupToken.length < 24) {
      await logSecurityEvent('ADMIN_SETUP_DISABLED_ATTEMPT', {}, req);
      return res.status(403).json({
        error: 'Setup desabilitado. Defina ADMIN_SETUP_TOKEN (min. 24 caracteres) no ambiente.',
        code: 'SETUP_DISABLED'
      });
    }

    const provided = req.headers['x-setup-token'] || req.body.setup_token || '';
    const a = Buffer.from(String(provided));
    const b = Buffer.from(setupToken);
    // timingSafeEqual exige buffers do mesmo tamanho; a checagem de length evita a excecao
    // e ao mesmo tempo nao vaza informacao util (o tamanho do token nao e segredo).
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      await logSecurityEvent('ADMIN_SETUP_INVALID_TOKEN', {}, req);
      return res.status(403).json({ error: 'Token de setup invalido', code: 'INVALID_SETUP_TOKEN' });
    }

    const existing = await db.query('SELECT COUNT(*) as count FROM admin_users');
    if (parseInt(existing.rows[0].count) > 0) {
      return res.status(403).json({ error: 'Admin already configured' });
    }

    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Senha forte obrigatoria para a conta mais poderosa do sistema.
    if (String(password).length < 12) {
      return res.status(400).json({
        error: 'A senha do administrador deve ter no minimo 12 caracteres',
        code: 'WEAK_PASSWORD'
      });
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
router.post('/payout-destinations/:id/review', authenticateAdmin, requireRole('support', 'finance'), async (req, res) => {
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
        clientIp(req)
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
//
// ==========================================================================================
// CORRECAO DE DUPLO PAGAMENTO (auditoria VULN-07)
//
// Comportamento anterior: SELECT sem lock -> checagem de status -> UPDATE -> sendPayment.
// Entre a leitura do status e a escrita havia uma janela aberta. Dois cliques rapidos no
// painel (ou duas abas, ou um retry do navegador) faziam as duas requisicoes lerem
// status = 'PENDING', ambas passarem na validacao e ambas chamarem faucetpay.sendPayment
// para o MESMO saque — enviando LTC duas vezes, com dinheiro real.
//
// Agravante: o cliente FaucetPay nao envia chave de idempotencia, portanto o provedor
// tambem nao deduplica. Nao havia nenhuma barreira em nenhuma camada.
//
// Agora a transicao PENDING -> PROCESSING acontece de forma atomica e condicional:
// o UPDATE ... WHERE status = 'PENDING' RETURNING so afeta linha se o saque ainda estiver
// pendente. A segunda requisicao concorrente recebe zero linhas e para antes de pagar.
// O status PROCESSING funciona como reserva: nenhuma outra rota o aceita como ponto de
// partida para um novo envio.
// ==========================================================================================
router.post('/withdrawals/:id/approve', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { id } = req.params;

    // Transicao atomica: reserva o saque para este admin.
    // Se outra requisicao chegou primeiro, esta retorna 0 linhas.
    const claimed = await db.query(
      `UPDATE withdrawals
          SET status = 'PROCESSING',
              approved_by = $1,
              approved_at = NOW(),
              updated_at = NOW()
        WHERE id = $2 AND status = 'PENDING'
        RETURNING id, user_id, status, amount, points_debited, crypto_address, crypto_currency`,
      [req.admin.id, id]
    );

    if (claimed.rows.length === 0) {
      // Distingue "nao existe" de "ja foi processado" para dar uma mensagem util ao admin.
      const current = await db.query('SELECT status FROM withdrawals WHERE id = $1', [id]);
      if (current.rows.length === 0) {
        return res.status(404).json({ error: 'Saque nao encontrado' });
      }
      return res.status(409).json({
        error: `Este saque ja esta sendo processado ou foi finalizado (status: ${current.rows[0].status}).`,
        code: 'ALREADY_PROCESSED',
        status: current.rows[0].status
      });
    }

    const w = claimed.rows[0];

    // Now process payment automatically.
    // Saques PIX pagam pela Asaas (transferencia para a chave PIX cadastrada);
    // saques FaucetPay continuam pelo fluxo LTC original.
    const amountBRL = parseFloat(w.amount);
    let paymentResult = null;
    let finalStatus = 'APPROVED';

    const isPix = w.payment_method === 'pix';
    const pixData = isPix ? parsePixData(w.crypto_address) : null;

    try {
      if (isPix && pixData) {
        paymentResult = await asaas.sendPixPayment({
          pixKeyValue: pixData.pixKeyValue,
          pixKeyType: pixData.pixKeyType,
          amountBRL,
          withdrawalId: id,
          holderName: pixData.holderName,
        });
      } else {
        paymentResult = await faucetpay.sendPayment({
          to: w.crypto_address,
          amountBRL: amountBRL,
          referralId: id,
        });
      }

      if (paymentResult.success) {
        // Pagamento confirmado: PROCESSING -> PAID
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
          WHERE id = $5 AND status = 'PROCESSING'`,
          [
            isPix ? paymentResult.value : paymentResult.ltcAmount,
            isPix ? null : paymentResult.exchangeRate,
            isPix ? (paymentResult.transferId || null) : (paymentResult.tx_hash || paymentResult.payout_hash || null),
            JSON.stringify(paymentResult),
            id
          ]
        );
      } else {
        // O provedor recusou de forma explicita (saldo insuficiente, chave invalida...).
        // Nao houve envio de valor, entao o saque volta para APPROVED e o admin pode
        // reprocessar por /process-faucetpay ou /process-pix, conforme o metodo.
        finalStatus = 'APPROVED';
        await db.query(
          `UPDATE withdrawals SET status = 'APPROVED', gateway_response = $1, updated_at = NOW()
            WHERE id = $2 AND status = 'PROCESSING'`,
          [JSON.stringify(paymentResult), id]
        );
      }
    } catch (payErr) {
      // ATENCAO: aqui a resposta do provedor e DESCONHECIDA (timeout, queda de conexao).
      // O pagamento pode ter sido efetivado sem que a confirmacao chegasse. Liberar o saque
      // para reprocessamento automatico neste estado e justamente o que causa pagamento em
      // duplicidade. Por isso o saque fica em PAYMENT_UNCONFIRMED, exigindo que o admin
      // confira o extrato do provedor (FaucetPay ou Asaas) antes de decidir.
      console.error('[Approve] Payment error:', payErr.message);
      finalStatus = 'PAYMENT_UNCONFIRMED';
      await db.query(
        `UPDATE withdrawals SET status = 'PAYMENT_UNCONFIRMED', gateway_response = $1, updated_at = NOW()
          WHERE id = $2 AND status = 'PROCESSING'`,
        [JSON.stringify({ error: payErr.message, requiresManualCheck: true }), id]
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
        clientIp(req)
      ]
    );

    if (finalStatus === 'PAID') {
      res.json({
        success: true,
        message: isPix
          ? `Saque aprovado e pago! R$ ${amountBRL.toFixed(2)} enviados via PIX (Asaas).`
          : `Saque aprovado e pago! ${paymentResult.ltcAmount} LTC enviado.`,
        status: 'PAID',
        ltcAmount: paymentResult.ltcAmount,
        exchangeRate: paymentResult.exchangeRate,
        pixValue: isPix ? paymentResult.value : null,
        transferId: isPix ? paymentResult.transferId : null,
        txHash: isPix ? paymentResult.transferId : (paymentResult.tx_hash || paymentResult.payout_hash)
      });
    } else if (finalStatus === 'PAYMENT_UNCONFIRMED') {
      res.json({
        success: false,
        message: `A conexao com o provedor de pagamento (${isPix ? 'Asaas' : 'FaucetPay'}) falhou e nao foi possivel confirmar o pagamento. ` +
                 `VERIFIQUE O EXTRATO DO PROVEDOR antes de reenviar: o valor pode ter sido pago. ` +
                 'O saque ficou marcado como PAYMENT_UNCONFIRMED.',
        status: 'PAYMENT_UNCONFIRMED',
        requiresManualCheck: true
      });
    } else {
      res.json({
        success: true,
        message: `Saque aprovado, mas o provedor de pagamento recusou (${isPix ? 'Asaas' : 'FaucetPay'}): ${paymentResult ? paymentResult.message : 'erro desconhecido'}. Use "${isPix ? 'Pagar via PIX' : 'Enviar FaucetPay'}" para tentar novamente.`,
        status: 'APPROVED',
        paymentError: paymentResult ? paymentResult.message : 'Erro de conexao'
      });
    }
  } catch (error) {
    console.error('Approve withdrawal error:', error);
    res.status(500).json({ error: 'Falha ao aprovar saque' });
  }
});

// POST /api/admin/withdrawals/:id/reject - Reject withdrawal
router.post('/withdrawals/:id/reject', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();
  
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason || String(reason).trim().length < 3) {
      return res.status(400).json({ error: 'Informe o motivo da rejeicao (min. 3 caracteres)' });
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

    // PAYMENT_UNCONFIRMED tambem pode ser rejeitado: e o caminho para quando o admin conferiu
    // o extrato e constatou que o pagamento NAO saiu, devolvendo os pontos ao usuario.
    if (!['PENDING', 'APPROVED', 'PAYMENT_UNCONFIRMED'].includes(withdrawal.rows[0].status)) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `Nao e possivel rejeitar saque com status: ${withdrawal.rows[0].status}`,
        code: 'INVALID_STATUS'
      });
    }

    // Update withdrawal status — condicional, para que apenas uma requisicao concorrente
    // consiga efetuar a rejeicao e, consequentemente, apenas um refund seja gerado.
    const rejected = await client.query(
      `UPDATE withdrawals SET status = 'REJECTED', rejection_reason = $1, updated_at = NOW()
        WHERE id = $2 AND status IN ('PENDING', 'APPROVED', 'PAYMENT_UNCONFIRMED')
        RETURNING id`,
      [reason, id]
    );

    if (rejected.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Saque ja processado por outra requisicao', code: 'ALREADY_PROCESSED' });
    }

    // Refund points.
    // Guarda de duplicidade: se ja existe um refund lancado para este saque, nao lanca outro.
    // Sem isso, duas rejeicoes (ou uma rejeicao apos um refund manual) creditariam os pontos
    // duas vezes, criando saldo do nada.
    const existingRefund = await client.query(
      `SELECT id FROM points_ledger
        WHERE reference_id = $1 AND transaction_type = 'WITHDRAWAL_REFUND'`,
      [id]
    );

    if (existingRefund.rows.length === 0) {
      const refundId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, $3, 'WITHDRAWAL_REFUND', $4, 'Withdrawal rejected - points refunded')`,
        [refundId, withdrawal.rows[0].user_id, withdrawal.rows[0].points_debited, id]
      );
    } else {
      console.warn(`[Reject] Refund ja existia para o saque ${id}; nao foi lancado novamente.`);
    }

    // Audit log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'WITHDRAWAL_REJECTED', 'withdrawal', $2, $3, $4)`,
      [req.admin.id, id, JSON.stringify({ reason, points_refunded: withdrawal.rows[0].points_debited }), clientIp(req)]
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
router.post('/withdrawals/:id/process-faucetpay', authenticateAdmin, requireRole('finance'), async (req, res) => {
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

    // PAYMENT_UNCONFIRMED foi deliberadamente deixado fora desta lista: nesse estado o
    // pagamento pode ja ter sido efetivado do lado da FaucetPay, e reenviar sem conferir
    // o extrato e exatamente o que gera pagamento em duplicidade. A saida desse estado e
    // pela rota mark-paid (confirmando) ou reject (confirmando que nao houve envio).
    if (!['PENDING', 'APPROVED'].includes(w.status)) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: w.status === 'PAYMENT_UNCONFIRMED'
          ? 'Este saque teve um envio sem confirmacao. Verifique o extrato da FaucetPay: se o pagamento saiu, use "Marcar como pago"; se nao saiu, rejeite e refaca.'
          : `Nao e possivel processar saque com status: ${w.status}`,
        code: 'INVALID_STATUS',
        status: w.status
      });
    }

    // Mark as processing.
    // O FOR UPDATE acima ja serializa o acesso a linha, e a condicao de status torna a
    // transicao idempotente: uma segunda requisicao concorrente encontra PROCESSING e para.
    const claimed = await client.query(
      `UPDATE withdrawals SET status = 'PROCESSING', updated_at = NOW()
        WHERE id = $1 AND status IN ('PENDING', 'APPROVED')
        RETURNING id`,
      [id]
    );

    if (claimed.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este saque ja esta sendo processado por outra requisicao',
        code: 'ALREADY_PROCESSING'
      });
    }

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
        WHERE id = $5 AND status = 'PROCESSING'`,
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
          clientIp(req)
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
      // Recusa explicita do provedor: nao houve envio de valor, pode voltar para PENDING.
      await db.query(
        `UPDATE withdrawals SET status = 'PENDING', gateway_response = $1, updated_at = NOW()
          WHERE id = $2 AND status = 'PROCESSING'`,
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
          clientIp(req)
        ]
      );

      res.json({
        success: false,
        message: paymentResult.message || 'Falha no pagamento FaucetPay',
        status: 'failed',
      });
    }
  } catch (error) {
    // ATENCAO: o comportamento anterior era devolver o saque para PENDING aqui.
    // Isso e perigoso: uma excecao neste ponto normalmente e timeout ou queda de conexao,
    // situacao em que NAO se sabe se a FaucetPay executou o pagamento. Voltando para
    // PENDING, o saque reaparecia na fila e um novo envio pagava de novo o mesmo valor.
    //
    // Agora o saque fica em PAYMENT_UNCONFIRMED e sai da fila automatica, exigindo que um
    // humano confira o extrato. Perder alguns minutos de conferencia e melhor que pagar duas vezes.
    try {
      await db.query(
        `UPDATE withdrawals SET status = 'PAYMENT_UNCONFIRMED',
                gateway_response = $2, updated_at = NOW()
          WHERE id = $1 AND status = 'PROCESSING'`,
        [req.params.id, JSON.stringify({ error: error.message, requiresManualCheck: true })]
      );
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'FAUCETPAY_PAYMENT_UNCONFIRMED', 'withdrawal', $2, $3, $4)`,
        [req.admin.id, req.params.id,
         JSON.stringify({ error: error.message, requiresManualCheck: true }),
         clientIp(req)]
      );
    } catch (revertErr) {
      console.error('Failed to mark withdrawal as unconfirmed:', revertErr);
    }

    console.error('Process FaucetPay error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Erro de comunicacao com a FaucetPay',
      message: 'Nao foi possivel confirmar o pagamento. O saque foi marcado como PAYMENT_UNCONFIRMED. ' +
               'VERIFIQUE O EXTRATO DA FAUCETPAY antes de reenviar.',
      requiresManualCheck: true
    });
  } finally {
    client.release();
  }
});

// POST /api/admin/withdrawals/:id/process-pix - Process PIX payment via Asaas
//
// Mesma disciplina anti-duplicidade de /process-faucetpay (VULN-07): a transicao
// PENDING/APPROVED -> PROCESSING e atomica e condicional, e o status PROCESSING
// bloqueia qualquer novo envio. Erro de rede vira PAYMENT_UNCONFIRMED em vez de
// liberar o saque para reprocessamento automatico (pagamento em duplicidade).
router.post('/withdrawals/:id/process-pix', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();

  try {
    const { id } = req.params;

    await client.query('BEGIN');

    const withdrawal = await client.query(
      `SELECT w.id, w.user_id, w.status, w.amount, w.payment_method, w.crypto_address,
              w.idempotency_key, w.ledger_reservation_id
       FROM withdrawals w WHERE w.id = $1 FOR UPDATE`,
      [id]
    );

    if (withdrawal.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Saque nao encontrado' });
    }

    const w = withdrawal.rows[0];

    if (w.payment_method !== 'pix') {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este saque nao e via PIX; use a rota correspondente ao metodo de pagamento.',
        code: 'INVALID_PAYMENT_METHOD',
        payment_method: w.payment_method
      });
    }

    if (!['PENDING', 'APPROVED'].includes(w.status)) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: w.status === 'PAYMENT_UNCONFIRMED'
          ? 'Este saque teve um envio sem confirmacao. Verifique o extrato da Asaas: se o pagamento saiu, use "Marcar como pago"; se nao saiu, rejeite e refaca.'
          : `Nao e possivel processar saque com status: ${w.status}`,
        code: 'INVALID_STATUS',
        status: w.status
      });
    }

    const claimed = await client.query(
      `UPDATE withdrawals SET status = 'PROCESSING', updated_at = NOW()
        WHERE id = $1 AND status IN ('PENDING', 'APPROVED')
        RETURNING id`,
      [id]
    );

    if (claimed.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Este saque ja esta sendo processado por outra requisicao',
        code: 'ALREADY_PROCESSING'
      });
    }

    await client.query('COMMIT');

    const pixData = parsePixData(w.crypto_address);
    if (!pixData) {
      await db.query(
        `UPDATE withdrawals SET status = 'PENDING', gateway_response = $1, updated_at = NOW()
          WHERE id = $2 AND status = 'PROCESSING'`,
        [JSON.stringify({ error: 'Dados da chave PIX ausentes no saque', requiresManualCheck: true }), id]
      );
      return res.status(400).json({
        success: false,
        message: 'Dados da chave PIX ausentes no saque. Verifique a conta PIX do usuario.',
        status: 'failed'
      });
    }

    const amountBRL = parseFloat(w.amount);
    const paymentResult = await asaas.sendPixPayment({
      pixKeyValue: pixData.pixKeyValue,
      pixKeyType: pixData.pixKeyType,
      amountBRL,
      withdrawalId: id,
      holderName: pixData.holderName,
    });

    if (paymentResult.success) {
      await db.query(
        `UPDATE withdrawals SET
          status = 'PAID',
          crypto_amount = $1,
          tx_hash = $2,
          gateway_response = $3,
          processed_at = NOW(),
          updated_at = NOW()
        WHERE id = $4 AND status = 'PROCESSING'`,
        [paymentResult.value, paymentResult.transferId || null, JSON.stringify(paymentResult), id]
      );

      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'ASAAS_PIX_PAYMENT_SUCCESS', 'withdrawal', $2, $3, $4)`,
        [
          req.admin.id,
          id,
          JSON.stringify({ amount_brl: amountBRL, transfer_id: paymentResult.transferId, pix_key_type: pixData.pixKeyType }),
          clientIp(req)
        ]
      );

      res.json({
        success: true,
        message: paymentResult.message,
        status: 'completed',
        transfer_id: paymentResult.transferId,
        pix_value: paymentResult.value,
      });
    } else {
      // Recusa explicita do provedor: nao houve envio de valor, volta para PENDING.
      await db.query(
        `UPDATE withdrawals SET status = 'PENDING', gateway_response = $1, updated_at = NOW()
          WHERE id = $2 AND status = 'PROCESSING'`,
        [JSON.stringify(paymentResult), id]
      );

      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'ASAAS_PIX_PAYMENT_FAILED', 'withdrawal', $2, $3, $4)`,
        [
          req.admin.id,
          id,
          JSON.stringify({ error: paymentResult.message, errorCode: paymentResult.errorCode }),
          clientIp(req)
        ]
      );

      res.json({
        success: false,
        message: paymentResult.message || 'Falha no pagamento PIX (Asaas)',
        status: 'failed',
      });
    }
  } catch (error) {
    // Erro de rede/timeout: nao se sabe se a Asaas processou a transferencia.
    // O saque fica em PAYMENT_UNCONFIRMED, exigindo conferencia do extrato.
    try {
      await db.query(
        `UPDATE withdrawals SET status = 'PAYMENT_UNCONFIRMED',
                gateway_response = $2, updated_at = NOW()
          WHERE id = $1 AND status = 'PROCESSING'`,
        [req.params.id, JSON.stringify({ error: error.message, requiresManualCheck: true })]
      );
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ($1, 'admin', 'ASAAS_PIX_PAYMENT_UNCONFIRMED', 'withdrawal', $2, $3, $4)`,
        [req.admin.id, req.params.id,
         JSON.stringify({ error: error.message, requiresManualCheck: true }),
         clientIp(req)]
      );
    } catch (revertErr) {
      console.error('Failed to mark withdrawal as unconfirmed:', revertErr);
    }

    console.error('Process PIX error:', error);
    res.status(500).json({
      success: false,
      error: 'Erro de comunicacao com a Asaas',
      message: 'Nao foi possivel confirmar o pagamento. O saque foi marcado como PAYMENT_UNCONFIRMED. ' +
               'VERIFIQUE O EXTRATO DA ASAAS antes de reenviar.',
      requiresManualCheck: true
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

// GET /api/admin/asaas/balance - Check Asaas balance
// GET /api/admin/users/activity - Atividade dos usuarios do app (agregado).
// - activeToday: usuarios distintos com last_login_at nas ultimas 24h (quem
//   entrou no app hoje).
// - onlineNow: usuarios distintos com last_login_at nos ultimos 15 minutos
//   (proxy de "online agora", ja que o app nao expoe heartbeat persistente).
// - lastHour: usuarios distintos que entraram na ultima hora.
// - active7d: usuarios distintos com acesso nos ultimos 7 dias.
// A coluna users.last_login_at e atualizada em todos os caminhos de login do
// app (auth.js), incluindo o primeiro acesso apos reinstalacao.
router.get('/users/activity', authenticateAdmin, async (req, res) => {
  try {
    const [today, lastHour, quarterHour, last7d, total] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS n FROM users WHERE last_login_at > NOW() - INTERVAL '24 hours'`),
      db.query(`SELECT COUNT(*)::int AS n FROM users WHERE last_login_at > NOW() - INTERVAL '1 hour'`),
      db.query(`SELECT COUNT(*)::int AS n FROM users WHERE last_login_at > NOW() - INTERVAL '15 minutes'`),
      db.query(`SELECT COUNT(*)::int AS n FROM users WHERE last_login_at > NOW() - INTERVAL '7 days'`),
      db.query(`SELECT COUNT(*)::int AS n FROM users`),
    ]);
    res.json({
      success: true,
      activity: {
        activeToday: today.rows[0].n,
        lastHour: lastHour.rows[0].n,
        onlineNow: quarterHour.rows[0].n,
        active7d: last7d.rows[0].n,
        totalUsers: total.rows[0].n,
      },
    });
  } catch (error) {
    console.error('Users activity error:', error);
    res.status(500).json({ error: 'Erro ao consultar atividade dos usuarios' });
  }
});

// GET /api/admin/withdrawals/report - Relatorio de saques por periodo.
// Query params:
//   from / to     - intervalo de datas (YYYY-MM-DD, inclusive; default: ultimos 30 dias)
//   status       - status ou comma-separated (ex: PAID,REJECTED; default: todos)
//   method       - payment_method ou comma-separated (ex: pix,faucetpay; default: todos)
// Retorno:
//   period      - intervalo aplicado
//   totals      - total geral (count, amount BRL)
//   byMethod    - soma e quantidade por payment_method
//   byStatus    - soma e quantidade por status
//   byDay       - distribuicao diaria (dia, count, amount)
//   detail      - lista paginada dos saques do periodo (para exportacao)
router.get('/withdrawals/report', authenticateAdmin, async (req, res) => {
  try {
    // -------------------------------------------------------------
    // Parse do intervalo. Fuso de Brasilia (UTC-3): o dia em BRT
    // equivale a [dia 00:00-3] .. [dia+1 00:00-3] em UTC. Usar a
    // aritmetica de DATE (sem tz) do Postgres, que opera na tz da
    // sessao; forcar a sessao para America/Sao_Paulo antes.
    // -------------------------------------------------------------
    const today = new Date();
    const fmtDate = (d) => d.toISOString().slice(0, 10);
    let fromDate = req.query.from;
    let toDate = req.query.to;
    if (!fromDate) {
      const start = new Date(today);
      start.setDate(start.getDate() - 29);
      fromDate = fmtDate(start);
    }
    if (!toDate) toDate = fmtDate(today);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fromDate) || !/^\d{4}-\d{2}-\d{2}$/.test(toDate)) {
      return res.status(400).json({ error: 'Datas devem estar no formato YYYY-MM-DD' });
    }
    const statusList = String(req.query.status || '').split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
    const methodList = String(req.query.method || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

    const params = [fromDate, toDate];
    let where = `WHERE w.created_at::date >= $1::date AND w.created_at::date <= $2::date`;
    if (statusList.length > 0) {
      params.push(statusList);
      where += ` AND w.status = ANY($${params.length}::text[])`;
    }
    if (methodList.length > 0) {
      params.push(methodList);
      where += ` AND w.payment_method = ANY($${params.length}::text[])`;
    }

    const setTz = await db.query(`SET LOCAL TimeZone = 'America/Sao_Paulo'`);

    const [totals, byMethod, byStatus, byDay] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS count, COALESCE(SUM(amount), 0)::float AS amount
                FROM withdrawals w ${where}`,
        params.slice(1)),
      db.query(`SELECT w.payment_method AS method, COUNT(*)::int AS count,
                       COALESCE(SUM(w.amount), 0)::float AS amount
                FROM withdrawals w ${where}
                GROUP BY w.payment_method ORDER BY amount DESC`,
        params.slice(1)),
      db.query(`SELECT w.status, COUNT(*)::int AS count,
                       COALESCE(SUM(w.amount), 0)::float AS amount
                FROM withdrawals w ${where}
                GROUP BY w.status ORDER BY count DESC`,
        params.slice(1)),
      db.query(`SELECT w.created_at::date AS day, COUNT(*)::int AS count,
                       COALESCE(SUM(w.amount), 0)::float AS amount
                FROM withdrawals w ${where}
                GROUP BY w.created_at::date ORDER BY day DESC`,
        params.slice(1)),
    ]);

    res.json({
      success: true,
      report: {
        period: { from: fromDate, to: toDate },
        totals: {
          count: totals.rows[0].count,
          amount: totals.rows[0].amount,
        },
        byMethod: byMethod.rows,
        byStatus: byStatus.rows,
        byDay: byDay.rows,
      },
    });
  } catch (error) {
    console.error('Withdrawals report error:', error);
    res.status(500).json({ error: 'Erro ao gerar relatorio de saques' });
  }
});

// GET /api/admin/withdrawals/report/csv - Exportacao CSV do mesmo relatorio.
// Aceita os mesmos parametros (from, to, status, method) e retorna texto/csv.
router.get('/withdrawals/report/csv', authenticateAdmin, async (req, res) => {
  try {
    const today = new Date();
    const fmtDate = (d) => d.toISOString().slice(0, 10);
    let fromDate = req.query.from;
    let toDate = req.query.to;
    if (!fromDate) {
      const start = new Date(today);
      start.setDate(start.getDate() - 29);
      fromDate = fmtDate(start);
    }
    if (!toDate) toDate = fmtDate(today);
    const statusList = String(req.query.status || '').split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
    const methodList = String(req.query.method || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

    const params = [fromDate, toDate];
    let where = `WHERE w.created_at::date >= $1::date AND w.created_at::date <= $2::date`;
    if (statusList.length > 0) {
      params.push(statusList);
      where += ` AND w.status = ANY($${params.length}::text[])`;
    }
    if (methodList.length > 0) {
      params.push(methodList);
      where += ` AND w.payment_method = ANY($${params.length}::text[])`;
    }

    await db.query(`SET LOCAL TimeZone = 'America/Sao_Paulo'`);

    const detail = await db.query(
      `SELECT w.created_at AT TIME ZONE 'America/Sao_Paulo' AS created_at_br,
              w.amount, w.points_debited, w.payment_method, w.status, w.tx_hash,
              u.email AS user_email, u.support_code
         FROM withdrawals w
         JOIN users u ON u.id = w.user_id
         ${where}
         ORDER BY w.created_at DESC`,
      params.slice(1),
    );

    const esc = (v) => {
      if (v === null || v === undefined) return '';
      const s = String(v);
      return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = 'data_hora_br;usuario;support_code;valor_brl;pontos;metodo;status;tx_hash\n';
    const rows = detail.rows
      .map((r) =>
        [
          new Date(r.created_at_br).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
          r.user_email,
          r.support_code,
          r.amount.toString(),
          r.points_debited,
          r.payment_method,
          r.status,
          r.tx_hash,
        ].map(esc).join(';'),
      )
      .join('\n');

    const bom = '\uFEFF'; // Excel abre UTF-8 corretamente
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="saques-${fromDate}-a-${toDate}.csv"`);
    res.send(bom + header + (rows ? rows + '\n' : ''));
  } catch (error) {
    console.error('Withdrawals report csv error:', error);
    res.status(500).json({ error: 'Erro ao exportar relatorio' });
  }
});

router.get('/asaas/balance', authenticateAdmin, async (req, res) => {
  try {
    const balance = await asaas.getBalance();
    res.json({
      success: balance.success,
      balance: balance.balance ?? null,
      balanceFormatted: balance.balanceFormatted ?? null,
      message: balance.success ? undefined : balance.message,
    });
  } catch (error) {
    console.error('Asaas balance error:', error);
    res.status(500).json({ error: error.message || 'Falha ao consultar saldo Asaas' });
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
    const userCount = await db.query(
      'SELECT COUNT(*) as count FROM users WHERE is_active = true AND merged_into_user_id IS NULL'
    );
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

// GET /api/admin/users - List users with unified support search
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const offset = (page - 1) * limit;
    const search = String(req.query.search || '').trim().slice(0, 120);
    const status = String(req.query.status || 'all').toLowerCase();
    const appVersion = String(req.query.appVersion || '').trim().slice(0, 20);

    // ------------------------------------------------------------------------
    // A clausula WHERE e montada UMA vez e reaproveitada em duas consultas: a
    // pagina de resultados e os totais agregados. Manter as duas em sincronia e
    // obrigatorio, caso contrario os cards do painel passam a descrever um
    // conjunto diferente do que a tabela exibe.
    // ------------------------------------------------------------------------
    let where = ' WHERE u.merged_into_user_id IS NULL';

    const params = [];
    if (search) {
      params.push(`%${search}%`);
      const p = `$${params.length}`;
      where += ` AND (
        u.support_code ILIKE ${p}
        OR COALESCE(u.support_label, '') ILIKE ${p}
        OR u.email ILIKE ${p}
        OR u.id::text ILIKE ${p}
        OR COALESCE(u.device_id, '') ILIKE ${p}
        OR COALESCE(u.device_account_key, '') ILIKE ${p}
        OR COALESCE(u.device_model, '') ILIKE ${p}
        OR COALESCE(u.ip_address, '') ILIKE ${p}
        OR EXISTS (
          SELECT 1 FROM device_account_aliases alias
           WHERE alias.user_id = u.id
             AND alias.device_account_key ILIKE ${p}
        )
        OR EXISTS (
          SELECT 1 FROM payout_destinations pd
           WHERE pd.user_id = u.id
             AND COALESCE(pd.value_masked, '') ILIKE ${p}
        )
        OR EXISTS (
          SELECT 1 FROM pix_accounts pa
           WHERE pa.user_id = u.id
             AND (
               COALESCE(pa.full_name, '') ILIKE ${p}
               OR COALESCE(pa.pix_key_masked, '') ILIKE ${p}
             )
        )
      )`;
    }

    if (status === 'active') {
      where += ' AND u.is_active = true AND u.is_banned = false';
    } else if (status === 'banned') {
      where += ' AND u.is_banned = true';
    } else if (status === 'inactive') {
      where += ' AND u.is_active = false';
    }

    if (appVersion) {
      params.push(appVersion);
      where += ` AND u.app_version = $${params.length}`;
    }

    // O nome do titular da chave PIX entra apenas como AUXILIO DE IDENTIFICACAO
    // no painel. Antes, uma conta sem `support_label` — o que ocorre em toda a
    // base, porque o rotulo e manual e nunca foi preenchido — aparecia como
    // "Sem apelido de suporte" e so podia ser distinguida pelo UUID ou pelo
    // e-mail sintetico `device-<hash>@cashpix.local`, ilegivel para o operador.
    //
    // Nao sobrescreve `support_label`: aquele campo e curadoria manual do
    // suporte e continua tendo precedencia. Este e um campo derivado, somente
    // leitura, resolvido por consulta.
    //
    // O LATERAL com LIMIT 1 garante resultado estavel para o usuario que possui
    // mais de uma pix_account (existe um caso na base): prefere APPROVED e,
    // entre elas, a mais recente. Sem essa ordenacao explicita o nome exibido
    // oscilaria entre recargas da pagina. LEFT JOIN preserva as 375 contas sem
    // chave PIX, que continuam vindo com pix_holder_name nulo.
    const pageQuery = `SELECT u.id, u.support_code, u.support_label, u.email,
                              u.device_id, u.device_account_key, u.device_model,
                              u.ip_address, u.app_version, u.is_active, u.is_banned,
                              u.created_at, u.last_login_at, u.fraud_score,
                              u.last_fraud_at, u.ban_reason, balance.total AS balance,
                              pix.full_name AS pix_holder_name,
                              pix.status AS pix_holder_status
                         FROM users u
                         CROSS JOIN LATERAL (
                           SELECT COALESCE(SUM(pl.amount), 0) AS total
                             FROM points_ledger pl
                            WHERE pl.user_id = u.id
                         ) balance
                         LEFT JOIN LATERAL (
                           SELECT pa.full_name, pa.status
                             FROM pix_accounts pa
                            WHERE pa.user_id = u.id
                              AND COALESCE(pa.full_name, '') <> ''
                            ORDER BY (pa.status = 'APPROVED') DESC,
                                     pa.reviewed_at DESC NULLS LAST,
                                     pa.submitted_at DESC
                            LIMIT 1
                         ) pix ON TRUE
                         ${where}
                        ORDER BY u.last_login_at DESC NULLS LAST, u.created_at DESC
                        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;

    // Totais sobre a BASE INTEIRA que satisfaz os filtros, sem LIMIT/OFFSET.
    //
    // Motivo: o painel calculava os cards a partir do array recebido
    // (users.length e reduce sobre balance). Como a resposta vinha truncada em
    // 100 registros, "Usuarios listados" exibia o proprio teto de paginacao e
    // "Pontos em circulacao" somava apenas a primeira pagina, subestimando o
    // passivo em pontos do sistema. Agregar no banco elimina a dependencia do
    // tamanho da pagina.
    //
    // A soma de pontos usa um LEFT JOIN agregado em vez de repetir o
    // CROSS JOIN LATERAL por usuario: uma unica varredura de points_ledger
    // agrupada por user_id, em lugar de uma subconsulta por linha.
    const totalsQuery = `SELECT COUNT(*)::bigint AS total_users,
                                COUNT(*) FILTER (WHERE u.is_banned)::bigint AS banned_users,
                                COUNT(*) FILTER (WHERE u.is_active AND NOT u.is_banned)::bigint AS active_users,
                                COALESCE(SUM(balance.total), 0) AS total_points
                           FROM users u
                           LEFT JOIN (
                             SELECT pl.user_id, SUM(pl.amount) AS total
                               FROM points_ledger pl
                              GROUP BY pl.user_id
                           ) balance ON balance.user_id = u.id
                           ${where}`;

    const [result, totalsResult] = await Promise.all([
      db.query(pageQuery, [...params, limit, offset]),
      db.query(totalsQuery, params),
    ]);

    const totalsRow = totalsResult.rows[0] || {};
    const totalUsers = Number(totalsRow.total_users || 0);

    res.json({
      success: true,
      users: result.rows,
      // Refletem todos os usuarios que atendem aos filtros, nao apenas a pagina.
      totals: {
        users: totalUsers,
        banned: Number(totalsRow.banned_users || 0),
        active: Number(totalsRow.active_users || 0),
        points: String(totalsRow.total_points ?? '0'),
      },
      pagination: {
        page,
        limit,
        total: totalUsers,
        totalPages: Math.max(Math.ceil(totalUsers / limit), 1),
        // Derivado do total real: antes era inferido de rows.length === limit,
        // que reportava outra pagina inexistente quando o ultimo lote enchia
        // a pagina exatamente.
        hasMore: offset + result.rows.length < totalUsers,
      },
    });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ error: 'Falha ao listar usuarios' });
  }
});

// PATCH /api/admin/users/:id/support-label - internal human-readable label
router.patch('/users/:id/support-label', authenticateAdmin, requireRole('support'), async (req, res) => {
  try {
    const supportLabel = typeof req.body.supportLabel === 'string'
      ? req.body.supportLabel.trim().slice(0, 120)
      : '';

    const updated = await db.query(
      `UPDATE users
          SET support_label = NULLIF($1, ''), updated_at = NOW()
        WHERE id = $2
        RETURNING id, support_code, support_label`,
      [supportLabel, req.params.id]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    await db.query(
      `INSERT INTO audit_log (
         actor_id, actor_type, action, target_type, target_id, new_value, ip_address
       ) VALUES ($1, 'admin', 'USER_SUPPORT_LABEL_UPDATED', 'user', $2, $3, $4)`,
      [
        req.admin.id,
        req.params.id,
        JSON.stringify({ supportLabel: updated.rows[0].support_label }),
        clientIp(req),
      ]
    );

    res.json({ success: true, user: updated.rows[0] });
  } catch (error) {
    console.error('Update support label error:', error);
    res.status(500).json({ error: 'Falha ao atualizar o rotulo de suporte' });
  }
});

// POST /api/admin/users/:sourceId/merge - merge duplicate into canonical account
router.post('/users/:sourceId/merge', authenticateAdmin, requireRole('super_admin'), async (req, res) => {
  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const result = await mergeUserAccounts({
      client,
      sourceUserId: req.params.sourceId,
      targetUserId: req.body.targetUserId,
      adminId: req.admin.id,
      reason: req.body.reason,
      requestIp: clientIp(req),
      confirmSupportCode: req.body.confirmSupportCode,
    });

    await client.query('COMMIT');
    res.json({
      success: true,
      message: `Contas reconciliadas. A conta principal agora e ${result.target.support_code}.`,
      ...result,
    });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error instanceof UserMergeError) {
      return res.status(error.statusCode).json({ error: error.message, code: error.code });
    }
    console.error('Merge users error:', error);
    res.status(500).json({ error: 'Falha ao reconciliar as contas' });
  } finally {
    client.release();
  }
});

// POST /api/admin/users/:id/points - Update user points (add, subtract, or set)
//
// Esta rota cria saldo do nada, portanto e a mais sensivel do painel depois da aprovacao
// de saque: e o caminho direto para transformar pontos em dinheiro. Passa a exigir role
// 'finance' (ou super_admin) e um motivo escrito, sempre registrado em auditoria.
router.post('/users/:id/points', authenticateAdmin, requireRole('finance'), async (req, res) => {
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

    // Teto por operacao: limita o estrago de um erro de digitacao ou de uma sessao
    // administrativa roubada. Ajustes maiores devem ser feitos em etapas, deixando
    // varios registros de auditoria.
    const MAX_MANUAL_ADJUSTMENT = parseInt(process.env.MAX_MANUAL_POINTS_ADJUSTMENT || '500000', 10);
    if (Number(amount) > MAX_MANUAL_ADJUSTMENT) {
      await logSecurityEvent('ADMIN_POINTS_LIMIT_EXCEEDED',
        { adminId: req.admin.id, targetUser: id, amount: Number(amount) }, req);
      return res.status(400).json({
        error: `Ajuste manual acima do limite permitido (${MAX_MANUAL_ADJUSTMENT} pontos por operacao)`,
        code: 'ADJUSTMENT_TOO_LARGE'
      });
    }

    // Motivo obrigatorio: sem ele o log de auditoria nao permite reconstruir a intencao.
    if (!reason || String(reason).trim().length < 5) {
      return res.status(400).json({
        error: 'Informe um motivo com no minimo 5 caracteres para o ajuste manual',
        code: 'REASON_REQUIRED'
      });
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

    // Mesmo lock dos saques: impede que um ajuste manual rode em paralelo com um saque
    // do proprio usuario, o que poderia fazer o saque enxergar um saldo intermediario.
    await client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [8471, id]);

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
        clientIp(req)
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
router.post('/users/:id/ban', authenticateAdmin, requireRole('support', 'finance'), async (req, res) => {
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
        clientIp(req)
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
router.post('/pix-accounts/:id/review', authenticateAdmin, requireRole('support', 'finance'), async (req, res) => {
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
        clientIp(req)
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
//
// Transicao atomica (auditoria VULN-07). Antes: SELECT sem lock, checagem de status e
// UPDATE incondicional. Dois cliques marcavam o mesmo saque como pago duas vezes, gerando
// dois registros de auditoria e mascarando um possivel pagamento manual duplicado no PIX.
//
// PAYMENT_UNCONFIRMED e aceito aqui de proposito: e justamente o caminho para o admin
// confirmar, depois de conferir o extrato, que o pagamento realmente saiu.
router.post('/withdrawals/:id/mark-paid', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { tx_reference } = req.body;

    const claimed = await db.query(
      `UPDATE withdrawals
          SET status = 'PAID',
              tx_hash = $1,
              processed_at = NOW(),
              approved_by = $2,
              approved_at = COALESCE(approved_at, NOW()),
              updated_at = NOW()
        WHERE id = $3 AND status IN ('PENDING', 'APPROVED', 'PAYMENT_UNCONFIRMED')
        RETURNING id, user_id, amount, payment_method`,
      [tx_reference || 'PIX_MANUAL', req.admin.id, id]
    );

    if (claimed.rows.length === 0) {
      const current = await db.query('SELECT status FROM withdrawals WHERE id = $1', [id]);
      if (current.rows.length === 0) {
        return res.status(404).json({ error: 'Saque nao encontrado' });
      }
      return res.status(409).json({
        error: `Nao e possivel marcar como pago um saque com status: ${current.rows[0].status}`,
        code: 'INVALID_STATUS',
        status: current.rows[0].status
      });
    }

    const w = claimed.rows[0];

    // Audit log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'WITHDRAWAL_MARKED_PAID', 'withdrawal', $2, $3, $4)`,
      [
        req.admin.id, id,
        JSON.stringify({ amount: w.amount, payment_method: w.payment_method, tx_reference }),
        clientIp(req)
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
router.put('/users/:id', authenticateAdmin, requireRole('finance'), async (req, res) => {
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
        clientIp(req)
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

// POST /api/admin/users/:id/allow-device-change
//
// Valvula de escape operacional do vinculo de dispositivo (auditoria VULN-05).
//
// Como o login do app usa apenas o e-mail, a conta e protegida pelo vinculo ao aparelho:
// quem tenta entrar de um celular diferente e recusado quando a conta tem saldo. Isso
// impede o roubo de conta, mas cria um caso legitimo de suporte: o usuario que trocou de
// aparelho ou reinstalou o app (o device_id e regerado quando os dados sao apagados).
//
// Esta rota libera UMA troca. A flag e consumida no proximo login bem-sucedido, portanto
// uma liberacao esquecida nao deixa a conta desprotegida para sempre.
router.post('/users/:id/allow-device-change', authenticateAdmin, requireRole('support', 'finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!reason || String(reason).trim().length < 3) {
      return res.status(400).json({
        error: 'Informe o motivo da liberacao (min. 3 caracteres)',
        code: 'REASON_REQUIRED'
      });
    }

    const updated = await db.query(
      `UPDATE users SET device_migration_allowed = true, updated_at = NOW()
        WHERE id = $1
        RETURNING id, email, device_id`,
      [id]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'DEVICE_CHANGE_ALLOWED', 'user', $2, $3, $4)`,
      [
        req.admin.id,
        id,
        JSON.stringify({
          reason: String(reason).trim(),
          email: updated.rows[0].email,
          previous_device_id: updated.rows[0].device_id
        }),
        clientIp(req)
      ]
    );

    res.json({
      success: true,
      message: 'Troca de aparelho liberada. Valida para o proximo login do usuario.'
    });
  } catch (error) {
    console.error('Allow device change error:', error);
    res.status(500).json({ error: 'Falha ao liberar a troca de aparelho' });
  }
});

// ============ USER DETAIL ============

// GET /api/admin/users/:id - Get full user details
router.get('/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const userResult = await db.query(
      `SELECT u.id, u.support_code, u.support_label, u.email,
              u.device_id, u.device_account_key, u.device_model,
              u.ip_address, u.app_version, u.is_active, u.is_banned,
              u.ban_reason, u.banned_at, u.banned_by, u.fraud_score,
              u.last_fraud_at, u.device_migration_allowed,
              u.merged_into_user_id, u.merged_at,
              merged.support_code AS merged_into_support_code,
              u.created_at, u.updated_at, u.last_login_at,
              COALESCE(SUM(pl.amount), 0) as balance
       FROM users u
       LEFT JOIN users merged ON merged.id = u.merged_into_user_id
       LEFT JOIN points_ledger pl ON pl.user_id = u.id
       WHERE u.id = $1
       GROUP BY u.id, merged.support_code`,
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usu\u00e1rio n\u00e3o encontrado' });
    }

    const user = userResult.rows[0];

    const aliasesResult = await db.query(
      `SELECT device_account_key, source, first_seen_at, last_seen_at, metadata
         FROM device_account_aliases
        WHERE user_id = $1
        ORDER BY last_seen_at DESC`,
      [id]
    );

    // Stats
    const statsResult = await db.query(
      `SELECT 
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_earned,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
        COUNT(CASE WHEN amount > 0 THEN 1 END) as total_rewards,
        COUNT(*) as total_transactions
       FROM points_ledger WHERE user_id = $1`,
      [id]
    );

    const todayResult = await db.query(
      `SELECT COUNT(*) as count, COALESCE(SUM(points_awarded), 0) as total
       FROM reward_events WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
      [id]
    );

    // Payout destinations
    const payoutResult = await db.query(
      `SELECT id, type, value_masked, status, version, submitted_at, reviewed_at, rejection_reason
       FROM payout_destinations WHERE user_id = $1 AND is_active = true
       ORDER BY submitted_at DESC`,
      [id]
    );

    // PIX accounts
    const pixResult = await db.query(
      `SELECT id, cpf, full_name, pix_key_type, pix_key_value, pix_key_masked, status, submitted_at, reviewed_at, rejection_reason
       FROM pix_accounts WHERE user_id = $1 AND is_active = true
       ORDER BY submitted_at DESC`,
      [id]
    );

    // Withdrawals summary
    const withdrawalsResult = await db.query(
      `SELECT id, amount, points_debited, payment_method, status, crypto_currency, created_at, processed_at
       FROM withdrawals WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 20`,
      [id]
    );

    res.json({
      success: true,
      user: {
        ...user,
        stats: {
          totalEarned: parseInt(statsResult.rows[0].total_earned),
          totalSpent: parseInt(statsResult.rows[0].total_spent),
          totalRewards: parseInt(statsResult.rows[0].total_rewards),
          totalTransactions: parseInt(statsResult.rows[0].total_transactions),
          todayRewards: parseInt(todayResult.rows[0].count),
          todayEarned: parseInt(todayResult.rows[0].total)
        },
        deviceAliases: aliasesResult.rows,
        payoutDestinations: payoutResult.rows,
        pixAccounts: pixResult.rows,
        withdrawals: withdrawalsResult.rows
      }
    });
  } catch (error) {
    console.error('Get user detail error:', error);
    res.status(500).json({ error: 'Falha ao obter detalhes do usu\u00e1rio' });
  }
});

// GET /api/admin/users/:id/history - Get user points history
router.get('/users/:id/history', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const offset = (page - 1) * limit;
    const type = req.query.type || '';

    let query = `SELECT id, amount, transaction_type, reference_id, description, created_at
                 FROM points_ledger WHERE user_id = $1`;
    const params = [id];

    if (type) {
      query += ` AND transaction_type = $2`;
      params.push(type);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await db.query(query, params);

    let countQuery = 'SELECT COUNT(*) as total FROM points_ledger WHERE user_id = $1';
    const countParams = [id];
    if (type) {
      countQuery += ' AND transaction_type = $2';
      countParams.push(type);
    }
    const countResult = await db.query(countQuery, countParams);

    res.json({
      success: true,
      transactions: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('User history error:', error);
    res.status(500).json({ error: 'Falha ao obter hist\u00f3rico' });
  }
});

// GET /api/admin/users/:id/rewards - Get user reward events
router.get('/users/:id/rewards', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT id, ad_type, ad_network, ad_unit_id, points_awarded, ssv_verified,
              reward_session_id, device_id, ip_address, created_at
       FROM reward_events WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [id, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1',
      [id]
    );

    res.json({
      success: true,
      rewards: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('User rewards error:', error);
    res.status(500).json({ error: 'Falha ao obter recompensas' });
  }
});

// POST /api/admin/payout-destinations/:id/revoke - Revoke a payout destination
router.post('/payout-destinations/:id/revoke', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const result = await db.query(
      `UPDATE payout_destinations SET status = 'REVOKED', rejection_reason = $1, updated_at = NOW()
       WHERE id = $2 AND status = 'APPROVED'
       RETURNING id, user_id`,
      [reason || 'Revogado pelo admin', id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Destino n\u00e3o encontrado ou n\u00e3o est\u00e1 aprovado' });
    }

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'PAYOUT_DESTINATION_REVOKED', 'payout_destination', $2, $3, $4)`,
      [req.admin.id, id, JSON.stringify({ reason }), clientIp(req)]
    );

    res.json({ success: true, message: 'Destino de pagamento revogado' });
  } catch (error) {
    console.error('Revoke payout destination error:', error);
    res.status(500).json({ error: 'Falha ao revogar destino' });
  }
});

// POST /api/admin/pix-accounts/:id/revoke - Revoke a PIX account
router.post('/pix-accounts/:id/revoke', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const result = await db.query(
      `UPDATE pix_accounts SET status = 'REVOKED', rejection_reason = $1, updated_at = NOW()
       WHERE id = $2 AND status = 'APPROVED'
       RETURNING id, user_id`,
      [reason || 'Revogado pelo admin', id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Conta PIX n\u00e3o encontrada ou n\u00e3o est\u00e1 aprovada' });
    }

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'PIX_ACCOUNT_REVOKED', 'pix_account', $2, $3, $4)`,
      [req.admin.id, id, JSON.stringify({ reason }), clientIp(req)]
    );

    res.json({ success: true, message: 'Conta PIX revogada' });
  } catch (error) {
    console.error('Revoke PIX account error:', error);
    res.status(500).json({ error: 'Falha ao revogar conta PIX' });
  }
});

// GET /api/admin/audit-log - Get audit log
router.get('/audit-log', authenticateAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const offset = (page - 1) * limit;
    const action = req.query.action || '';
    const targetId = req.query.target_id || '';

    let query = `SELECT al.id, al.actor_id, al.actor_type, al.action, al.target_type, al.target_id,
                        al.old_value, al.new_value, al.ip_address, al.created_at,
                        COALESCE(au.email, au2.email) as actor_email
                 FROM audit_log al
                 LEFT JOIN admin_users au ON al.actor_id = au.id AND al.actor_type = 'admin'
                 LEFT JOIN users au2 ON al.actor_id = au2.id AND al.actor_type = 'user'
                 WHERE 1=1`;
    const params = [];

    if (action) {
      params.push(action);
      query += ` AND al.action = $${params.length}`;
    }
    if (targetId) {
      params.push(targetId);
      query += ` AND al.target_id = $${params.length}`;
    }

    query += ` ORDER BY al.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await db.query(query, params);

    let countQuery = 'SELECT COUNT(*) as total FROM audit_log WHERE 1=1';
    const countParams = [];
    if (action) {
      countParams.push(action);
      countQuery += ` AND action = $${countParams.length}`;
    }
    if (targetId) {
      countParams.push(targetId);
      countQuery += ` AND target_id = $${countParams.length}`;
    }
    const countResult = await db.query(countQuery, countParams);

    res.json({
      success: true,
      entries: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('Audit log error:', error);
    res.status(500).json({ error: 'Falha ao obter log de auditoria' });
  }
});

// GET /api/admin/system-config - Get system configuration
router.get('/system-config', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT key, value, updated_at FROM system_config ORDER BY key');
    const config = {};
    result.rows.forEach(row => {
      try {
        config[row.key] = { value: JSON.parse(row.value), updatedAt: row.updated_at };
      } catch {
        config[row.key] = { value: row.value, updatedAt: row.updated_at };
      }
    });
    res.json({ success: true, config });
  } catch (error) {
    console.error('System config error:', error);
    res.status(500).json({ error: 'Falha ao obter configura\u00e7\u00f5es' });
  }
});

// PUT /api/admin/system-config - Update system configuration
router.put('/system-config', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ error: 'Chave obrigat\u00f3ria' });

    const oldResult = await db.query('SELECT value FROM system_config WHERE key = $1', [key]);
    const oldValue = oldResult.rows.length > 0 ? oldResult.rows[0].value : null;

    await db.query(
      `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
      [key, JSON.stringify(value)]
    );

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', 'SYSTEM_CONFIG_UPDATED', 'system_config', NULL, $2, $3, $4)`,
      [req.admin.id, JSON.stringify({ key, value: oldValue }), JSON.stringify({ key, value }), clientIp(req)]
    );

    res.json({ success: true, message: `Configura\u00e7\u00e3o '${key}' atualizada` });
  } catch (error) {
    console.error('Update system config error:', error);
    res.status(500).json({ error: 'Falha ao atualizar configura\u00e7\u00e3o' });
  }
});

module.exports = router;
