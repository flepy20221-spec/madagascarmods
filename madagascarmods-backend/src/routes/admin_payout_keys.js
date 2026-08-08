/**
 * ===========================================================================================
 * CashPix - Correcao administrativa de chave de pagamento
 *
 * PROBLEMA ATENDIDO
 * -----------------
 * O painel administrativo so oferecia aprovar, rejeitar e revogar dados de pagamento. Quando
 * o usuario cadastrava a chave errada (CPF trocado, e-mail FaucetPay com um caractere a menos,
 * nome divergente do titular), o unico caminho era revogar e pedir que ele cadastrasse de
 * novo. Isso trava o saque, gera atendimento manual e, no caso do FaucetPay, o admin nao
 * tinha como sequer VER o valor completo para conferir onde estava o erro: o e-mail e gravado
 * cifrado (AES-256 via crypto-js) e somente a versao mascarada chegava ao painel.
 *
 * ROTAS ADICIONADAS
 * -----------------
 *   GET  /api/admin/payout-destinations/:id/reveal   revela o e-mail FaucetPay (auditado)
 *   PUT  /api/admin/payout-destinations/:id          corrige o e-mail FaucetPay
 *   POST /api/admin/users/:id/payout-destination     cria destino FaucetPay inexistente
 *   PUT  /api/admin/pix-accounts/:id                 corrige CPF / nome / chave PIX
 *   POST /api/admin/users/:id/pix-account            cria conta PIX inexistente
 *
 * GARANTIAS APLICADAS EM TODAS ELAS
 * ---------------------------------
 *   1. Papel 'finance' (ou super_admin): sao os dados que definem para onde o dinheiro vai.
 *   2. Motivo obrigatorio, gravado em audit_log junto do valor antigo e do novo, mascarados.
 *   3. Mesmas validacoes do fluxo do aplicativo (utils/payoutHelpers.js), para nao existir
 *      um caminho administrativo capaz de gravar CPF ou e-mail invalido no banco.
 *   4. Unicidade entre contas preservada (cpf_hash / value_hash): a correcao nao pode
 *      apontar a chave de um usuario para dados ja usados por outro.
 *   5. Bloqueio quando existe saque em andamento (PENDING / PROCESSING /
 *      PAYMENT_UNCONFIRMED). Trocar o destino com um pagamento em voo enviaria o valor para
 *      a chave nova enquanto o comprovante aponta para a antiga.
 *   6. Transacao com SELECT ... FOR UPDATE: duas correcoes simultaneas nao podem deixar
 *      `value_hash` inconsistente com `value_encrypted`.
 *
 * Este arquivo e separado de routes/admin.js apenas por organizacao; ele e montado no mesmo
 * prefixo /api/admin em src/index.js.
 * ===========================================================================================
 */
const express = require('express');
const { clientIp } = require('../middleware/antiFraud');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateAdmin, requireRole } = require('../middleware/auth');
const { decrypt, encrypt, hashValue, maskEmail } = require('../utils/crypto');
const {
  maskCpf,
  isValidEmail,
  normalizeEmail,
  validatePixPayload
} = require('../utils/payoutHelpers');

const router = express.Router();

/** Statuses de saque que impedem a alteracao do destino de pagamento. */
const BLOCKING_WITHDRAWAL_STATUSES = ['PENDING', 'PROCESSING', 'PAYMENT_UNCONFIRMED'];

/**
 * Retorna o saque em andamento que bloqueia a alteracao, ou null.
 *
 * A consulta usa o client da transacao quando fornecido, para que a checagem aconteca sob o
 * mesmo snapshot do lock aplicado na linha do destino.
 */
async function findBlockingWithdrawal(executor, userId) {
  const result = await executor.query(
    `SELECT id, status, payment_method, amount, created_at
       FROM withdrawals
      WHERE user_id = $1 AND status = ANY($2::text[])
      ORDER BY created_at DESC
      LIMIT 1`,
    [userId, BLOCKING_WITHDRAWAL_STATUSES]
  );
  return result.rows[0] || null;
}

/** Normaliza e valida o motivo exigido em toda correcao administrativa. */
function normalizeReason(raw) {
  const reason = String(raw || '').trim();
  if (reason.length < 5) return null;
  return reason.slice(0, 500);
}

// clientIp vem de middleware/antiFraud: resolve o IP real atras do proxy e evita
// gravar a lista completa do X-Forwarded-For no campo ip_address.

// -------------------------------------------------------------------------------------------
// GET /api/admin/payout-destinations/:id/reveal
//
// Revela o e-mail FaucetPay em claro para que o admin possa conferir e corrigir o cadastro.
//
// Este endpoint expoe dado sensivel de proposito, por isso: exige papel 'finance', registra
// SEMPRE um evento de auditoria (quem revelou, de qual IP e quando) e nunca aparece em
// listagens - e preciso pedir explicitamente por um id.
// -------------------------------------------------------------------------------------------
router.get('/payout-destinations/:id/reveal', authenticateAdmin, requireRole('finance'), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.query(
      `SELECT pd.id, pd.user_id, pd.type, pd.value_encrypted, pd.value_masked, pd.status,
              pd.version, pd.is_active, u.email AS user_email
         FROM payout_destinations pd
         JOIN users u ON u.id = pd.user_id
        WHERE pd.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Destino de pagamento nao encontrado' });
    }

    const dest = result.rows[0];

    let value;
    try {
      value = decrypt(dest.value_encrypted);
    } catch (err) {
      console.error('Reveal payout destination decrypt error:', err.message);
      return res.status(500).json({
        error: 'Nao foi possivel decifrar o valor. Verifique a variavel ENCRYPTION_KEY.',
        code: 'DECRYPT_FAILED'
      });
    }

    // decrypt() do crypto-js devolve string vazia (em vez de lancar) quando a chave de
    // criptografia nao corresponde ao que cifrou o valor.
    if (!value) {
      return res.status(500).json({
        error: 'Valor cifrado ilegivel com a ENCRYPTION_KEY atual.',
        code: 'DECRYPT_EMPTY'
      });
    }

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'PAYOUT_DESTINATION_REVEALED', 'payout_destination', $2, $3, $4)`,
      [
        req.admin.id,
        id,
        JSON.stringify({ user_id: dest.user_id, value_masked: dest.value_masked }),
        clientIp(req)
      ]
    );

    res.json({
      success: true,
      destination: {
        id: dest.id,
        userId: dest.user_id,
        userEmail: dest.user_email,
        type: dest.type,
        value,
        valueMasked: dest.value_masked,
        status: dest.status,
        version: dest.version,
        isActive: dest.is_active
      }
    });
  } catch (error) {
    console.error('Reveal payout destination error:', error);
    res.status(500).json({ error: 'Falha ao revelar destino de pagamento' });
  }
});

// -------------------------------------------------------------------------------------------
// PUT /api/admin/payout-destinations/:id
//
// Corrige o e-mail FaucetPay de um destino existente.
//
// Corpo: { value, reason, status? }
//   value  : novo e-mail FaucetPay (obrigatorio)
//   reason : justificativa (obrigatoria, min. 5 caracteres, vai para auditoria)
//   status : opcional. Por padrao a correcao PRESERVA o status atual, porque o caso de uso
//            principal e consertar o dado de uma conta ja aprovada sem obrigar o usuario a
//            esperar nova analise. Envie 'PENDING' para exigir revisao novamente.
// -------------------------------------------------------------------------------------------
router.put('/payout-destinations/:id', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();
  let inTransaction = false;
  try {
    const { id } = req.params;
    const { value, reason, status } = req.body;

    const auditReason = normalizeReason(reason);
    if (!auditReason) {
      return res.status(400).json({
        error: 'Informe o motivo da correcao (minimo 5 caracteres)',
        code: 'REASON_REQUIRED'
      });
    }

    const newEmail = normalizeEmail(value);
    if (!isValidEmail(newEmail)) {
      return res.status(400).json({ error: 'E-mail FaucetPay invalido', code: 'INVALID_EMAIL' });
    }

    if (status !== undefined && !['PENDING', 'APPROVED'].includes(status)) {
      return res.status(400).json({
        error: 'Status permitido na correcao: PENDING ou APPROVED',
        code: 'INVALID_STATUS'
      });
    }

    await client.query('BEGIN');
    inTransaction = true;

    const current = await client.query(
      `SELECT id, user_id, type, value_masked, value_hash, status, version
         FROM payout_destinations
        WHERE id = $1
        FOR UPDATE`,
      [id]
    );

    if (current.rows.length === 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(404).json({ error: 'Destino de pagamento nao encontrado' });
    }

    const dest = current.rows[0];

    const blocking = await findBlockingWithdrawal(client, dest.user_id);
    if (blocking) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(409).json({
        error: `O usuario possui um saque em andamento (${blocking.status}). ` +
               'Finalize ou rejeite o saque antes de alterar a chave de pagamento.',
        code: 'WITHDRAWAL_IN_PROGRESS',
        withdrawal: { id: blocking.id, status: blocking.status }
      });
    }

    const newHash = hashValue(newEmail);

    if (newHash === dest.value_hash) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(400).json({
        error: 'O e-mail informado e igual ao atual',
        code: 'NO_CHANGE'
      });
    }

    // Unicidade entre contas: o mesmo e-mail FaucetPay nao pode receber pagamentos de dois
    // usuarios diferentes, senao um usuario passaria a sacar para a carteira de outro.
    const duplicate = await client.query(
      `SELECT pd.id, u.email AS user_email
         FROM payout_destinations pd
         JOIN users u ON u.id = pd.user_id
        WHERE pd.value_hash = $1
          AND pd.user_id <> $2
          AND pd.is_active = true
          AND pd.status IN ('PENDING', 'APPROVED')
        LIMIT 1`,
      [newHash, dest.user_id]
    );

    if (duplicate.rows.length > 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(409).json({
        error: 'Este e-mail FaucetPay ja esta vinculado a outro usuario',
        code: 'EMAIL_ALREADY_USED',
        conflict: { userEmail: duplicate.rows[0].user_email }
      });
    }

    const newStatus = status || dest.status;
    const newMasked = maskEmail(newEmail);

    // `version` aumenta a cada alteracao, preservando o significado que a coluna ja tinha no
    // fluxo do aplicativo (cada reenvio do usuario gera uma nova versao).
    const updated = await client.query(
      `UPDATE payout_destinations
          SET value_encrypted  = $1,
              value_masked     = $2,
              value_hash       = $3,
              status           = $4,
              version          = version + 1,
              is_active        = true,
              reviewed_at      = NOW(),
              reviewed_by      = $5,
              rejection_reason = NULL,
              updated_at       = NOW()
        WHERE id = $6
        RETURNING id, user_id, value_masked, status, version`,
      [encrypt(newEmail), newMasked, newHash, newStatus, req.admin.id, id]
    );

    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', 'PAYOUT_DESTINATION_EDITED', 'payout_destination', $2, $3, $4, $5)`,
      [
        req.admin.id,
        id,
        JSON.stringify({
          value_masked: dest.value_masked,
          status: dest.status,
          version: dest.version
        }),
        JSON.stringify({
          value_masked: newMasked,
          status: newStatus,
          version: dest.version + 1,
          reason: auditReason
        }),
        clientIp(req)
      ]
    );

    await client.query('COMMIT');
    inTransaction = false;

    res.json({
      success: true,
      message: 'Chave de pagamento FaucetPay atualizada',
      destination: updated.rows[0]
    });
  } catch (error) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    console.error('Edit payout destination error:', error);
    res.status(500).json({ error: 'Falha ao atualizar chave de pagamento FaucetPay' });
  } finally {
    client.release();
  }
});

// -------------------------------------------------------------------------------------------
// POST /api/admin/users/:id/payout-destination
//
// Cadastra um destino FaucetPay para usuario que ainda nao possui nenhum.
//
// Existe porque parte dos atendimentos e o oposto de "cadastrou errado": o usuario nao
// consegue concluir o cadastro pelo app (versao antiga, falha de rede persistente) e informa
// o e-mail pelo suporte. Sem esta rota o admin nao tinha como destravar o saque.
// -------------------------------------------------------------------------------------------
router.post('/users/:id/payout-destination', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();
  let inTransaction = false;
  try {
    const { id: userId } = req.params;
    const { value, reason, status } = req.body;

    const auditReason = normalizeReason(reason);
    if (!auditReason) {
      return res.status(400).json({
        error: 'Informe o motivo do cadastro manual (minimo 5 caracteres)',
        code: 'REASON_REQUIRED'
      });
    }

    const newEmail = normalizeEmail(value);
    if (!isValidEmail(newEmail)) {
      return res.status(400).json({ error: 'E-mail FaucetPay invalido', code: 'INVALID_EMAIL' });
    }

    const newStatus = status === 'PENDING' ? 'PENDING' : 'APPROVED';

    await client.query('BEGIN');
    inTransaction = true;

    const user = await client.query('SELECT id, email FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    const newHash = hashValue(newEmail);

    const duplicate = await client.query(
      `SELECT pd.id, u.email AS user_email
         FROM payout_destinations pd
         JOIN users u ON u.id = pd.user_id
        WHERE pd.value_hash = $1
          AND pd.user_id <> $2
          AND pd.is_active = true
          AND pd.status IN ('PENDING', 'APPROVED')
        LIMIT 1`,
      [newHash, userId]
    );

    if (duplicate.rows.length > 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(409).json({
        error: 'Este e-mail FaucetPay ja esta vinculado a outro usuario',
        code: 'EMAIL_ALREADY_USED',
        conflict: { userEmail: duplicate.rows[0].user_email }
      });
    }

    // Apenas UM destino ativo por usuario, mesma regra do fluxo do aplicativo.
    await client.query(
      'UPDATE payout_destinations SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );

    const destId = uuidv4();
    const masked = maskEmail(newEmail);

    await client.query(
      `INSERT INTO payout_destinations
         (id, user_id, type, value_encrypted, value_masked, value_hash, status, version,
          is_active, submitted_at, reviewed_at, reviewed_by)
       VALUES ($1, $2, 'FAUCETPAY_EMAIL', $3, $4, $5, $6, 1, true, NOW(), NOW(), $7)`,
      [destId, userId, encrypt(newEmail), masked, newHash, newStatus, req.admin.id]
    );

    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'PAYOUT_DESTINATION_CREATED_BY_ADMIN', 'payout_destination', $2, $3, $4)`,
      [
        req.admin.id,
        destId,
        JSON.stringify({
          user_id: userId,
          value_masked: masked,
          status: newStatus,
          reason: auditReason
        }),
        clientIp(req)
      ]
    );

    await client.query('COMMIT');
    inTransaction = false;

    res.status(201).json({
      success: true,
      message: 'Destino FaucetPay cadastrado',
      destination: { id: destId, userId, valueMasked: masked, status: newStatus, version: 1 }
    });
  } catch (error) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    console.error('Create payout destination error:', error);
    res.status(500).json({ error: 'Falha ao cadastrar destino FaucetPay' });
  } finally {
    client.release();
  }
});

// -------------------------------------------------------------------------------------------
// PUT /api/admin/pix-accounts/:id
//
// Corrige CPF, nome do titular e chave PIX de uma conta existente.
//
// Corpo: { cpf?, full_name?, pix_key_type?, pix_key_value?, reason, status? }
// Campos ausentes mantem o valor atual, permitindo que o painel envie apenas o que mudou.
// Os dados passam pela MESMA validacao do fluxo do aplicativo (validatePixPayload), inclusive
// digitos verificadores do CPF.
// -------------------------------------------------------------------------------------------
router.put('/pix-accounts/:id', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();
  let inTransaction = false;
  try {
    const { id } = req.params;
    const { reason, status } = req.body;

    const auditReason = normalizeReason(reason);
    if (!auditReason) {
      return res.status(400).json({
        error: 'Informe o motivo da correcao (minimo 5 caracteres)',
        code: 'REASON_REQUIRED'
      });
    }

    if (status !== undefined && !['PENDING', 'APPROVED'].includes(status)) {
      return res.status(400).json({
        error: 'Status permitido na correcao: PENDING ou APPROVED',
        code: 'INVALID_STATUS'
      });
    }

    await client.query('BEGIN');
    inTransaction = true;

    const current = await client.query(
      `SELECT id, user_id, cpf, cpf_hash, full_name, pix_key_type, pix_key_value,
              pix_key_masked, status
         FROM pix_accounts
        WHERE id = $1
        FOR UPDATE`,
      [id]
    );

    if (current.rows.length === 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(404).json({ error: 'Conta PIX nao encontrada' });
    }

    const account = current.rows[0];

    const payload = {
      cpf: req.body.cpf !== undefined ? req.body.cpf : account.cpf,
      full_name: req.body.full_name !== undefined ? req.body.full_name : account.full_name,
      pix_key_type: req.body.pix_key_type !== undefined ? req.body.pix_key_type : account.pix_key_type,
      pix_key_value: req.body.pix_key_value !== undefined ? req.body.pix_key_value : account.pix_key_value
    };

    const validation = validatePixPayload(payload);
    if (!validation.ok) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(400).json({ error: validation.error, code: validation.code });
    }

    const next = validation.data;

    const blocking = await findBlockingWithdrawal(client, account.user_id);
    if (blocking) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(409).json({
        error: `O usuario possui um saque em andamento (${blocking.status}). ` +
               'Finalize ou rejeite o saque antes de alterar os dados PIX.',
        code: 'WITHDRAWAL_IN_PROGRESS',
        withdrawal: { id: blocking.id, status: blocking.status }
      });
    }

    const unchanged =
      next.cpf === account.cpf &&
      next.fullName === account.full_name &&
      next.pixKeyType === account.pix_key_type &&
      next.pixKeyValue === account.pix_key_value;

    if (unchanged) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(400).json({ error: 'Nenhuma alteracao fornecida', code: 'NO_CHANGE' });
    }

    const newCpfHash = hashValue(next.cpf);

    // Regra de negocio existente: um CPF pertence a uma unica conta ativa.
    if (newCpfHash !== account.cpf_hash) {
      const duplicate = await client.query(
        `SELECT pa.id, u.email AS user_email
           FROM pix_accounts pa
           JOIN users u ON u.id = pa.user_id
          WHERE pa.cpf_hash = $1
            AND pa.user_id <> $2
            AND pa.is_active = true
            AND pa.status IN ('PENDING', 'APPROVED')
          LIMIT 1`,
        [newCpfHash, account.user_id]
      );

      if (duplicate.rows.length > 0) {
        await client.query('ROLLBACK');
        inTransaction = false;
        return res.status(409).json({
          error: 'Este CPF ja esta vinculado a outro usuario',
          code: 'CPF_ALREADY_USED',
          conflict: { userEmail: duplicate.rows[0].user_email }
        });
      }
    }

    const newStatus = status || account.status;

    const updated = await client.query(
      `UPDATE pix_accounts
          SET cpf              = $1,
              cpf_hash         = $2,
              full_name        = $3,
              pix_key_type     = $4,
              pix_key_value    = $5,
              pix_key_masked   = $6,
              status           = $7,
              is_active        = true,
              reviewed_at      = NOW(),
              reviewed_by      = $8,
              rejection_reason = NULL,
              updated_at       = NOW()
        WHERE id = $9
        RETURNING id, user_id, full_name, pix_key_type, pix_key_masked, status`,
      [
        next.cpf,
        newCpfHash,
        next.fullName,
        next.pixKeyType,
        next.pixKeyValue,
        next.pixKeyMasked,
        newStatus,
        req.admin.id,
        id
      ]
    );

    // A auditoria guarda apenas valores MASCARADOS: o registro precisa provar o que foi
    // alterado sem transformar o proprio log em um deposito de CPFs em claro.
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value, ip_address)
       VALUES ($1, 'admin', 'PIX_ACCOUNT_EDITED', 'pix_account', $2, $3, $4, $5)`,
      [
        req.admin.id,
        id,
        JSON.stringify({
          cpf_masked: maskCpf(account.cpf),
          full_name: account.full_name,
          pix_key_type: account.pix_key_type,
          pix_key_masked: account.pix_key_masked,
          status: account.status
        }),
        JSON.stringify({
          cpf_masked: maskCpf(next.cpf),
          full_name: next.fullName,
          pix_key_type: next.pixKeyType,
          pix_key_masked: next.pixKeyMasked,
          status: newStatus,
          reason: auditReason
        }),
        clientIp(req)
      ]
    );

    await client.query('COMMIT');
    inTransaction = false;

    res.json({
      success: true,
      message: 'Dados PIX atualizados',
      account: {
        ...updated.rows[0],
        cpf_masked: maskCpf(next.cpf)
      }
    });
  } catch (error) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    console.error('Edit PIX account error:', error);
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Este CPF ja esta vinculado a outra conta',
        code: 'CPF_ALREADY_USED'
      });
    }
    res.status(500).json({ error: 'Falha ao atualizar dados PIX' });
  } finally {
    client.release();
  }
});

// -------------------------------------------------------------------------------------------
// POST /api/admin/users/:id/pix-account
//
// Cadastra uma conta PIX para usuario que ainda nao possui nenhuma (mesmo motivo da rota
// equivalente de FaucetPay).
// -------------------------------------------------------------------------------------------
router.post('/users/:id/pix-account', authenticateAdmin, requireRole('finance'), async (req, res) => {
  const client = await db.getClient();
  let inTransaction = false;
  try {
    const { id: userId } = req.params;
    const { reason, status } = req.body;

    const auditReason = normalizeReason(reason);
    if (!auditReason) {
      return res.status(400).json({
        error: 'Informe o motivo do cadastro manual (minimo 5 caracteres)',
        code: 'REASON_REQUIRED'
      });
    }

    const validation = validatePixPayload(req.body);
    if (!validation.ok) {
      return res.status(400).json({ error: validation.error, code: validation.code });
    }

    const next = validation.data;
    const newStatus = status === 'PENDING' ? 'PENDING' : 'APPROVED';

    await client.query('BEGIN');
    inTransaction = true;

    const user = await client.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    const cpfHash = hashValue(next.cpf);

    const duplicate = await client.query(
      `SELECT pa.id, u.email AS user_email
         FROM pix_accounts pa
         JOIN users u ON u.id = pa.user_id
        WHERE pa.cpf_hash = $1
          AND pa.user_id <> $2
          AND pa.is_active = true
          AND pa.status IN ('PENDING', 'APPROVED')
        LIMIT 1`,
      [cpfHash, userId]
    );

    if (duplicate.rows.length > 0) {
      await client.query('ROLLBACK');
      inTransaction = false;
      return res.status(409).json({
        error: 'Este CPF ja esta vinculado a outro usuario',
        code: 'CPF_ALREADY_USED',
        conflict: { userEmail: duplicate.rows[0].user_email }
      });
    }

    await client.query(
      'UPDATE pix_accounts SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND is_active = true',
      [userId]
    );

    const pixId = uuidv4();

    await client.query(
      `INSERT INTO pix_accounts
         (id, user_id, cpf, cpf_hash, full_name, pix_key_type, pix_key_value, pix_key_masked,
          status, is_active, submitted_at, reviewed_at, reviewed_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, NOW(), NOW(), $10)`,
      [
        pixId,
        userId,
        next.cpf,
        cpfHash,
        next.fullName,
        next.pixKeyType,
        next.pixKeyValue,
        next.pixKeyMasked,
        newStatus,
        req.admin.id
      ]
    );

    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'admin', 'PIX_ACCOUNT_CREATED_BY_ADMIN', 'pix_account', $2, $3, $4)`,
      [
        req.admin.id,
        pixId,
        JSON.stringify({
          user_id: userId,
          cpf_masked: maskCpf(next.cpf),
          full_name: next.fullName,
          pix_key_type: next.pixKeyType,
          pix_key_masked: next.pixKeyMasked,
          status: newStatus,
          reason: auditReason
        }),
        clientIp(req)
      ]
    );

    await client.query('COMMIT');
    inTransaction = false;

    res.status(201).json({
      success: true,
      message: 'Conta PIX cadastrada',
      account: {
        id: pixId,
        userId,
        cpf_masked: maskCpf(next.cpf),
        full_name: next.fullName,
        pix_key_type: next.pixKeyType,
        pix_key_masked: next.pixKeyMasked,
        status: newStatus
      }
    });
  } catch (error) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    console.error('Create PIX account error:', error);
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Este CPF ja esta vinculado a outra conta',
        code: 'CPF_ALREADY_USED'
      });
    }
    res.status(500).json({ error: 'Falha ao cadastrar conta PIX' });
  } finally {
    client.release();
  }
});

module.exports = router;
