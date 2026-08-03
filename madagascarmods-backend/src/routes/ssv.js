/**
 * CashPix — AdMob Server-Side Verification (SSV) Callback
 * 
 * Esta rota recebe callbacks diretamente do Google quando um usuário
 * assiste um anúncio rewarded completo. É a forma mais segura de
 * validar que o anúncio foi realmente assistido.
 * 
 * URL a configurar no AdMob: 
 * https://madagascarmods-production.up.railway.app/api/ssv/callback
 */
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { validateSsvCallback } = require('../utils/admobSsv');
const { drawRewardPoints, POINT_VALUES } = require('../utils/pointsRandom');

const router = express.Router();

// GET /api/ssv/callback - AdMob SSV callback (chamado pelo Google)
// O Google envia via GET com query params assinados
router.get('/callback', async (req, res) => {
  try {
    const queryParams = req.query;

    // Registrar somente metadados operacionais; a assinatura completa e os dados
    // do usuário não devem aparecer nos logs de produção.
    console.log('[SSV] Callback received', {
      adUnit: queryParams.ad_unit || null,
      transactionId: queryParams.transaction_id || null,
      keyId: queryParams.key_id || null,
      hasUserData: Boolean(queryParams.custom_data || queryParams.user_id)
    });

    // A verificação criptográfica precisa dos bytes exatos da query antes de
    // `&signature=`. `req.query` já foi decodificado pelo Express e não serve
    // como fonte canônica quando há percent-encoding em custom_data/user_id.
    const queryStart = req.originalUrl.indexOf('?');
    const rawQueryString = queryStart >= 0 ? req.originalUrl.slice(queryStart + 1) : '';
    const validation = await validateSsvCallback(queryParams, rawQueryString);

    if (!validation.valid) {
      console.warn('[SSV] Invalid callback:', validation.error);
      // Retornar 200 mesmo em caso de erro para o Google não retentar
      return res.status(200).json({ success: false, error: validation.error });
    }

    const { data } = validation;

    // Extrair user_id do custom_data (enviado pelo app)
    // O custom_data contém o userId do nosso sistema
    const userId = data.customData || data.userId;

    if (!userId) {
      console.warn('[SSV] No user_id in callback');
      return res.status(200).json({ success: false, error: 'No user_id' });
    }

    // Verificar se o transaction_id já foi processado (anti-replay)
    if (data.transactionId) {
      const existing = await db.query(
        `SELECT id FROM reward_events WHERE ssv_transaction_id = $1 LIMIT 1`,
        [data.transactionId]
      );

      if (existing.rows.length > 0) {
        console.log('[SSV] Duplicate transaction:', data.transactionId);
        return res.status(200).json({ success: true, message: 'Already processed' });
      }
    }

    // Verificar se o usuário existe e não está banido
    const userCheck = await db.query(
      'SELECT id, is_banned, is_active FROM users WHERE id = $1',
      [userId]
    );

    if (userCheck.rows.length === 0) {
      console.warn('[SSV] User not found:', userId);
      return res.status(200).json({ success: false, error: 'User not found' });
    }

    if (userCheck.rows[0].is_banned || !userCheck.rows[0].is_active) {
      console.warn('[SSV] User banned/inactive:', userId);
      return res.status(200).json({ success: false, error: 'User banned' });
    }

    // Sortear pontos
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key = 'reward_points_multiplier'"
    );
    const multiplier = configResult.rows.length > 0 
      ? Number(JSON.parse(configResult.rows[0].value)) || 1 
      : 1;

    const draw = drawRewardPoints({ multiplier });
    const pointsToAward = draw.points;

    // Creditar pontos via SSV (verificado pelo Google)
    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      // Registrar evento de reward com SSV verificado
      const eventId = uuidv4();
      await client.query(
        `INSERT INTO reward_events (id, user_id, ad_type, ad_network, ad_unit_id, points_awarded, ssv_token, ssv_verified, ssv_transaction_id, ip_address)
         VALUES ($1, $2, 'rewarded', $3, $4, $5, $6, true, $7, $8)`,
        [
          eventId, userId,
          data.adNetwork || 'admob',
          data.adUnit || null,
          pointsToAward,
          JSON.stringify(queryParams),
          data.transactionId || null,
          req.headers['x-forwarded-for'] || req.socket.remoteAddress
        ]
      );

      // Creditar no ledger
      const ledgerId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, $3, 'REWARD_SSV', $4, 'Rewarded ad (SSV verified)')`,
        [ledgerId, userId, pointsToAward, eventId]
      );

      await client.query('COMMIT');

      console.log(`[SSV] Credited ${pointsToAward} pts to user ${userId} (tx: ${data.transactionId})`);

      // Retornar 200 para o Google saber que processamos
      res.status(200).json({ success: true, pointsAwarded: pointsToAward });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('[SSV] Callback error:', error);
    // Sempre retornar 200 para o Google não retentar indefinidamente
    res.status(200).json({ success: false, error: 'Internal error' });
  }
});

// GET /api/ssv/verify - Verificar se SSV está funcionando (health check)
router.get('/verify', async (req, res) => {
  try {
    const { fetchGoogleKeys } = require('../utils/admobSsv');
    const keys = await fetchGoogleKeys();
    res.json({
      success: true,
      message: 'SSV verification endpoint is active',
      googleKeysLoaded: keys.length,
      keysUrl: 'https://www.gstatic.com/admob/reward/verifier-keys.json'
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
