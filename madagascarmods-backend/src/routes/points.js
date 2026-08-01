const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { rewardFraudDetection } = require('../middleware/antiFraud');
const {
  drawRewardPoints,
  getRewardDistribution,
  POINT_VALUES
} = require('../utils/pointsRandom');
const { validateSsvToken } = require('../utils/admobSsv');

const router = express.Router();

// POST /api/points/reward - Credit points for ad view (server-validated)
// Middleware chain: auth -> fraud detection -> handler
router.post('/reward', authenticateToken, rewardFraudDetection, async (req, res) => {
  try {
    const { ad_type, ad_unit_id, ad_network, ssv_token } = req.body;

    if (!ad_type) {
      return res.status(400).json({ error: 'ad_type is required' });
    }

    const userId = req.user.userId;

    // Bloquear se fraud score é muito alto (detectado pelo middleware)
    if (req.fraudScore && req.fraudScore >= 3) {
      console.warn(`[Reward] Blocked reward for user ${userId} - fraud score: ${req.fraudScore}`);
      return res.status(403).json({ 
        error: 'Atividade suspeita detectada. Aguarde alguns minutos.',
        code: 'FRAUD_DETECTED'
      });
    }
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Get reward config from system
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key IN ('reward_points_multiplier', 'reward_points_interstitial', 'reward_points_banner')"
    );

    const config = {};
    configResult.rows.forEach(row => {
      try {
        config[row.key] = JSON.parse(row.value);
      } catch (err) {
        config[row.key] = row.value;
      }
    });

    // Determine points based on ad type.
    // Para 'rewarded' o valor NAO e fixo: aplicamos o sorteio ponderado que
    // reproduz a logica original do app, na qual pontuacoes altas sao raras.
    let pointsToAward = 0;
    let rewardRoll = null;
    let rewardTier = null;

    switch (ad_type) {
      case 'rewarded': {
        const multiplier = Number(config.reward_points_multiplier) || 1;
        const draw = drawRewardPoints({ multiplier });
        pointsToAward = draw.points;
        rewardRoll = draw.roll;
        rewardTier = draw.tier;
        break;
      }
      case 'interstitial':
        pointsToAward = Number(config.reward_points_interstitial) || 0;
        break;
      case 'banner':
        pointsToAward = Number(config.reward_points_banner) || 0;
        break;
      default:
        return res.status(400).json({ error: 'Invalid ad_type. Must be: rewarded, interstitial, or banner' });
    }

    if (pointsToAward <= 0) {
      return res.status(400).json({ error: 'This ad type does not award points' });
    }

    // SSV Validation: se o app enviou ssv_token, validar antes de creditar
    let ssvVerified = false;
    let ssvTransactionId = null;
    if (ssv_token && ad_type === 'rewarded') {
      const ssvResult = await validateSsvToken(ssv_token);
      if (ssvResult.valid) {
        ssvVerified = true;
        ssvTransactionId = ssvResult.data?.transactionId || null;
        console.log(`[SSV-Inline] Valid SSV for user ${userId}, tx: ${ssvTransactionId}`);
      } else {
        console.warn(`[SSV-Inline] Invalid SSV for user ${userId}: ${ssvResult.error}`);
        // Não bloquear por enquanto - apenas logar. Quando SSV estiver 100% ativo,
        // descomentar a linha abaixo para rejeitar rewards sem SSV válido:
        // return res.status(403).json({ error: 'Verificação de anúncio falhou', code: 'SSV_INVALID' });
      }
    }

    // Rate limiting: check last reward time for this user
    const lastReward = await db.query(
      `SELECT created_at FROM reward_events 
       WHERE user_id = $1 AND ad_type = $2 
       ORDER BY created_at DESC LIMIT 1`,
      [userId, ad_type]
    );

    if (lastReward.rows.length > 0) {
      const lastTime = new Date(lastReward.rows[0].created_at);
      const now = new Date();
      const diffSeconds = (now - lastTime) / 1000;
      
      // Minimum 10 seconds between rewarded ads, 30 seconds for others
      const minInterval = ad_type === 'rewarded' ? 10 : 30;
      if (diffSeconds < minInterval) {
        return res.status(429).json({ 
          error: 'Too soon since last reward', 
          retryAfter: Math.ceil(minInterval - diffSeconds) 
        });
      }
    }

    // Daily limit check
    const dailyCount = await db.query(
      `SELECT COUNT(*) as count FROM reward_events 
       WHERE user_id = $1 AND ad_type = $2 AND created_at > NOW() - INTERVAL '24 hours'`,
      [userId, ad_type]
    );

    const dailyLimit = ad_type === 'rewarded' ? 100 : 50;
    const currentDailyCount = parseInt(dailyCount.rows[0].count);
    if (currentDailyCount >= dailyLimit) {
      return res.status(429).json({ 
        error: 'Limite diário atingido. Volte amanhã!', 
        code: 'DAILY_LIMIT',
        dailyLimit,
        dailyCount: currentDailyCount
      });
    }

    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      // Record reward event
      const eventId = uuidv4();
      await client.query(
        `INSERT INTO reward_events (id, user_id, ad_type, ad_network, ad_unit_id, points_awarded, ssv_token, ssv_verified, ssv_transaction_id, device_id, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [eventId, userId, ad_type, ad_network || 'admob', ad_unit_id || null, pointsToAward, ssv_token || null, ssvVerified, ssvTransactionId, req.body.device_id || null, ip]
      );

      // Credit points in ledger
      const ledgerId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, $3, 'REWARD', $4, $5)`,
        [ledgerId, userId, pointsToAward, eventId, `${ad_type} ad reward`]
      );

      await client.query('COMMIT');

      // Get updated balance
      const balanceResult = await db.query(
        'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
        [userId]
      );

      res.json({
        success: true,
        pointsAwarded: pointsToAward,
        newBalance: parseInt(balanceResult.rows[0].balance),
        eventId,
        pointValues: POINT_VALUES,
        rewardTier,
        rewardRoll: rewardRoll === null ? null : Number(rewardRoll.toFixed(4)),
        dailyLimit,
        dailyCount: currentDailyCount + 1
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Reward error:', error);
    res.status(500).json({ error: 'Failed to process reward' });
  }
});

// GET /api/points/table - Grade de valores e distribuicao de probabilidade
router.get('/table', async (req, res) => {
  try {
    res.json({
      success: true,
      pointValues: POINT_VALUES,
      distribution: getRewardDistribution()
    });
  } catch (error) {
    console.error('Points table error:', error);
    res.status(500).json({ error: 'Failed to get points table' });
  }
});

// GET /api/points/history - Get points history
router.get('/history', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT id, amount, transaction_type, description, created_at 
       FROM points_ledger 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
      [req.user.userId, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM points_ledger WHERE user_id = $1',
      [req.user.userId]
    );

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
    console.error('History error:', error);
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// GET /api/points/stats - Get user reward stats
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await db.query(
      `SELECT 
        COALESCE(SUM(amount), 0) as total_balance,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_earned,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
        COUNT(CASE WHEN amount > 0 THEN 1 END) as total_rewards
       FROM points_ledger WHERE user_id = $1`,
      [req.user.userId]
    );

    const todayStats = await db.query(
      `SELECT 
        COALESCE(SUM(points_awarded), 0) as today_earned,
        COUNT(*) as today_views
       FROM reward_events 
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
      [req.user.userId]
    );

    res.json({
      success: true,
      stats: {
        balance: parseInt(stats.rows[0].total_balance),
        totalEarned: parseInt(stats.rows[0].total_earned),
        totalSpent: parseInt(stats.rows[0].total_spent),
        totalRewards: parseInt(stats.rows[0].total_rewards),
        todayEarned: parseInt(todayStats.rows[0].today_earned),
        todayViews: parseInt(todayStats.rows[0].today_views)
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

module.exports = router;
