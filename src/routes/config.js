const express = require('express');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { POINT_VALUES, getRewardDistribution } = require('../utils/pointsRandom');

const router = express.Router();

// GET /api/config/app - Get app configuration (public)
router.get('/app', async (req, res) => {
  try {
    const result = await db.query(
      "SELECT key, value FROM system_config WHERE key IN ('withdrawal_min_points', 'points_per_real', 'withdrawal_min_amount', 'withdrawal_max_amount', 'withdrawal_methods', 'withdrawal_crypto_currency', 'quick_values', 'reward_points_multiplier', 'reward_point_values', 'daily_ad_limit_rewarded', 'daily_ad_limit_other', 'app_version')"
    );

    const config = {};
    result.rows.forEach(row => {
      try {
        config[row.key] = JSON.parse(row.value);
      } catch (err) {
        config[row.key] = row.value;
      }
    });

    res.json({
      success: true,
      config: {
        withdrawalMinPoints: config.withdrawal_min_points || 2000,
        pointsPerReal: config.points_per_real || 2000,
        withdrawalMinAmount: config.withdrawal_min_amount || 1.00,
        withdrawalMaxAmount: config.withdrawal_max_amount || 1000.00,
        withdrawalMethods: config.withdrawal_methods || ['faucetpay'],
        cryptoCurrency: config.withdrawal_crypto_currency || 'LTC',
        quickValues: config.quick_values || [1, 2, 5, 10, 20, 50],
        dailyAdLimitRewarded: Number(config.daily_ad_limit_rewarded) || 50,
        dailyAdLimitOther: Number(config.daily_ad_limit_other) || 30,
        // A pontuacao por anuncio premiado NAO e fixa: o servidor sorteia um
        // valor da grade abaixo com probabilidade ponderada.
        rewardPointValues: config.reward_point_values || POINT_VALUES,
        rewardPointsMultiplier: Number(config.reward_points_multiplier) || 1,
        rewardDistribution: getRewardDistribution(),
        appVersion: config.app_version || '1.3.2'
      }
    });
  } catch (error) {
    console.error('Get config error:', error);
    res.status(500).json({ error: 'Failed to get configuration' });
  }
});

// GET /api/config/withdrawal - Get withdrawal config (authenticated)
router.get('/withdrawal', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT key, value FROM system_config WHERE key LIKE 'withdrawal_%' OR key = 'points_per_real' OR key = 'quick_values'"
    );

    const config = {};
    result.rows.forEach(row => {
      config[row.key] = JSON.parse(row.value);
    });

    res.json({
      success: true,
      config
    });
  } catch (error) {
    console.error('Get withdrawal config error:', error);
    res.status(500).json({ error: 'Failed to get withdrawal configuration' });
  }
});

module.exports = router;
