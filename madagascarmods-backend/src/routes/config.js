const express = require('express');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { configLimiter } = require('../middleware/rateLimits');
const { POINT_VALUES, getRewardDistribution } = require('../utils/pointsRandom');

const router = express.Router();

// GET /api/config/app - Get app configuration (public, rate limited)
router.get('/app', configLimiter, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT key, value FROM system_config WHERE key IN (
        'withdrawal_min_points', 'points_per_real', 'withdrawal_min_amount',
        'withdrawal_max_amount', 'withdrawal_methods', 'withdrawal_crypto_currency',
        'quick_values', 'reward_points_multiplier', 'reward_point_values',
        'daily_ad_limit_rewarded', 'daily_ad_limit_other', 'app_version',
        'test_ads_enabled', 'maintenance_mode', 'maintenance_message',
        'min_supported_version', 'force_update_message', 'play_store_url'
      )`
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
        rewardPointValues: config.reward_point_values || POINT_VALUES,
        rewardPointsMultiplier: Number(config.reward_points_multiplier) || 1,
        rewardDistribution: getRewardDistribution(),
        appVersion: config.app_version || '1.3.2',
        testAdsEnabled: config.test_ads_enabled === true || config.test_ads_enabled === 'true' || false,

        // ====================================================================
        // Controle remoto do app: Manutenção e Atualização Forçada
        // ====================================================================
        // Modo manutenção: bloqueia o app com mensagem customizável
        maintenanceMode: config.maintenance_mode === true || config.maintenance_mode === 'true' || false,
        maintenanceMessage: config.maintenance_message || 'Estamos em manutenção. Voltaremos em breve!',

        // Atualização forçada: versão mínima suportada (semver)
        minSupportedVersion: config.min_supported_version || '1.0.0',
        forceUpdateMessage: config.force_update_message || 'Uma nova versão do CashPix está disponível. Atualize para continuar usando o app.',
        playStoreUrl: config.play_store_url || 'https://play.google.com/store/apps/details?id=com.madagascarmods'
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
