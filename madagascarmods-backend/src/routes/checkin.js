const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');

/**
 * GET /api/checkin/status
 * Retorna o status do check-in do usuário (se já fez hoje, streak atual, próximo bônus)
 */
router.get('/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Buscar último check-in do usuário
    const lastCheckin = await db.query(
      `SELECT checkin_date, streak_day, points_awarded 
       FROM daily_checkins 
       WHERE user_id = $1 
       ORDER BY checkin_date DESC 
       LIMIT 1`,
      [userId]
    );

    // Buscar configs
    const configResult = await db.query(
      `SELECT key, value FROM system_config WHERE key IN ('checkin_base_points', 'checkin_streak_multiplier', 'checkin_max_streak_bonus')`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });
    const basePoints = config.checkin_base_points || 10;
    const streakMultiplier = config.checkin_streak_multiplier || 5;
    const maxBonus = config.checkin_max_streak_bonus || 100;

    const today = new Date().toISOString().split('T')[0];
    let currentStreak = 0;
    let checkedInToday = false;
    let nextReward = basePoints;

    if (lastCheckin.rows.length > 0) {
      const lastDate = lastCheckin.rows[0].checkin_date.toISOString().split('T')[0];
      const lastStreak = lastCheckin.rows[0].streak_day;

      if (lastDate === today) {
        // Já fez check-in hoje
        checkedInToday = true;
        currentStreak = lastStreak;
        nextReward = Math.min(basePoints + (lastStreak * streakMultiplier), maxBonus);
      } else {
        // Verificar se é dia consecutivo
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        const yesterdayStr = yesterday.toISOString().split('T')[0];

        if (lastDate === yesterdayStr) {
          // Streak continua
          currentStreak = lastStreak;
          nextReward = Math.min(basePoints + (lastStreak * streakMultiplier), maxBonus);
        } else {
          // Streak quebrou
          currentStreak = 0;
          nextReward = basePoints;
        }
      }
    }

    // Buscar histórico dos últimos 7 dias
    const history = await db.query(
      `SELECT checkin_date, streak_day, points_awarded 
       FROM daily_checkins 
       WHERE user_id = $1 AND checkin_date >= CURRENT_DATE - INTERVAL '6 days'
       ORDER BY checkin_date ASC`,
      [userId]
    );

    res.json({
      success: true,
      checkin: {
        checkedInToday,
        currentStreak,
        nextReward,
        maxBonus,
        history: history.rows.map(r => ({
          date: r.checkin_date,
          day: r.streak_day,
          points: r.points_awarded
        }))
      }
    });
  } catch (error) {
    console.error('Checkin status error:', error);
    res.status(500).json({ error: 'Erro ao buscar status do check-in' });
  }
});

/**
 * POST /api/checkin/claim
 * Realiza o check-in diário e credita os pontos
 */
router.post('/claim', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const { ad_watched } = req.body;

    // Exigir que o usuário tenha assistido um anúncio antes de fazer check-in
    if (!ad_watched) {
      return res.status(403).json({ error: 'É necessário assistir um anúncio para fazer check-in', require_ad: true });
    }

    await client.query('BEGIN');

    // Verificar se já fez check-in hoje
    const today = new Date().toISOString().split('T')[0];
    const existing = await client.query(
      `SELECT id FROM daily_checkins WHERE user_id = $1 AND checkin_date = $2`,
      [userId, today]
    );

    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Você já fez check-in hoje!' });
    }

    // Buscar configs
    const configResult = await client.query(
      `SELECT key, value FROM system_config WHERE key IN ('checkin_base_points', 'checkin_streak_multiplier', 'checkin_max_streak_bonus')`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });
    const basePoints = config.checkin_base_points || 10;
    const streakMultiplier = config.checkin_streak_multiplier || 5;
    const maxBonus = config.checkin_max_streak_bonus || 100;

    // Calcular streak
    const lastCheckin = await client.query(
      `SELECT checkin_date, streak_day FROM daily_checkins 
       WHERE user_id = $1 ORDER BY checkin_date DESC LIMIT 1`,
      [userId]
    );

    let newStreak = 1;
    if (lastCheckin.rows.length > 0) {
      const lastDate = lastCheckin.rows[0].checkin_date.toISOString().split('T')[0];
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];

      if (lastDate === yesterdayStr) {
        newStreak = lastCheckin.rows[0].streak_day + 1;
      }
    }

    // Calcular pontos (base + streak bonus, limitado ao max)
    const points = Math.min(basePoints + ((newStreak - 1) * streakMultiplier), maxBonus);

    // Inserir check-in
    await client.query(
      `INSERT INTO daily_checkins (user_id, checkin_date, streak_day, points_awarded)
       VALUES ($1, $2, $3, $4)`,
      [userId, today, newStreak, points]
    );

    // Creditar pontos ao usuário
    await client.query(
      `UPDATE users SET balance = balance + $1 WHERE id = $2`,
      [points, userId]
    );

    // Registrar no ledger
    await client.query(
      `INSERT INTO points_ledger (user_id, amount, type, description)
       VALUES ($1, $2, 'checkin', $3)`,
      [userId, points, `Check-in dia ${newStreak} (+${points} pts)`]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      checkin: {
        streakDay: newStreak,
        pointsAwarded: points,
        nextReward: Math.min(basePoints + (newStreak * streakMultiplier), maxBonus)
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Checkin claim error:', error);
    res.status(500).json({ error: 'Erro ao realizar check-in' });
  } finally {
    client.release();
  }
});

module.exports = router;
