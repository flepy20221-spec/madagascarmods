const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

function compatibleField(body, camelCase, snakeCase) {
  if (Object.prototype.hasOwnProperty.call(body, camelCase)) {
    return body[camelCase];
  }
  if (Object.prototype.hasOwnProperty.call(body, snakeCase)) {
    return body[snakeCase];
  }
  return undefined;
}

function parseOptionalPositiveInteger(value) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseOptionalNonNegativeInteger(value) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

/**
 * GET /api/missions
 * Lista missões ativas com progresso do usuário
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const today = new Date().toISOString().split('T')[0];

    // Buscar missões ativas
    const missions = await db.query(
      `SELECT m.id, m.title, m.description, m.type, m.target_value, m.reward_points, m.icon, m.is_daily,
              COALESCE(mp.current_value, 0) as current_value,
              COALESCE(mp.is_completed, false) as is_completed,
              COALESCE(mp.is_claimed, false) as is_claimed
       FROM missions m
       LEFT JOIN mission_progress mp ON mp.mission_id = m.id AND mp.user_id = $1 
         AND (m.is_daily = false OR mp.reset_date = $2)
       WHERE m.is_active = true
       ORDER BY m.sort_order ASC`,
      [userId, today]
    );

    // Calcular progresso automático para missões baseadas em dados existentes
    const enrichedMissions = [];
    for (const mission of missions.rows) {
      let currentValue = mission.current_value;

      // Auto-calcular progresso para missões do tipo watch_ads (baseado no dia)
      if (mission.type === 'watch_ads' && mission.is_daily) {
        const adsToday = await db.query(
          `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1 AND DATE(created_at) = $2`,
          [userId, today]
        );
        currentValue = parseInt(adsToday.rows[0].total);
      }

      // Auto-calcular para reach_level
      if (mission.type === 'reach_level') {
        const totalAds = await db.query(
          `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1`,
          [userId]
        );
        currentValue = Math.floor(parseInt(totalAds.rows[0].total) / 50);
      }

      // Auto-calcular para referral
      if (mission.type === 'referral') {
        const referrals = await db.query(
          `SELECT referral_count FROM users WHERE id = $1`,
          [userId]
        );
        currentValue = referrals.rows[0]?.referral_count || 0;
      }

      // Auto-calcular para checkin
      if (mission.type === 'checkin' && mission.is_daily) {
        const checkinToday = await db.query(
          `SELECT id FROM daily_checkins WHERE user_id = $1 AND checkin_date = $2`,
          [userId, today]
        );
        currentValue = checkinToday.rows.length > 0 ? 1 : 0;
      }

      const isCompleted = currentValue >= mission.target_value;

      enrichedMissions.push({
        id: mission.id,
        title: mission.title,
        description: mission.description,
        type: mission.type,
        targetValue: mission.target_value,
        rewardPoints: mission.reward_points,
        icon: mission.icon,
        isDaily: mission.is_daily,
        currentValue: Math.min(currentValue, mission.target_value),
        isCompleted,
        isClaimed: mission.is_claimed
      });
    }

    res.json({
      success: true,
      missions: enrichedMissions
    });
  } catch (error) {
    console.error('Missions list error:', error);
    res.status(500).json({ error: 'Erro ao buscar missões' });
  }
});

/**
 * POST /api/missions/:id/claim
 * Resgata a recompensa de uma missão completa
 */
router.post('/:id/claim', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const missionId = req.params.id;
    const { ad_watched } = req.body;
    const today = new Date().toISOString().split('T')[0];

    // Exigir que o usuário tenha assistido um anúncio antes de coletar recompensa
    if (!ad_watched) {
      return res.status(403).json({ error: 'É necessário assistir um anúncio para coletar a recompensa', require_ad: true });
    }

    await client.query('BEGIN');

    // Buscar missão
    const mission = await client.query(
      `SELECT * FROM missions WHERE id = $1 AND is_active = true`,
      [missionId]
    );

    if (mission.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Missão não encontrada' });
    }

    const m = mission.rows[0];

    // Verificar se já foi resgatada
    const existing = await client.query(
      `SELECT id, is_claimed FROM mission_progress 
       WHERE user_id = $1 AND mission_id = $2 AND (reset_date = $3 OR $4 = false)
       ORDER BY created_at DESC LIMIT 1`,
      [userId, missionId, today, m.is_daily]
    );

    if (existing.rows.length > 0 && existing.rows[0].is_claimed) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Recompensa já resgatada' });
    }

    // Verificar se a missão está completa (recalcular progresso)
    let currentValue = 0;

    if (m.type === 'watch_ads' && m.is_daily) {
      const adsToday = await client.query(
        `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1 AND DATE(created_at) = $2`,
        [userId, today]
      );
      currentValue = parseInt(adsToday.rows[0].total);
    } else if (m.type === 'reach_level') {
      const totalAds = await client.query(
        `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1`,
        [userId]
      );
      currentValue = Math.floor(parseInt(totalAds.rows[0].total) / 50);
    } else if (m.type === 'referral') {
      const referrals = await client.query(
        `SELECT referral_count FROM users WHERE id = $1`,
        [userId]
      );
      currentValue = referrals.rows[0]?.referral_count || 0;
    } else if (m.type === 'checkin' && m.is_daily) {
      const checkinToday = await client.query(
        `SELECT id FROM daily_checkins WHERE user_id = $1 AND checkin_date = $2`,
        [userId, today]
      );
      currentValue = checkinToday.rows.length > 0 ? 1 : 0;
    }

    if (currentValue < m.target_value) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Missão ainda não foi completada' });
    }

    // Upsert progress e marcar como claimed
    await client.query(
      `INSERT INTO mission_progress (user_id, mission_id, current_value, is_completed, is_claimed, completed_at, claimed_at, reset_date)
       VALUES ($1, $2, $3, true, true, NOW(), NOW(), $4)
       ON CONFLICT (user_id, mission_id, reset_date) 
       DO UPDATE SET is_completed = true, is_claimed = true, current_value = $3, completed_at = NOW(), claimed_at = NOW()`,
      [userId, missionId, currentValue, today]
    );

    // Registrar no ledger (saldo é calculado pela soma do points_ledger)
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'MISSION', $4)`,
      [uuidv4(), userId, m.reward_points, `Missão: ${m.title}`]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      pointsAwarded: m.reward_points,
      message: `Parabéns! Você ganhou ${m.reward_points} pontos!`
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Mission claim error:', error);
    res.status(500).json({ error: 'Erro ao resgatar recompensa' });
  } finally {
    client.release();
  }
});

// ============ ADMIN ROUTES ============

/**
 * GET /api/admin/missions
 * Lista todas as missões (admin)
 */
router.get('/admin/list', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM missions ORDER BY sort_order ASC, created_at DESC`
    );
    res.json({ success: true, missions: result.rows });
  } catch (error) {
    console.error('Admin missions list error:', error);
    res.status(500).json({ error: 'Erro ao buscar missões' });
  }
});

/**
 * POST /api/admin/missions
 * Criar nova missão (admin)
 */
router.post('/admin/create', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, type, icon } = req.body;
    const targetValue = parseOptionalPositiveInteger(
      compatibleField(req.body, 'targetValue', 'target_value')
    );
    const rewardPoints = parseOptionalPositiveInteger(
      compatibleField(req.body, 'rewardPoints', 'reward_points')
    );
    const sortOrder = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'sortOrder', 'sort_order')
    );
    const isActive = compatibleField(req.body, 'isActive', 'is_active');
    const isDaily = compatibleField(req.body, 'isDaily', 'is_daily');

    if (!title || !type || targetValue === undefined || rewardPoints === undefined) {
      return res.status(400).json({ error: 'Campos obrigatórios: title, type, targetValue, rewardPoints' });
    }
    if (targetValue === null || rewardPoints === null) {
      return res.status(400).json({ error: 'Meta e recompensa devem ser números inteiros maiores que zero' });
    }
    if (sortOrder === null) {
      return res.status(400).json({ error: 'Ordem deve ser um número inteiro maior ou igual a zero' });
    }
    if (isActive !== undefined && typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive deve ser booleano' });
    }
    if (isDaily !== undefined && typeof isDaily !== 'boolean') {
      return res.status(400).json({ error: 'isDaily deve ser booleano' });
    }

    const result = await db.query(
      `INSERT INTO missions (title, description, type, target_value, reward_points, icon, is_active, is_daily, sort_order)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [title, description || '', type, targetValue, rewardPoints, icon || 'star', isActive !== false, isDaily !== false, sortOrder ?? 0]
    );

    res.json({ success: true, mission: result.rows[0] });
  } catch (error) {
    console.error('Admin create mission error:', error);
    res.status(500).json({ error: 'Erro ao criar missão' });
  }
});

/**
 * PUT /api/admin/missions/:id
 * Atualizar missão (admin)
 */
router.put('/admin/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, type, icon } = req.body;
    const targetValue = parseOptionalPositiveInteger(
      compatibleField(req.body, 'targetValue', 'target_value')
    );
    const rewardPoints = parseOptionalPositiveInteger(
      compatibleField(req.body, 'rewardPoints', 'reward_points')
    );
    const sortOrder = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'sortOrder', 'sort_order')
    );
    const isActive = compatibleField(req.body, 'isActive', 'is_active');
    const isDaily = compatibleField(req.body, 'isDaily', 'is_daily');

    if (targetValue === null || rewardPoints === null) {
      return res.status(400).json({ error: 'Meta e recompensa devem ser números inteiros maiores que zero' });
    }
    if (sortOrder === null) {
      return res.status(400).json({ error: 'Ordem deve ser um número inteiro maior ou igual a zero' });
    }
    if (isActive !== undefined && typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive deve ser booleano' });
    }
    if (isDaily !== undefined && typeof isDaily !== 'boolean') {
      return res.status(400).json({ error: 'isDaily deve ser booleano' });
    }

    const result = await db.query(
      `UPDATE missions SET 
        title = COALESCE($1, title),
        description = COALESCE($2, description),
        type = COALESCE($3, type),
        target_value = COALESCE($4, target_value),
        reward_points = COALESCE($5, reward_points),
        icon = COALESCE($6, icon),
        is_active = COALESCE($7, is_active),
        is_daily = COALESCE($8, is_daily),
        sort_order = COALESCE($9, sort_order),
        updated_at = NOW()
       WHERE id = $10 RETURNING *`,
      [title, description, type, targetValue, rewardPoints, icon, isActive, isDaily, sortOrder, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Missão não encontrada' });
    }

    res.json({ success: true, mission: result.rows[0] });
  } catch (error) {
    console.error('Admin update mission error:', error);
    res.status(500).json({ error: 'Erro ao atualizar missão' });
  }
});

/**
 * DELETE /api/admin/missions/:id
 * Deletar missão (admin)
 */
router.delete('/admin/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query(`DELETE FROM mission_progress WHERE mission_id = $1`, [id]);
    await db.query(`DELETE FROM missions WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Admin delete mission error:', error);
    res.status(500).json({ error: 'Erro ao deletar missão' });
  }
});

module.exports = router;
