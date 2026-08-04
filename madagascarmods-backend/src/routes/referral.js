const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const crypto = require('crypto');

/**
 * Gera um código de referral único de 6 caracteres alfanuméricos
 */
function generateReferralCode() {
  return crypto.randomBytes(4).toString('hex').substring(0, 6).toUpperCase();
}

/**
 * GET /api/referral/info
 * Retorna o código de referral do usuário, stats e lista de convidados
 */
router.get('/info', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Buscar ou gerar código de referral
    let user = await db.query(
      `SELECT referral_code, referral_count FROM users WHERE id = $1`,
      [userId]
    );

    let referralCode = user.rows[0]?.referral_code;

    if (!referralCode) {
      // Gerar código único
      let attempts = 0;
      while (attempts < 10) {
        referralCode = generateReferralCode();
        try {
          await db.query(
            `UPDATE users SET referral_code = $1 WHERE id = $2`,
            [referralCode, userId]
          );
          break;
        } catch (e) {
          if (e.code === '23505') { // unique violation
            attempts++;
            continue;
          }
          throw e;
        }
      }
    }

    // Buscar convidados
    const referrals = await db.query(
      `SELECT u.email, u.created_at, 
              COALESCE((SELECT SUM(points_awarded) FROM referral_rewards WHERE referrer_id = $1 AND referred_id = u.id), 0) as total_earned
       FROM users u 
       WHERE u.referred_by = $1
       ORDER BY u.created_at DESC
       LIMIT 50`,
      [userId]
    );

    // Total de pontos ganhos com referrals
    const totalEarned = await db.query(
      `SELECT COALESCE(SUM(points_awarded), 0) as total FROM referral_rewards WHERE referrer_id = $1`,
      [userId]
    );

    // Buscar configs de referral
    const configResult = await db.query(
      `SELECT key, value FROM system_config WHERE key LIKE 'referral_%'`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });

    res.json({
      success: true,
      referral: {
        code: referralCode,
        totalReferred: user.rows[0]?.referral_count || 0,
        totalEarned: parseInt(totalEarned.rows[0]?.total || 0),
        signupBonus: config.referral_signup_bonus_referrer || 200,
        referredBonus: config.referral_signup_bonus_referred || 100,
        milestoneBonus: config.referral_milestone_50ads || 500,
        referrals: referrals.rows.map(r => ({
          email: r.email.replace(/(.{2})(.*)(@.*)/, '$1***$3'), // Mascarar email
          joinedAt: r.created_at,
          earned: parseInt(r.total_earned)
        }))
      }
    });
  } catch (error) {
    console.error('Referral info error:', error);
    res.status(500).json({ error: 'Erro ao buscar informações de referral' });
  }
});

/**
 * POST /api/referral/apply
 * Aplica um código de referral (chamado no cadastro/primeiro login)
 */
router.post('/apply', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const { code } = req.body;

    if (!code || code.length < 4) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await client.query('BEGIN');

    // Verificar se o usuário já tem um referrer
    const user = await client.query(
      `SELECT referred_by FROM users WHERE id = $1`,
      [userId]
    );

    if (user.rows[0]?.referred_by) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Você já usou um código de convite' });
    }

    // Buscar dono do código
    const referrer = await client.query(
      `SELECT id FROM users WHERE referral_code = $1`,
      [code.toUpperCase()]
    );

    if (referrer.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Código de convite não encontrado' });
    }

    const referrerId = referrer.rows[0].id;

    if (referrerId === userId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Você não pode usar seu próprio código' });
    }

    // Buscar configs
    const configResult = await client.query(
      `SELECT key, value FROM system_config WHERE key IN ('referral_signup_bonus_referrer', 'referral_signup_bonus_referred')`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });
    const referrerBonus = config.referral_signup_bonus_referrer || 200;
    const referredBonus = config.referral_signup_bonus_referred || 100;

    // Aplicar referral
    await client.query(
      `UPDATE users SET referred_by = $1 WHERE id = $2`,
      [referrerId, userId]
    );

    // Incrementar contador do referrer
    await client.query(
      `UPDATE users SET referral_count = referral_count + 1 WHERE id = $1`,
      [referrerId]
    );

    // Bônus para o referrer
    await client.query(
      `INSERT INTO referral_rewards (referrer_id, referred_id, reward_type, points_awarded)
       VALUES ($1, $2, 'signup', $3)
       ON CONFLICT DO NOTHING`,
      [referrerId, userId, referrerBonus]
    );
    await client.query(
      `UPDATE users SET balance = balance + $1 WHERE id = $2`,
      [referrerBonus, referrerId]
    );
    await client.query(
      `INSERT INTO points_ledger (user_id, amount, type, description)
       VALUES ($1, $2, 'referral', 'Bônus: novo convidado se cadastrou')`,
      [referrerId, referrerBonus]
    );

    // Bônus para o convidado
    await client.query(
      `UPDATE users SET balance = balance + $1 WHERE id = $2`,
      [referredBonus, userId]
    );
    await client.query(
      `INSERT INTO points_ledger (user_id, amount, type, description)
       VALUES ($1, $2, 'referral', 'Bônus: código de convite aplicado')`,
      [userId, referredBonus]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: `Código aplicado! Você ganhou ${referredBonus} pontos de bônus.`,
      pointsEarned: referredBonus
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Referral apply error:', error);
    res.status(500).json({ error: 'Erro ao aplicar código de referral' });
  } finally {
    client.release();
  }
});

/**
 * Middleware interno: verificar milestones de referral
 * Chamado quando um convidado atinge marcos (50 anúncios, etc.)
 */
async function checkReferralMilestones(userId) {
  try {
    const user = await db.query(
      `SELECT referred_by FROM users WHERE id = $1`,
      [userId]
    );

    if (!user.rows[0]?.referred_by) return;

    const referrerId = user.rows[0].referred_by;

    // Contar total de anúncios do convidado
    const adsCount = await db.query(
      `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1`,
      [userId]
    );
    const totalAds = parseInt(adsCount.rows[0].total);

    // Milestone: 50 anúncios
    if (totalAds >= 50) {
      const configResult = await db.query(
        `SELECT value FROM system_config WHERE key = 'referral_milestone_50ads'`
      );
      const milestoneBonus = parseInt(configResult.rows[0]?.value || 500);

      // Verificar se já foi dado
      const existing = await db.query(
        `SELECT id FROM referral_rewards 
         WHERE referrer_id = $1 AND referred_id = $2 AND reward_type = 'milestone' AND milestone_name = '50_ads'`,
        [referrerId, userId]
      );

      if (existing.rows.length === 0) {
        await db.query(
          `INSERT INTO referral_rewards (referrer_id, referred_id, reward_type, points_awarded, milestone_name)
           VALUES ($1, $2, 'milestone', $3, '50_ads')`,
          [referrerId, userId, milestoneBonus]
        );
        await db.query(
          `UPDATE users SET balance = balance + $1 WHERE id = $2`,
          [milestoneBonus, referrerId]
        );
        await db.query(
          `INSERT INTO points_ledger (user_id, amount, type, description)
           VALUES ($1, $2, 'referral', 'Bônus: convidado atingiu 50 anúncios')`,
          [referrerId, milestoneBonus]
        );
      }
    }
  } catch (error) {
    console.error('Referral milestone check error:', error);
  }
}

module.exports = router;
module.exports.checkReferralMilestones = checkReferralMilestones;
