const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const crypto = require('crypto');
const { clientIp } = require('../middleware/antiFraud');

/**
 * ============================================================================
 * SISTEMA DE REFERRAL COM PROTEÇÃO ANTI-FRAUDE
 * ============================================================================
 * 
 * Proteções implementadas:
 * 1. Verificação de mesmo IP entre referrer e referred
 * 2. Verificação de mesmo device_id entre referrer e referred
 * 3. Rate limit por IP no endpoint /apply (max 3 por hora por IP)
 * 4. Limite máximo de referrals por dia por código
 * 5. Conta convidada precisa de mínimo de atividade para dar bônus ao referrer
 * 6. Cooldown entre criação da conta e aplicação de código (anti-bot)
 * 7. Verificação de padrões suspeitos (muitos referrals do mesmo IP)
 * 8. Bônus ao referrer só é creditado após convidado assistir X anúncios (deferred reward)
 * ============================================================================
 */

function generateReferralCode() {
  return crypto.randomBytes(4).toString('hex').substring(0, 6).toUpperCase();
}

/**
 * Verifica se um IP já foi usado em muitos referrals recentes (anti-farm)
 */
async function isIPSuspicious(ip, client) {
  if (!ip) return false;
  
  // Contar quantos referrals vieram deste IP nas últimas 24h
  const result = await (client || db).query(
    `SELECT COUNT(*) as total FROM users 
     WHERE ip_address = $1 
     AND referred_by IS NOT NULL 
     AND created_at > NOW() - INTERVAL '24 hours'`,
    [ip]
  );
  
  return parseInt(result.rows[0].total) >= 3; // Max 3 referrals do mesmo IP por dia
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
          if (e.code === '23505') {
            attempts++;
            continue;
          }
          throw e;
        }
      }
    }

    // Buscar convidados com status de ativação
    const referrals = await db.query(
      `SELECT u.email, u.created_at, u.is_active,
              COALESCE((SELECT COUNT(*) FROM reward_events WHERE user_id = u.id), 0) as ads_watched,
              COALESCE((SELECT SUM(points_awarded) FROM referral_rewards WHERE referrer_id = $1 AND referred_id = u.id), 0) as total_earned,
              (SELECT status FROM referral_rewards WHERE referrer_id = $1 AND referred_id = u.id AND reward_type = 'signup' LIMIT 1) as reward_status
       FROM users u 
       WHERE u.referred_by = $1
       ORDER BY u.created_at DESC
       LIMIT 50`,
      [userId]
    );

    // Total de pontos ganhos com referrals (apenas os já creditados)
    const totalEarned = await db.query(
      `SELECT COALESCE(SUM(points_awarded), 0) as total FROM referral_rewards WHERE referrer_id = $1 AND status = 'credited'`,
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
        minAdsForBonus: config.referral_min_ads_for_bonus || 10,
        referrals: referrals.rows.map(r => ({
          email: r.email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
          joinedAt: r.created_at,
          earned: parseInt(r.total_earned),
          adsWatched: parseInt(r.ads_watched),
          status: r.reward_status || 'pending'
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
 * Aplica um código de referral com múltiplas verificações anti-fraude
 */
router.post('/apply', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const { code, ad_watched } = req.body;
    const userIP = clientIp(req);

    // Exigir que o usuário tenha assistido um anúncio antes de aplicar código
    if (!ad_watched) {
      return res.status(403).json({ error: 'É necessário assistir um anúncio para aplicar o código', require_ad: true });
    }

    if (!code || code.length < 4) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    await client.query('BEGIN');

    // =========================================================================
    // VERIFICAÇÃO 1: Usuário já tem um referrer?
    // =========================================================================
    const user = await client.query(
      `SELECT referred_by, ip_address, device_id, created_at FROM users WHERE id = $1`,
      [userId]
    );

    if (user.rows[0]?.referred_by) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Você já usou um código de convite' });
    }

    // =========================================================================
    // VERIFICAÇÃO 2: Cooldown - conta precisa ter pelo menos 2 minutos de vida
    // (anti-bot que cria e aplica código instantaneamente)
    // =========================================================================
    const accountAge = Date.now() - new Date(user.rows[0]?.created_at).getTime();
    if (accountAge < 2 * 60 * 1000) { // 2 minutos
      await client.query('ROLLBACK');
      return res.status(429).json({ error: 'Aguarde um momento antes de aplicar um código de convite' });
    }

    // =========================================================================
    // VERIFICAÇÃO 3: Buscar dono do código
    // =========================================================================
    const referrer = await client.query(
      `SELECT id, ip_address, device_id FROM users WHERE referral_code = $1`,
      [code.toUpperCase()]
    );

    if (referrer.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Código de convite não encontrado' });
    }

    const referrerId = referrer.rows[0].id;
    const referrerIP = referrer.rows[0].ip_address;
    const referrerDeviceId = referrer.rows[0].device_id;

    // =========================================================================
    // VERIFICAÇÃO 4: Auto-convite (mesmo user ID)
    // =========================================================================
    if (referrerId === userId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Você não pode usar seu próprio código' });
    }

    // =========================================================================
    // VERIFICAÇÃO 4.5: Referral circular (A convidou B, B não pode usar código de A)
    // Se o dono do código (referrer) já foi convidado pelo usuário atual, bloquear
    // =========================================================================
    const referrerUser = await client.query(
      `SELECT referred_by FROM users WHERE id = $1`,
      [referrerId]
    );
    if (referrerUser.rows[0]?.referred_by === userId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Não é possível usar o código de alguém que você convidou' });
    }

    // =========================================================================
    // VERIFICAÇÃO 5: Mesmo IP (possível auto-convite com emulador/multi-conta)
    // =========================================================================
    const currentUserIP = user.rows[0]?.ip_address || userIP;
    if (referrerIP && currentUserIP && referrerIP === currentUserIP) {
      await client.query('ROLLBACK');
      // Registrar tentativa suspeita no audit_log
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
         VALUES ($1, 'user', 'REFERRAL_SAME_IP_BLOCKED', 'referral', $2, $3)`,
        [userId, JSON.stringify({ referrer_id: referrerId, ip: currentUserIP }), currentUserIP]
      );
      return res.status(403).json({ error: 'Não foi possível aplicar este código. Tente novamente mais tarde.' });
    }

    // =========================================================================
    // VERIFICAÇÃO 6: Mesmo device_id (mesmo dispositivo/emulador)
    // =========================================================================
    const currentDeviceId = user.rows[0]?.device_id;
    if (referrerDeviceId && currentDeviceId && referrerDeviceId === currentDeviceId) {
      await client.query('ROLLBACK');
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
         VALUES ($1, 'user', 'REFERRAL_SAME_DEVICE_BLOCKED', 'referral', $2, $3)`,
        [userId, JSON.stringify({ referrer_id: referrerId, device_id: currentDeviceId }), userIP]
      );
      return res.status(403).json({ error: 'Não foi possível aplicar este código. Tente novamente mais tarde.' });
    }

    // =========================================================================
    // VERIFICAÇÃO 7: Rate limit por IP (max 3 aplicações por hora do mesmo IP)
    // =========================================================================
    const recentFromIP = await client.query(
      `SELECT COUNT(*) as total FROM users 
       WHERE ip_address = $1 
       AND referred_by IS NOT NULL 
       AND updated_at > NOW() - INTERVAL '1 hour'`,
      [userIP]
    );
    if (parseInt(recentFromIP.rows[0].total) >= 3) {
      await client.query('ROLLBACK');
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
         VALUES ($1, 'user', 'REFERRAL_IP_RATE_LIMITED', 'referral', $2, $3)`,
        [userId, JSON.stringify({ ip: userIP, count: recentFromIP.rows[0].total }), userIP]
      );
      return res.status(429).json({ error: 'Muitas tentativas. Tente novamente mais tarde.' });
    }

    // =========================================================================
    // VERIFICAÇÃO 8: IP suspeito (muitos referrals nas últimas 24h)
    // =========================================================================
    if (await isIPSuspicious(userIP, client)) {
      await client.query('ROLLBACK');
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
         VALUES ($1, 'user', 'REFERRAL_SUSPICIOUS_IP', 'referral', $2, $3)`,
        [userId, JSON.stringify({ ip: userIP }), userIP]
      );
      return res.status(403).json({ error: 'Não foi possível aplicar este código. Tente novamente mais tarde.' });
    }

    // =========================================================================
    // VERIFICAÇÃO 9: Limite diário de referrals por código (max 10 por dia)
    // =========================================================================
    const dailyReferrals = await client.query(
      `SELECT COUNT(*) as total FROM users 
       WHERE referred_by = $1 
       AND created_at > NOW() - INTERVAL '24 hours'`,
      [referrerId]
    );
    if (parseInt(dailyReferrals.rows[0].total) >= 10) {
      await client.query('ROLLBACK');
      return res.status(429).json({ error: 'Este código atingiu o limite diário. Tente amanhã.' });
    }

    // =========================================================================
    // TUDO OK - Aplicar referral
    // =========================================================================
    
    // Buscar configs
    const configResult = await client.query(
      `SELECT key, value FROM system_config WHERE key IN ('referral_signup_bonus_referrer', 'referral_signup_bonus_referred', 'referral_min_ads_for_bonus')`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });
    const referrerBonus = config.referral_signup_bonus_referrer || 200;
    const referredBonus = config.referral_signup_bonus_referred || 100;
    const minAdsForBonus = config.referral_min_ads_for_bonus || 10;

    // Marcar referral
    await client.query(
      `UPDATE users SET referred_by = $1, updated_at = NOW() WHERE id = $2`,
      [referrerId, userId]
    );

    // Incrementar contador do referrer
    await client.query(
      `UPDATE users SET referral_count = referral_count + 1 WHERE id = $1`,
      [referrerId]
    );

    // Bônus IMEDIATO para o convidado (saldo calculado pelo points_ledger)
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'REFERRAL', 'Bônus: código de convite aplicado')`,
      [uuidv4(), userId, referredBonus]
    );

    // Bônus PENDENTE para o referrer (só credita quando convidado assistir X anúncios)
    await client.query(
      `INSERT INTO referral_rewards (referrer_id, referred_id, reward_type, points_awarded, status)
       VALUES ($1, $2, 'signup', $3, 'pending')
       ON CONFLICT DO NOTHING`,
      [referrerId, userId, referrerBonus]
    );

    // Registrar no audit_log
    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, new_value, ip_address)
       VALUES ($1, 'user', 'REFERRAL_APPLIED', 'referral', $2, $3)`,
      [userId, JSON.stringify({ referrer_id: referrerId, code: code.toUpperCase() }), userIP]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: `Código aplicado! Você ganhou ${referredBonus} pontos de bônus.`,
      pointsEarned: referredBonus,
      note: `Seu amigo receberá o bônus quando você assistir ${minAdsForBonus} anúncios.`
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
 * Verifica e credita bônus pendentes de referral
 * Chamado após cada anúncio assistido pelo convidado
 * O referrer só recebe o bônus quando o convidado atinge o mínimo de anúncios
 */
async function checkReferralBonusActivation(userId) {
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

    // Buscar config de mínimo de anúncios
    const configResult = await db.query(
      `SELECT key, value FROM system_config WHERE key IN ('referral_min_ads_for_bonus', 'referral_milestone_50ads')`
    );
    const config = {};
    configResult.rows.forEach(r => { config[r.key] = parseInt(r.value); });
    const minAdsForBonus = config.referral_min_ads_for_bonus || 10;
    const milestoneBonus = config.referral_milestone_50ads || 500;

    // =========================================================================
    // Ativação do bônus de signup (convidado atingiu mínimo de anúncios)
    // =========================================================================
    if (totalAds >= minAdsForBonus) {
      const pendingReward = await db.query(
        `SELECT id, points_awarded FROM referral_rewards 
         WHERE referrer_id = $1 AND referred_id = $2 AND reward_type = 'signup' AND status = 'pending'`,
        [referrerId, userId]
      );

      if (pendingReward.rows.length > 0) {
        const reward = pendingReward.rows[0];
        
        // Creditar bônus ao referrer (saldo calculado pelo points_ledger)
        await db.query(
          `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
           VALUES ($1, $2, $3, 'REFERRAL', $4)`,
          [uuidv4(), referrerId, reward.points_awarded, `Bônus: convidado atingiu ${minAdsForBonus} anúncios`]
        );
        
        // Marcar como creditado
        await db.query(
          `UPDATE referral_rewards SET status = 'credited', credited_at = NOW() WHERE id = $1`,
          [reward.id]
        );
      }
    }

    // =========================================================================
    // Milestone: 50 anúncios
    // =========================================================================
    if (totalAds >= 50) {
      const existing = await db.query(
        `SELECT id FROM referral_rewards 
         WHERE referrer_id = $1 AND referred_id = $2 AND reward_type = 'milestone' AND milestone_name = '50_ads'`,
        [referrerId, userId]
      );

      if (existing.rows.length === 0) {
        await db.query(
          `INSERT INTO referral_rewards (referrer_id, referred_id, reward_type, points_awarded, milestone_name, status)
           VALUES ($1, $2, 'milestone', $3, '50_ads', 'credited')`,
          [referrerId, userId, milestoneBonus]
        );
        await db.query(
          `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
           VALUES ($1, $2, $3, 'REFERRAL', 'Bônus: convidado atingiu 50 anúncios')`,
          [uuidv4(), referrerId, milestoneBonus]
        );
      }
    }
  } catch (error) {
    console.error('Referral bonus activation error:', error);
  }
}

module.exports = router;
module.exports.checkReferralBonusActivation = checkReferralBonusActivation;
