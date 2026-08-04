const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

/**
 * POST /api/push/register
 * Registra o token FCM do dispositivo do usuário
 */
router.post('/register', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { token, platform } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token FCM é obrigatório' });
    }

    await db.query(
      `INSERT INTO push_tokens (user_id, token, platform, is_active, updated_at)
       VALUES ($1, $2, $3, true, NOW())
       ON CONFLICT (user_id, token) DO UPDATE SET is_active = true, updated_at = NOW()`,
      [userId, token, platform || 'android']
    );

    res.json({ success: true, message: 'Token registrado com sucesso' });
  } catch (error) {
    console.error('Push register error:', error);
    res.status(500).json({ error: 'Erro ao registrar token' });
  }
});

/**
 * POST /api/push/unregister
 * Desativa o token FCM (quando o usuário faz logout)
 */
router.post('/unregister', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { token } = req.body;

    if (token) {
      await db.query(
        `UPDATE push_tokens SET is_active = false, updated_at = NOW() WHERE user_id = $1 AND token = $2`,
        [userId, token]
      );
    } else {
      await db.query(
        `UPDATE push_tokens SET is_active = false, updated_at = NOW() WHERE user_id = $1`,
        [userId]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Push unregister error:', error);
    res.status(500).json({ error: 'Erro ao desregistrar token' });
  }
});

/**
 * POST /api/admin/push/send
 * Envia notificação push para todos ou usuários específicos (admin only)
 */
router.post('/admin/send', authenticateAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, targetType, targetUsers } = req.body;

    if (!title || !body) {
      return res.status(400).json({ error: 'Título e corpo são obrigatórios' });
    }

    // Buscar tokens ativos
    let tokensQuery;
    let tokensParams = [];

    if (targetType === 'specific' && targetUsers && targetUsers.length > 0) {
      tokensQuery = `SELECT DISTINCT token FROM push_tokens WHERE is_active = true AND user_id = ANY($1)`;
      tokensParams = [targetUsers];
    } else {
      // Enviar para todos
      tokensQuery = `SELECT DISTINCT token FROM push_tokens WHERE is_active = true`;
    }

    const tokensResult = await db.query(tokensQuery, tokensParams);
    const tokens = tokensResult.rows.map(r => r.token);

    if (tokens.length === 0) {
      return res.status(400).json({ error: 'Nenhum dispositivo registrado para receber notificações' });
    }

    // Enviar via FCM (Firebase Cloud Messaging)
    let successCount = 0;
    let failureCount = 0;

    const fcmServerKey = process.env.FCM_SERVER_KEY;
    
    if (fcmServerKey) {
      // Enviar em lotes de 1000 (limite do FCM)
      const batchSize = 1000;
      for (let i = 0; i < tokens.length; i += batchSize) {
        const batch = tokens.slice(i, i + batchSize);
        
        try {
          const fcmPayload = {
            registration_ids: batch,
            notification: {
              title,
              body,
              ...(imageUrl && { image: imageUrl }),
              sound: 'default',
              click_action: 'FLUTTER_NOTIFICATION_CLICK'
            },
            data: {
              title,
              body,
              type: 'admin_notification',
              ...(imageUrl && { image: imageUrl })
            }
          };

          const response = await fetch('https://fcm.googleapis.com/fcm/send', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `key=${fcmServerKey}`
            },
            body: JSON.stringify(fcmPayload)
          });

          const result = await response.json();
          successCount += result.success || 0;
          failureCount += result.failure || 0;

          // Remover tokens inválidos
          if (result.results) {
            for (let j = 0; j < result.results.length; j++) {
              if (result.results[j].error === 'NotRegistered' || result.results[j].error === 'InvalidRegistration') {
                await db.query(
                  `UPDATE push_tokens SET is_active = false WHERE token = $1`,
                  [batch[j]]
                );
              }
            }
          }
        } catch (fcmError) {
          console.error('FCM batch error:', fcmError);
          failureCount += batch.length;
        }
      }
    } else {
      // Sem FCM key configurada - simular envio para desenvolvimento
      successCount = tokens.length;
      console.warn('FCM_SERVER_KEY não configurada. Notificação registrada mas não enviada.');
    }

    // Registrar no histórico
    await db.query(
      `INSERT INTO push_notifications (title, body, image_url, target_type, target_users, sent_count, success_count, failure_count, sent_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [title, body, imageUrl || null, targetType || 'all', targetUsers || [], tokens.length, successCount, failureCount, req.admin?.id || null]
    );

    res.json({
      success: true,
      stats: {
        totalTokens: tokens.length,
        sent: successCount,
        failed: failureCount
      }
    });
  } catch (error) {
    console.error('Push send error:', error);
    res.status(500).json({ error: 'Erro ao enviar notificação' });
  }
});

/**
 * GET /api/admin/push/history
 * Lista histórico de notificações enviadas (admin only)
 */
router.get('/admin/history', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT id, title, body, image_url, target_type, sent_count, success_count, failure_count, created_at
       FROM push_notifications
       ORDER BY created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const countResult = await db.query(`SELECT COUNT(*) FROM push_notifications`);

    res.json({
      success: true,
      notifications: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      totalPages: Math.ceil(parseInt(countResult.rows[0].count) / limit)
    });
  } catch (error) {
    console.error('Push history error:', error);
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
});

/**
 * GET /api/admin/push/stats
 * Estatísticas gerais de push (admin only)
 */
router.get('/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const activeTokens = await db.query(
      `SELECT COUNT(DISTINCT token) as total FROM push_tokens WHERE is_active = true`
    );
    const totalSent = await db.query(
      `SELECT COALESCE(SUM(sent_count), 0) as total FROM push_notifications`
    );
    const todaySent = await db.query(
      `SELECT COALESCE(SUM(sent_count), 0) as total FROM push_notifications WHERE created_at >= CURRENT_DATE`
    );

    res.json({
      success: true,
      stats: {
        activeDevices: parseInt(activeTokens.rows[0].total),
        totalSent: parseInt(totalSent.rows[0].total),
        todaySent: parseInt(todaySent.rows[0].total)
      }
    });
  } catch (error) {
    console.error('Push stats error:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

module.exports = router;
