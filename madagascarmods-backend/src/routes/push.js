const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

// Firebase Admin SDK para push notifications (FCM v1)
let firebaseAdmin = null;
try {
  const admin = require('firebase-admin');
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (serviceAccountJson) {
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    firebaseAdmin = admin;
    console.log('Firebase Admin SDK inicializado com sucesso');
  } else {
    console.warn('FIREBASE_SERVICE_ACCOUNT não configurada. Push notifications desabilitadas.');
  }
} catch (e) {
  console.error('Erro ao inicializar Firebase Admin:', e.message);
}

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

    // Enviar via Firebase Admin SDK (FCM v1 API)
    let successCount = 0;
    let failureCount = 0;

    if (firebaseAdmin) {
      // Enviar em lotes de 500 (limite do sendEachForMulticast)
      const batchSize = 500;
      for (let i = 0; i < tokens.length; i += batchSize) {
        const batch = tokens.slice(i, i + batchSize);
        
        try {
          const message = {
            notification: {
              title,
              body,
              ...(imageUrl && { imageUrl })
            },
            data: {
              title,
              body,
              type: 'admin_notification',
              ...(imageUrl && { image: imageUrl })
            },
            android: {
              priority: 'high',
              notification: {
                sound: 'default',
                icon: 'ic_stat_cashpix',
                color: '#9C27B0',
                clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                channelId: 'cashpix_notifications'
              }
            },
            tokens: batch
          };

          const response = await firebaseAdmin.messaging().sendEachForMulticast(message);
          successCount += response.successCount;
          failureCount += response.failureCount;

          // Remover tokens inválidos
          response.responses.forEach(async (resp, idx) => {
            if (!resp.success) {
              const errorCode = resp.error?.code;
              if (errorCode === 'messaging/registration-token-not-registered' ||
                  errorCode === 'messaging/invalid-registration-token') {
                await db.query(
                  `UPDATE push_tokens SET is_active = false WHERE token = $1`,
                  [batch[idx]]
                );
              }
            }
          });
        } catch (fcmError) {
          console.error('FCM batch error:', fcmError);
          failureCount += batch.length;
        }
      }
    } else {
      // Sem Firebase configurado - simular envio para desenvolvimento
      successCount = tokens.length;
      console.warn('Firebase Admin não configurado. Notificação registrada mas não enviada.');
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

// =============================================================================
// NOTIFICAÇÕES AGENDADAS (Scheduled Notifications)
// =============================================================================

/**
 * GET /api/admin/push/scheduled
 * Lista todas as notificações agendadas
 */
router.get('/admin/scheduled', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, title, body, image_url, target_type, schedule_time, days_of_week, 
              is_active, last_sent_at, total_sent, created_at
       FROM scheduled_notifications
       ORDER BY schedule_time ASC`
    );
    res.json({ success: true, schedules: result.rows });
  } catch (error) {
    console.error('Scheduled list error:', error);
    res.status(500).json({ error: 'Erro ao listar agendamentos' });
  }
});

/**
 * POST /api/admin/push/scheduled
 * Cria uma nova notificação agendada
 */
router.post('/admin/scheduled', authenticateAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, targetType, scheduleTime, daysOfWeek } = req.body;

    if (!title || !body || !scheduleTime) {
      return res.status(400).json({ error: 'Título, mensagem e horário são obrigatórios' });
    }

    // Validar formato do horário (HH:MM)
    const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
    if (!timeRegex.test(scheduleTime)) {
      return res.status(400).json({ error: 'Horário inválido. Use formato HH:MM' });
    }

    const days = daysOfWeek && daysOfWeek.length > 0 ? daysOfWeek : [0, 1, 2, 3, 4, 5, 6];

    const result = await db.query(
      `INSERT INTO scheduled_notifications (title, body, image_url, target_type, schedule_time, days_of_week, created_by)
       VALUES ($1, $2, $3, $4, $5::time, $6, $7)
       RETURNING *`,
      [title, body, imageUrl || null, targetType || 'all', scheduleTime + ':00', days, req.admin?.id || null]
    );

    res.json({ success: true, schedule: result.rows[0] });
  } catch (error) {
    console.error('Scheduled create error:', error);
    res.status(500).json({ error: 'Erro ao criar agendamento' });
  }
});

/**
 * PUT /api/admin/push/scheduled/:id
 * Atualiza uma notificação agendada
 */
router.put('/admin/scheduled/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, body, imageUrl, targetType, scheduleTime, daysOfWeek, isActive } = req.body;

    const result = await db.query(
      `UPDATE scheduled_notifications 
       SET title = COALESCE($1, title),
           body = COALESCE($2, body),
           image_url = $3,
           target_type = COALESCE($4, target_type),
           schedule_time = COALESCE($5::time, schedule_time),
           days_of_week = COALESCE($6, days_of_week),
           is_active = COALESCE($7, is_active),
           updated_at = NOW()
       WHERE id = $8
       RETURNING *`,
      [title, body, imageUrl || null, targetType, scheduleTime ? scheduleTime + ':00' : null, daysOfWeek, isActive, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Agendamento não encontrado' });
    }

    res.json({ success: true, schedule: result.rows[0] });
  } catch (error) {
    console.error('Scheduled update error:', error);
    res.status(500).json({ error: 'Erro ao atualizar agendamento' });
  }
});

/**
 * DELETE /api/admin/push/scheduled/:id
 * Remove uma notificação agendada
 */
router.delete('/admin/scheduled/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query(
      `DELETE FROM scheduled_notifications WHERE id = $1 RETURNING id`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Agendamento não encontrado' });
    }

    res.json({ success: true, message: 'Agendamento removido' });
  } catch (error) {
    console.error('Scheduled delete error:', error);
    res.status(500).json({ error: 'Erro ao remover agendamento' });
  }
});

// =============================================================================
// SCHEDULER - Verifica e dispara notificações agendadas a cada minuto
// =============================================================================

/**
 * Retorna a data/hora atual em Brasília (UTC-3).
 * Não depende do timezone do servidor (Railway usa UTC).
 */
function getBrasiliaTime() {
  const now = new Date();
  // Brasília = UTC-3 (sem horário de verão desde 2019)
  const utcMs = now.getTime() + now.getTimezoneOffset() * 60000;
  const brasiliaMs = utcMs - 3 * 3600000;
  return new Date(brasiliaMs);
}

/**
 * Retorna a data de "hoje" em Brasília como string YYYY-MM-DD.
 * Usada para verificar se já enviou hoje.
 */
function getBrasiliaDateString() {
  const brasilia = getBrasiliaTime();
  const year = brasilia.getFullYear();
  const month = String(brasilia.getMonth() + 1).padStart(2, '0');
  const day = String(brasilia.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

async function processScheduledNotifications() {
  try {
    const brasilia = getBrasiliaTime();
    const currentHour = String(brasilia.getHours()).padStart(2, '0');
    const currentMinute = String(brasilia.getMinutes()).padStart(2, '0');
    const currentTime = `${currentHour}:${currentMinute}:00`; // Formato TIME completo (HH:MM:SS)
    const currentDay = brasilia.getDay(); // 0=domingo, 6=sábado
    const todayStr = getBrasiliaDateString();

    // Buscar notificações ativas para este horário e dia.
    // A comparação usa timezone de Brasília explicitamente:
    // - schedule_time é comparado com o horário atual de Brasília
    // - last_sent_at é convertido para Brasília antes de comparar com "hoje"
    const schedules = await db.query(
      `SELECT * FROM scheduled_notifications 
       WHERE is_active = true 
       AND schedule_time = $1::time
       AND $2 = ANY(days_of_week)
       AND (
         last_sent_at IS NULL 
         OR (last_sent_at AT TIME ZONE 'America/Sao_Paulo')::date < $3::date
       )`,
      [currentTime, currentDay, todayStr]
    );

    if (schedules.rows.length > 0) {
      console.log(`[Scheduler] ${schedules.rows.length} notificação(ões) para enviar às ${currentHour}:${currentMinute} (Brasília)`);
    }

    for (const schedule of schedules.rows) {
      try {
        // Buscar todos os tokens ativos
        const tokensResult = await db.query(
          `SELECT DISTINCT token FROM push_tokens WHERE is_active = true`
        );
        const tokens = tokensResult.rows.map(r => r.token);

        if (tokens.length === 0) {
          console.log(`[Scheduler] Nenhum token ativo. Pulando "${schedule.title}".`);
          continue;
        }

        let successCount = 0;
        let failureCount = 0;

        if (firebaseAdmin) {
          const batchSize = 500;
          for (let i = 0; i < tokens.length; i += batchSize) {
            const batch = tokens.slice(i, i + batchSize);
            try {
              const message = {
                notification: {
                  title: schedule.title,
                  body: schedule.body,
                  ...(schedule.image_url && { imageUrl: schedule.image_url })
                },
                data: {
                  title: schedule.title,
                  body: schedule.body,
                  type: 'scheduled_notification'
                },
                android: {
                  priority: 'high',
                  notification: {
                    sound: 'default',
                    icon: 'ic_stat_cashpix',
                    color: '#9C27B0',
                    clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                    channelId: 'cashpix_notifications'
                  }
                },
                tokens: batch
              };

              const response = await firebaseAdmin.messaging().sendEachForMulticast(message);
              successCount += response.successCount;
              failureCount += response.failureCount;

              // Remover tokens inválidos
              const invalidTokenUpdates = [];
              response.responses.forEach((resp, idx) => {
                if (!resp.success) {
                  const errorCode = resp.error?.code;
                  if (errorCode === 'messaging/registration-token-not-registered' ||
                      errorCode === 'messaging/invalid-registration-token') {
                    invalidTokenUpdates.push(
                      db.query(
                        `UPDATE push_tokens SET is_active = false WHERE token = $1`,
                        [batch[idx]]
                      )
                    );
                  }
                }
              });
              // Aguardar remoção de tokens inválidos
              if (invalidTokenUpdates.length > 0) {
                await Promise.allSettled(invalidTokenUpdates);
              }
            } catch (fcmError) {
              console.error('[Scheduler] FCM batch error:', fcmError.message);
              failureCount += batch.length;
            }
          }
        } else {
          // Firebase não configurado — registrar mas não enviar
          successCount = 0;
          failureCount = tokens.length;
          console.warn(`[Scheduler] Firebase Admin não configurado. Notificação "${schedule.title}" NÃO enviada.`);
        }

        // Atualizar registro do agendamento com timestamp UTC (será convertido para Brasília na query)
        await db.query(
          `UPDATE scheduled_notifications SET last_sent_at = NOW(), total_sent = total_sent + 1 WHERE id = $1`,
          [schedule.id]
        );

        // Registrar no histórico de push
        await db.query(
          `INSERT INTO push_notifications (title, body, image_url, target_type, sent_count, success_count, failure_count)
           VALUES ($1, $2, $3, 'all (agendado)', $4, $5, $6)`,
          [schedule.title, schedule.body, schedule.image_url, tokens.length, successCount, failureCount]
        );

        console.log(`[Scheduler] Notificação "${schedule.title}" enviada: ${successCount} sucesso, ${failureCount} falha (${tokens.length} tokens)`);
      } catch (scheduleError) {
        console.error(`[Scheduler] Erro ao processar agendamento ${schedule.id}:`, scheduleError.message);
      }
    }
  } catch (error) {
    console.error('[Scheduler] Erro geral:', error.message);
  }
}

// =============================================================================
// Iniciar scheduler com intervalo de 60 segundos.
//
// CORREÇÃO: O setInterval puro pode "perder" o minuto exato se a execução
// anterior demorar ou se houver drift. Para garantir que o scheduler dispare
// exatamente no início de cada minuto, alinhamos o primeiro tick ao próximo
// segundo :00 e depois usamos intervalo de 60s.
// =============================================================================
function startScheduler() {
  const now = new Date();
  const msUntilNextMinute = (60 - now.getSeconds()) * 1000 - now.getMilliseconds();

  // Primeiro tick alinhado ao início do próximo minuto
  setTimeout(() => {
    processScheduledNotifications();
    // Depois, a cada 60 segundos
    setInterval(processScheduledNotifications, 60 * 1000);
  }, msUntilNextMinute);

  const brasilia = getBrasiliaTime();
  console.log(`[Scheduler] Notificações agendadas ativo. Horário atual de Brasília: ${brasilia.toTimeString().slice(0, 8)}. Próximo tick em ${Math.round(msUntilNextMinute / 1000)}s.`);
}

startScheduler();

module.exports = router;
