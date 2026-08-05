/**
 * CashPix — Bot/Automation Detection Middleware v2
 *
 * Detecta e bloqueia contas com comportamento de automação.
 *
 * DIFERENÇA DA v1: a detecção principal agora é PERSISTIDA NO BANCO,
 * não depende de cache em memória. Isso significa que:
 *   - Reiniciar o servidor não reseta os contadores
 *   - Atacante usando sleep(30s+) entre requests ainda é detectado
 *   - A métrica principal é: QUANTAS REQUESTS DE REWARD O USUÁRIO FEZ
 *     SEM NENHUM SSV CONFIRMADO PELO GOOGLE (em janela de 1 hora)
 *
 * Lógica:
 *   Um usuário legítimo faz POST /reward → Google envia SSV → reward_event criado.
 *   Um bot faz POST /reward → Google NUNCA envia SSV → nenhum reward_event.
 *   Se o usuário fez muitos POST /reward mas tem 0 reward_events com ssv_verified,
 *   é automação — independente do intervalo entre requests.
 *
 * Ações:
 *   - 5+ phantom rewards (sem SSV) em 1h → rate limit (1 req/60s)
 *   - 10+ phantom rewards em 1h → auto-ban permanente
 *   - 5+ logins do mesmo IP em 10 min → bloqueio de login
 */
const db = require('../models/db');

// Cache em memória para burst detection (complementar ao banco)
const burstTracker = new Map();
const BURST_CLEANUP_INTERVAL = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [userId, data] of burstTracker.entries()) {
    if (now - data.lastActivity > 10 * 60 * 1000) {
      burstTracker.delete(userId);
    }
  }
}, BURST_CLEANUP_INTERVAL);

/**
 * IP real do cliente.
 */
function clientIp(req) {
  if (req.ip) return req.ip;
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || null;
}

/**
 * Conta quantas requests de reward o usuário fez na última hora
 * que NÃO resultaram em SSV confirmado.
 *
 * Usa a tabela audit_log como registro de tentativas (BOT_REWARD_ATTEMPT).
 * Compara com reward_events (ssv_verified = true) no mesmo período.
 */
async function getPhantomRewardCount(userId) {
  try {
    // Contar tentativas de reward registradas na última hora
    const attempts = await db.query(
      `SELECT COUNT(*) as count FROM audit_log
       WHERE actor_id = $1
         AND action = 'BOT_REWARD_ATTEMPT'
         AND created_at > NOW() - INTERVAL '1 hour'`,
      [userId]
    );

    // Contar SSVs confirmados na última hora
    const confirmed = await db.query(
      `SELECT COUNT(*) as count FROM reward_events
       WHERE user_id = $1
         AND ssv_verified = true
         AND created_at > NOW() - INTERVAL '1 hour'`,
      [userId]
    );

    const attemptCount = parseInt(attempts.rows[0].count, 10);
    const confirmedCount = parseInt(confirmed.rows[0].count, 10);

    // Phantom = tentativas que não resultaram em SSV
    return {
      attempts: attemptCount,
      confirmed: confirmedCount,
      phantom: Math.max(0, attemptCount - confirmedCount),
    };
  } catch (err) {
    console.error('[BotDetection] getPhantomRewardCount error:', err.message);
    return { attempts: 0, confirmed: 0, phantom: 0 };
  }
}

/**
 * Registra uma tentativa de reward no audit_log.
 */
async function logRewardAttempt(userId, ip) {
  try {
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'user', 'BOT_REWARD_ATTEMPT', 'user', $1, $2, $3)`,
      [userId, JSON.stringify({ timestamp: new Date().toISOString() }), ip]
    );
  } catch (err) {
    // Não bloquear por falha de log
    console.error('[BotDetection] logRewardAttempt error:', err.message);
  }
}

/**
 * Auto-ban por automação detectada.
 */
async function autoBanUser(userId, reason, phantomCount, ip) {
  try {
    // Buscar email do usuário para o alerta
    const userInfo = await db.query('SELECT email FROM users WHERE id = $1', [userId]);
    const userEmail = userInfo.rows[0]?.email || 'desconhecido';

    await db.query(
      `UPDATE users SET
        is_banned = true,
        ban_reason = $2,
        fraud_score = COALESCE(fraud_score, 0) + $3,
        last_fraud_at = NOW(),
        banned_at = NOW(),
        updated_at = NOW()
       WHERE id = $1 AND is_banned = false`,
      [userId, reason, phantomCount]
    );

    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'system', 'BOT_AUTO_BAN', 'user', $1, $2, $3)`,
      [userId, JSON.stringify({ reason, phantomCount }), ip]
    );

    console.warn(`[BotDetection] AUTO-BANNED user ${userId} | Reason: ${reason} | Phantom: ${phantomCount}`);

    // ============ WEBHOOK DE ALERTA ============
    // Envia notificação para o admin quando um usuário é banido automaticamente.
    // Configure a URL do webhook via variável de ambiente BAN_WEBHOOK_URL.
    // Suporta Discord, Telegram Bot API, ou qualquer endpoint que aceite JSON POST.
    const webhookUrl = process.env.BAN_WEBHOOK_URL;
    if (webhookUrl) {
      const payload = webhookUrl.includes('discord.com')
        ? {
            embeds: [{
              title: '⚠️ Auto-Ban Executado',
              color: 0xFF0000,
              fields: [
                { name: 'Usuário', value: userEmail, inline: true },
                { name: 'ID', value: userId.substring(0, 8) + '...', inline: true },
                { name: 'Motivo', value: reason },
                { name: 'Score', value: String(phantomCount), inline: true },
                { name: 'IP', value: ip || 'N/A', inline: true },
              ],
              timestamp: new Date().toISOString()
            }]
          }
        : {
            event: 'auto_ban',
            userId,
            email: userEmail,
            reason,
            phantomCount,
            ip,
            timestamp: new Date().toISOString()
          };

      // Fire-and-forget (não bloqueia a resposta)
      fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).catch(err => console.error('[BotDetection] Webhook error:', err.message));
    }
  } catch (err) {
    console.error('[BotDetection] autoBanUser error:', err.message);
  }
}

/**
 * Middleware de detecção de bots para rotas de reward.
 */
async function botDetectionMiddleware(req, res, next) {
  try {
    const userId = req.user?.userId;
    if (!userId) return next();

    const ip = clientIp(req);
    const now = Date.now();

    // ===== VERIFICAR SE JÁ ESTÁ BANIDO =====
    const userCheck = await db.query(
      'SELECT is_banned FROM users WHERE id = $1',
      [userId]
    );
    if (userCheck.rows.length > 0 && userCheck.rows[0].is_banned) {
      return res.status(403).json({
        error: 'Conta suspensa.',
        code: 'ACCOUNT_BANNED',
      });
    }

    // ===== BURST DETECTION (em memória - para rajadas rápidas) =====
    // CORREÇÃO: O burst detection anterior usava threshold de 8 reqs/60s, que é
    // facilmente atingido por uso legítimo. Cenário real:
    //   - Vídeo rewarded de 5s → POST /reward + 2-3x GET /reward-status = 3-4 reqs
    //   - Usuário assiste 3 vídeos curtos em 60s = 9-12 reqs (BANIDO INDEVIDAMENTE)
    //
    // Correções aplicadas:
    //   1. Excluir requisições GET de polling (reward-status) do burst count
    //   2. Aumentar threshold para 25 reqs/60s (comportamento impossível sem automação)
    //   3. Não banir imediatamente — primeiro aplicar rate limit, só banir em 40+
    const isPollingRequest = req.method === 'GET' && req.path.includes('reward-status');

    if (!isPollingRequest) {
      if (!burstTracker.has(userId)) {
        burstTracker.set(userId, { requests: [], lastActivity: now });
      }
      const burst = burstTracker.get(userId);
      burst.lastActivity = now;
      burst.requests.push(now);
      // Limpar requests antigas (>60s)
      burst.requests = burst.requests.filter(t => t > now - 60000);

      // 40+ requests em 60s (excluindo polling) = automação certa → AUTO-BAN
      if (burst.requests.length >= 40) {
        console.warn(`[BotDetection] BURST detected for user ${userId} (${burst.requests.length} reqs in 60s)`);
        await autoBanUser(userId, `Auto-ban: burst de requests (${burst.requests.length} em 60s)`, burst.requests.length, ip);
        return res.status(403).json({
          error: 'Conta suspensa por atividade automatizada.',
          code: 'ACCOUNT_BANNED',
        });
      }

      // 25+ requests em 60s = rate limit temporário (sem ban, sem fraud_score)
      if (burst.requests.length >= 25) {
        console.warn(`[BotDetection] Rate limiting user ${userId} (${burst.requests.length} reqs in 60s)`);
        return res.status(429).json({
          error: 'Muitas solicitações. Aguarde alguns segundos.',
          code: 'BURST_RATE_LIMITED',
          retryAfter: 10,
        });
      }
    }

    // ===== PHANTOM REWARD DETECTION (persistido no banco) =====
    if (req.method === 'POST' && req.path.includes('reward')) {
      // CORREÇÃO: Apenas anúncios 'rewarded' possuem SSV do Google.
      // Interstitial e banner NUNCA recebem confirmação SSV por design do AdMob.
      // Registrar tentativas desses tipos geraria falsos positivos, pois o
      // phantom count subiria indefinidamente para uso legítimo do app.
      const adType = req.body?.ad_type;
      const isRewardedAd = adType === 'rewarded';

      // Registrar tentativa APENAS para anúncios rewarded
      if (isRewardedAd) {
        await logRewardAttempt(userId, ip);
      }

      // Verificar contagem de phantoms
      const { phantom, attempts, confirmed } = await getPhantomRewardCount(userId);

      // 10+ phantom rewards na última hora → AUTO-BAN
      if (phantom >= 10) {
        await autoBanUser(
          userId,
          `Auto-ban: automação detectada (${phantom} rewards sem confirmação SSV em 1h)`,
          phantom,
          ip
        );
        return res.status(403).json({
          error: 'Conta suspensa por atividade automatizada.',
          code: 'ACCOUNT_BANNED',
        });
      }

      // 5+ phantom rewards → rate limit agressivo (bloqueia se <60s desde a última)
      if (phantom >= 5) {
        const lastAttempt = await db.query(
          `SELECT created_at FROM audit_log
           WHERE actor_id = $1 AND action = 'BOT_REWARD_ATTEMPT'
           ORDER BY created_at DESC OFFSET 1 LIMIT 1`,
          [userId]
        );

        if (lastAttempt.rows.length > 0) {
          const lastTime = new Date(lastAttempt.rows[0].created_at).getTime();
          const diffSeconds = (now - lastTime) / 1000;

          if (diffSeconds < 60) {
            console.warn(`[BotDetection] Rate limited user ${userId} | Phantom: ${phantom} | Interval: ${diffSeconds.toFixed(1)}s`);

            // Incrementar fraud_score
            await db.query(
              `UPDATE users SET fraud_score = COALESCE(fraud_score, 0) + 1, last_fraud_at = NOW(), updated_at = NOW() WHERE id = $1`,
              [userId]
            ).catch(() => {});

            return res.status(429).json({
              error: 'Aguarde antes de tentar novamente.',
              code: 'RATE_LIMITED',
              retryAfter: 60,
            });
          }
        }
      }
    }

    // ===== EXCESSIVE POLLING (reward-status) =====
    if (req.path.includes('reward-status')) {
      const recentPolling = await db.query(
        `SELECT COUNT(*) as count FROM audit_log
         WHERE actor_id = $1 AND action = 'BOT_REWARD_ATTEMPT'
           AND created_at > NOW() - INTERVAL '5 minutes'`,
        [userId]
      );
      const pollingCount = parseInt(recentPolling.rows[0].count, 10);

      if (pollingCount >= 15) {
        return res.status(429).json({
          error: 'Muitas consultas. Aguarde.',
          code: 'EXCESSIVE_POLLING',
          retryAfter: 300,
        });
      }
    }

    next();
  } catch (error) {
    // Fail-open para não travar usuários legítimos por erro interno
    console.error('[BotDetection] Error:', error.message);
    next();
  }
}

/**
 * Middleware de detecção de bots no LOGIN.
 * Detecta criação em massa de contas do mesmo IP.
 */
async function loginBotDetection(req, res, next) {
  try {
    const ip = clientIp(req);
    if (!ip) return next();

    // Contar logins/registros deste IP nos últimos 10 minutos
    const recentLogins = await db.query(
      `SELECT COUNT(*) as count FROM users
       WHERE ip_address = $1 AND last_login_at > NOW() - INTERVAL '10 minutes'`,
      [ip]
    );

    const count = parseInt(recentLogins.rows[0]?.count || '0', 10);

    // Mais de 5 logins do mesmo IP em 10 min = suspeito
    if (count >= 5) {
      console.warn(`[BotDetection] Login rate limit for IP ${ip} (${count} logins in 10min)`);

      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
         VALUES ('system', 'system', 'LOGIN_RATE_LIMIT', 'ip', $1, $2, $1)`,
        [ip, JSON.stringify({ count, threshold: 5 })]
      ).catch(() => {});

      return res.status(429).json({
        error: 'Muitas tentativas de login. Aguarde alguns minutos.',
        code: 'LOGIN_RATE_LIMITED',
        retryAfter: 600,
      });
    }

    next();
  } catch (error) {
    console.error('[BotDetection] Login check error:', error.message);
    next();
  }
}

module.exports = {
  botDetectionMiddleware,
  loginBotDetection,
};
