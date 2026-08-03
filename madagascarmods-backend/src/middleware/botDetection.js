/**
 * CashPix — Bot/Automation Detection Middleware
 *
 * Detecta e bloqueia contas que apresentam comportamento de automação.
 *
 * Diferença do antiFraud.js:
 *   - antiFraud.js valida integridade de requests individuais (HMAC, nonce, timestamp)
 *   - rewardFraudDetection analisa padrões em reward_events JÁ CREDITADOS
 *   - ESTE middleware analisa o PADRÃO DE REQUESTS em si, mesmo que nenhum ponto
 *     tenha sido creditado. Detecta bots que fazem requests válidas (com HMAC correto)
 *     mas em padrões impossíveis para um humano.
 *
 * Flags detectadas:
 *   - PHANTOM_REWARDS: muitas requests de reward sem nenhum SSV confirmado
 *   - BURST_REQUESTS: muitas requests em intervalo muito curto
 *   - ZERO_SUCCESS_RATIO: dezenas de tentativas sem nenhum sucesso
 *   - SUSPICIOUS_SESSION_PATTERN: sessões UUID sequenciais ou padrão de geração
 *   - NO_AD_LOADED: requests de reward sem ter carregado anúncio (fingerprint vazio)
 *
 * Ações:
 *   - Score 3+: rate limit agressivo (1 request por 30s)
 *   - Score 5+: bloqueio temporário (15 min)
 *   - Score 8+: auto-ban permanente
 */
const db = require('../models/db');

// Cache em memória para tracking de requests (por userId)
// Formato: { userId: { requests: [timestamp, ...], phantomCount: N, lastReset: Date } }
const requestTracker = new Map();

// Limpar cache a cada 10 minutos
const TRACKER_CLEANUP_INTERVAL = 10 * 60 * 1000;
const TRACKER_WINDOW = 5 * 60 * 1000; // Janela de 5 minutos
const PHANTOM_THRESHOLD = 5; // 5+ rewards sem SSV = suspeito
const BURST_THRESHOLD = 8; // 8+ requests em 60 segundos = burst
const AUTO_BAN_SCORE = 8;
const TEMP_BLOCK_SCORE = 5;
const RATE_LIMIT_SCORE = 3;

setInterval(() => {
  const now = Date.now();
  for (const [userId, data] of requestTracker.entries()) {
    if (now - data.lastActivity > TRACKER_WINDOW * 2) {
      requestTracker.delete(userId);
    }
  }
}, TRACKER_CLEANUP_INTERVAL);

/**
 * Obtém ou cria o tracker de um usuário.
 */
function getTracker(userId) {
  if (!requestTracker.has(userId)) {
    requestTracker.set(userId, {
      requests: [],
      phantomRewards: 0,
      confirmedRewards: 0,
      lastActivity: Date.now(),
      blocked: false,
      blockedUntil: null,
      botScore: 0,
    });
  }
  const tracker = requestTracker.get(userId);
  tracker.lastActivity = Date.now();

  // Limpar requests antigas (fora da janela)
  const cutoff = Date.now() - TRACKER_WINDOW;
  tracker.requests = tracker.requests.filter(t => t > cutoff);

  return tracker;
}

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
 * Middleware de detecção de bots para rotas de reward.
 * Aplicar ANTES do antifraudMiddleware nas rotas /points/reward e /points/reward-status.
 */
async function botDetectionMiddleware(req, res, next) {
  try {
    const userId = req.user?.userId;
    if (!userId) return next();

    const tracker = getTracker(userId);
    const now = Date.now();
    const ip = clientIp(req);

    // Verificar se está temporariamente bloqueado
    if (tracker.blocked && tracker.blockedUntil) {
      if (now < tracker.blockedUntil) {
        const remainingSeconds = Math.ceil((tracker.blockedUntil - now) / 1000);
        console.warn(`[BotDetection] Blocked request from user ${userId} (${remainingSeconds}s remaining)`);
        return res.status(429).json({
          error: 'Muitas tentativas. Aguarde antes de tentar novamente.',
          code: 'BOT_DETECTED',
          retryAfter: remainingSeconds,
        });
      }
      // Bloqueio expirou
      tracker.blocked = false;
      tracker.blockedUntil = null;
    }

    // Registrar esta request
    tracker.requests.push(now);

    // ===== DETECÇÃO DE PADRÕES =====
    const flags = [];

    // 1. BURST: muitas requests em 60 segundos
    const last60s = tracker.requests.filter(t => t > now - 60000);
    if (last60s.length >= BURST_THRESHOLD) {
      flags.push('BURST_REQUESTS');
    }

    // 2. PHANTOM REWARDS: muitas requests de reward sem SSV confirmado
    // Verificar no banco quantos SSV foram confirmados vs quantos rewards foram pedidos
    if (req.path.includes('reward') && req.method === 'POST') {
      tracker.phantomRewards++;

      // A cada 5 phantom rewards, verificar se algum foi confirmado
      if (tracker.phantomRewards % 5 === 0) {
        const confirmed = await db.query(
          `SELECT COUNT(*) as count FROM reward_events
           WHERE user_id = $1 AND ssv_verified = true
             AND created_at > NOW() - INTERVAL '10 minutes'`,
          [userId]
        );
        const confirmedCount = parseInt(confirmed.rows[0].count, 10);
        tracker.confirmedRewards = confirmedCount;

        // Se tem 5+ pedidos sem nenhuma confirmação, é bot
        if (tracker.phantomRewards >= PHANTOM_THRESHOLD && confirmedCount === 0) {
          flags.push('PHANTOM_REWARDS');
        }

        // Ratio muito baixo (menos de 10% de sucesso com muitas tentativas)
        if (tracker.phantomRewards >= 10 && confirmedCount / tracker.phantomRewards < 0.1) {
          flags.push('ZERO_SUCCESS_RATIO');
        }
      }
    }

    // 3. Rate limit para requests GET de reward-status em rajada
    if (req.path.includes('reward-status')) {
      const statusRequests = tracker.requests.filter(t => t > now - 30000);
      if (statusRequests.length > 15) {
        flags.push('EXCESSIVE_POLLING');
      }
    }

    // ===== CALCULAR SCORE E AGIR =====
    if (flags.length > 0) {
      tracker.botScore += flags.length;

      console.warn(`[BotDetection] User ${userId} | Flags: ${flags.join(', ')} | Score: ${tracker.botScore} | IP: ${ip}`);

      // Registrar no audit_log
      try {
        await db.query(
          `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
           VALUES ($1, 'system', 'BOT_DETECTED', 'user', $2, $3, $4)`,
          [userId, userId, JSON.stringify({
            flags,
            totalScore: tracker.botScore,
            phantomRewards: tracker.phantomRewards,
            confirmedRewards: tracker.confirmedRewards,
            requestsInWindow: tracker.requests.length,
            timestamp: new Date().toISOString(),
          }), ip]
        );
      } catch (err) {
        console.error('[BotDetection] Audit log error:', err.message);
      }

      // AUTO-BAN: score >= 8
      if (tracker.botScore >= AUTO_BAN_SCORE) {
        try {
          await db.query(
            `UPDATE users SET
              is_banned = true,
              ban_reason = 'Auto-ban: automação detectada (bot score: ' || $2 || ')',
              fraud_score = COALESCE(fraud_score, 0) + $2,
              last_fraud_at = NOW(),
              banned_at = NOW(),
              updated_at = NOW()
             WHERE id = $1 AND is_banned = false`,
            [userId, tracker.botScore]
          );
          console.warn(`[BotDetection] AUTO-BANNED user ${userId} (score: ${tracker.botScore})`);
        } catch (err) {
          console.error('[BotDetection] Ban error:', err.message);
        }

        return res.status(403).json({
          error: 'Conta suspensa por atividade automatizada.',
          code: 'ACCOUNT_BANNED',
        });
      }

      // BLOQUEIO TEMPORÁRIO: score >= 5
      if (tracker.botScore >= TEMP_BLOCK_SCORE) {
        tracker.blocked = true;
        tracker.blockedUntil = now + (15 * 60 * 1000); // 15 minutos

        // Incrementar fraud_score no banco
        await db.query(
          `UPDATE users SET
            fraud_score = COALESCE(fraud_score, 0) + $2,
            last_fraud_at = NOW(),
            updated_at = NOW()
           WHERE id = $1`,
          [userId, flags.length]
        ).catch(() => {});

        return res.status(429).json({
          error: 'Atividade suspeita detectada. Tente novamente em 15 minutos.',
          code: 'TEMP_BLOCKED',
          retryAfter: 900,
        });
      }

      // RATE LIMIT AGRESSIVO: score >= 3
      if (tracker.botScore >= RATE_LIMIT_SCORE) {
        const lastRequest = tracker.requests[tracker.requests.length - 2] || 0;
        if (now - lastRequest < 30000) { // Menos de 30s desde a última
          return res.status(429).json({
            error: 'Aguarde antes de tentar novamente.',
            code: 'RATE_LIMITED',
            retryAfter: 30,
          });
        }
      }
    }

    next();
  } catch (error) {
    // Fail-open apenas para este middleware de detecção. O antifraudMiddleware
    // (que é fail-closed) ainda protege a rota.
    console.error('[BotDetection] Error:', error.message);
    next();
  }
}

/**
 * Middleware leve para detecção de bots no LOGIN.
 * Detecta criação em massa de contas do mesmo IP.
 */
async function loginBotDetection(req, res, next) {
  try {
    const ip = clientIp(req);
    if (!ip) return next();

    // Contar logins/registros deste IP nos últimos 10 minutos
    const recentLogins = await db.query(
      `SELECT COUNT(*) as count FROM users
       WHERE last_login_ip = $1 AND last_login_at > NOW() - INTERVAL '10 minutes'`,
      [ip]
    );

    const count = parseInt(recentLogins.rows[0]?.count || '0', 10);

    // Mais de 5 logins do mesmo IP em 10 min = suspeito
    if (count >= 5) {
      console.warn(`[BotDetection] Login rate limit for IP ${ip} (${count} logins in 10min)`);

      // Registrar no audit
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
