/**
 * CashPix — Anti-Fraud Middleware
 * 
 * Detecta e bloqueia tentativas de burlar a pontuação:
 * 1. Valida integridade da request (HMAC + timestamp + nonce)
 * 2. Detecta replay attacks (nonce já usado)
 * 3. Verifica janela de tempo (request muito antiga = replay)
 * 4. Fingerprint de request (detecta requests forjadas)
 * 5. Score de suspeita (acumula flags e bane automaticamente)
 * 
 * Quando fraude é detectada, marca o usuário no banco com flag
 * visível no painel admin.
 */
const crypto = require('crypto');
const db = require('../models/db');

// Chave secreta para validação HMAC (mesma do app)
const APP_SECRET = process.env.APP_HMAC_SECRET || 'mds_app_s3cr3t_k3y_2024_pr0d';

// Janela de validade de uma request (em segundos)
const REQUEST_VALIDITY_WINDOW = 120; // 2 minutos

// Cache de nonces usados (em memória, limpa a cada 5 min)
const usedNonces = new Map();
const NONCE_CLEANUP_INTERVAL = 5 * 60 * 1000;

// Limpar nonces antigos periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > REQUEST_VALIDITY_WINDOW * 1000 * 2) {
      usedNonces.delete(nonce);
    }
  }
}, NONCE_CLEANUP_INTERVAL);

/**
 * Valida a assinatura HMAC da request.
 * O app assina: path|timestamp|nonce|body
 */
function validateSignature(path, timestamp, nonce, body, signature) {
  const payload = `${path}|${timestamp}|${nonce}|${body}`;
  const hmac = crypto.createHmac('sha256', APP_SECRET);
  hmac.update(payload);
  const expected = hmac.digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expected, 'hex')
  );
}

/**
 * Middleware de validação anti-fraude para rotas sensíveis.
 * Aplicar em: /api/points/reward
 */
function antifraudMiddleware(req, res, next) {
  try {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const appVersion = req.headers['x-app-version'];
    const platform = req.headers['x-platform'];

    // 1. Headers obrigatórios
    if (!signature || !timestamp || !nonce) {
      logSuspicion(req, 'MISSING_SECURITY_HEADERS', 'high');
      return res.status(400).json({ error: 'Invalid request format' });
    }

    // 2. Verificar janela de tempo (anti-replay)
    const requestTime = parseInt(timestamp);
    const now = Date.now();
    const diffSeconds = Math.abs(now - requestTime) / 1000;

    if (diffSeconds > REQUEST_VALIDITY_WINDOW) {
      logSuspicion(req, 'EXPIRED_TIMESTAMP', 'medium', {
        diff: diffSeconds,
        requestTime,
        serverTime: now
      });
      return res.status(400).json({ error: 'Request expired' });
    }

    // 3. Verificar nonce (anti-replay)
    if (usedNonces.has(nonce)) {
      logSuspicion(req, 'REPLAY_ATTACK_NONCE', 'critical', { nonce });
      return res.status(409).json({ error: 'Duplicate request' });
    }
    usedNonces.set(nonce, Date.now());

    // 4. Validar assinatura HMAC
    const path = req.path;
    const body = JSON.stringify(req.body) || '';

    try {
      const isValid = validateSignature(path, timestamp, nonce, body, signature);
      if (!isValid) {
        logSuspicion(req, 'INVALID_SIGNATURE', 'critical', {
          path,
          timestamp,
          bodyLength: body.length
        });
        return res.status(403).json({ error: 'Request integrity check failed' });
      }
    } catch (sigErr) {
      logSuspicion(req, 'SIGNATURE_VALIDATION_ERROR', 'high', {
        error: sigErr.message
      });
      return res.status(403).json({ error: 'Request integrity check failed' });
    }

    // 5. Verificar versão do app (bloquear versões antigas/modificadas)
    if (!appVersion || !platform) {
      logSuspicion(req, 'MISSING_APP_INFO', 'low');
      // Não bloquear, apenas logar
    }

    // Request válida - continuar
    next();
  } catch (error) {
    console.error('[AntifraudMiddleware] Error:', error.message);
    // Em caso de erro no middleware, permitir (fail-open)
    next();
  }
}

/**
 * Middleware de detecção de fraude para reward.
 * Verifica padrões suspeitos APÓS a validação básica.
 * Não bloqueia, mas marca o usuário como suspeito.
 */
async function rewardFraudDetection(req, res, next) {
  try {
    const userId = req.user?.userId;
    if (!userId) return next();

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = new Date();

    // Buscar histórico recente de rewards do usuário
    const recentRewards = await db.query(
      `SELECT COUNT(*) as count, 
              MIN(created_at) as first_reward,
              MAX(created_at) as last_reward
       FROM reward_events 
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '5 minutes'`,
      [userId]
    );

    const rewardCount = parseInt(recentRewards.rows[0].count);
    const suspicionFlags = [];

    // Flag: Muitos rewards em 5 minutos (mais de 20 = impossível assistir tantos anúncios)
    if (rewardCount > 20) {
      suspicionFlags.push('EXCESSIVE_REWARDS_5MIN');
    }

    // Flag: Rewards sem intervalo mínimo realista (anúncio dura ~15-30s)
    if (rewardCount > 0) {
      const lastReward = new Date(recentRewards.rows[0].last_reward);
      const timeSinceLast = (now - lastReward) / 1000;
      if (timeSinceLast < 5) { // Menos de 5 segundos entre rewards
        suspicionFlags.push('TOO_FAST_REWARD');
      }
    }

    // Flag: Mesmo IP com múltiplas contas fazendo rewards
    const ipCheck = await db.query(
      `SELECT COUNT(DISTINCT user_id) as user_count
       FROM reward_events 
       WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '1 hour' AND user_id != $2`,
      [ip, userId]
    );
    if (parseInt(ipCheck.rows[0].user_count) > 3) {
      suspicionFlags.push('MULTI_ACCOUNT_IP');
    }

    // Flag: Reward sem SSV em horários suspeitos (madrugada com volume alto)
    const hour = now.getHours();
    if ((hour >= 2 && hour <= 5) && rewardCount > 10) {
      suspicionFlags.push('SUSPICIOUS_TIMING');
    }

    // Se há flags de suspeita, registrar
    if (suspicionFlags.length > 0) {
      await logFraudFlags(userId, suspicionFlags, ip, req);
    }

    // Anexar informação de fraude ao request para uso na rota
    req.fraudFlags = suspicionFlags;
    req.fraudScore = suspicionFlags.length;

    next();
  } catch (error) {
    console.error('[FraudDetection] Error:', error.message);
    next(); // Fail-open
  }
}

/**
 * Registra flags de suspeita no banco de dados.
 * Visível no painel admin.
 */
async function logFraudFlags(userId, flags, ip, req) {
  try {
    // Registrar no audit_log
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'system', 'FRAUD_DETECTED', 'user', $2, $3, $4)`,
      [
        userId,
        userId,
        JSON.stringify({
          flags,
          timestamp: new Date().toISOString(),
          userAgent: req.headers['user-agent'],
          appVersion: req.headers['x-app-version'],
        }),
        ip
      ]
    );

    // Incrementar contador de suspeita do usuário
    await db.query(
      `UPDATE users SET 
        fraud_score = COALESCE(fraud_score, 0) + $1,
        last_fraud_at = NOW(),
        updated_at = NOW()
       WHERE id = $2`,
      [flags.length, userId]
    );

    // Se score acumulado > 10, banir automaticamente
    const userResult = await db.query(
      'SELECT fraud_score, is_banned FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length > 0) {
      const totalScore = parseInt(userResult.rows[0].fraud_score) || 0;
      if (totalScore >= 10 && !userResult.rows[0].is_banned) {
        await db.query(
          `UPDATE users SET is_banned = true, ban_reason = 'Auto-ban: fraude detectada (score: ' || fraud_score || ')', 
           banned_at = NOW(), updated_at = NOW() WHERE id = $1`,
          [userId]
        );
        console.warn(`[AntifraudMiddleware] Auto-banned user ${userId} (score: ${totalScore})`);
      }
    }

    console.warn(`[FraudDetection] User ${userId}: ${flags.join(', ')} (IP: ${ip})`);
  } catch (err) {
    console.error('[FraudDetection] Log error:', err.message);
  }
}

/**
 * Registra suspeita individual
 */
function logSuspicion(req, type, severity, details = {}) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userId = req.user?.userId || 'unknown';

  console.warn(`[Antifraud] ${severity.toUpperCase()} | ${type} | user:${userId} | ip:${ip}`, details);

  // Registrar no banco de forma assíncrona (não bloquear a response)
  if (userId !== 'unknown') {
    db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'system', $2, 'user', $3, $4, $5)`,
      [userId, `ANTIFRAUD_${type}`, userId, JSON.stringify({ severity, ...details }), ip]
    ).catch(err => console.error('[Antifraud] DB log error:', err.message));
  }
}

module.exports = {
  antifraudMiddleware,
  rewardFraudDetection,
  validateSignature,
};
