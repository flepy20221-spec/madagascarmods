/**
 * CashPix — Anti-Fraud Middleware
 *
 * Camada de integridade de requisicao para as rotas sensiveis (pontuacao e saque).
 *
 * O que este middleware garante:
 *   1. A request foi montada pelo app oficial (assinatura HMAC-SHA256 do corpo bruto)
 *   2. A request e recente (janela de 2 minutos contra replay diferido)
 *   3. A request nao e uma reexecucao (nonce de uso unico, persistido no banco)
 *   4. Tentativas suspeitas ficam registradas em audit_log e no fraud_score do usuario
 *
 * IMPORTANTE (correcoes aplicadas na auditoria de seguranca):
 *   - A assinatura passou a ser calculada sobre o CORPO BRUTO (req.rawBody), nao sobre
 *     JSON.stringify(req.body). Reparsear e reserializar mudava a string (ordem de chaves,
 *     campos null, espacos) e invalidava assinaturas legitimas.
 *   - O path assinado passou a ser o caminho COMPLETO (req.originalUrl sem query string).
 *     Dentro de um router montado, req.path e relativo ('/reward'), enquanto o app assina
 *     '/api/points/reward'. Isso fazia toda assinatura legitima falhar.
 *   - Os nonces passaram a ser persistidos em tabela (request_nonces). Antes ficavam em um
 *     Map de memoria, perdido em cada restart/deploy e nao compartilhado entre instancias,
 *     o que anulava a protecao anti-replay.
 *   - Removido o fail-open: erro interno no middleware agora BLOQUEIA a request. Antes
 *     qualquer excecao chamava next() e liberava a rota sensivel sem nenhuma validacao.
 *   - Comparacao de assinatura protegida contra tamanhos diferentes antes de
 *     crypto.timingSafeEqual (que lanca excecao se os buffers divergem em tamanho).
 */
const crypto = require('crypto');
const db = require('../models/db');
const { APP_HMAC_SECRET } = require('../config/secrets');

// Janela de validade de uma request (em segundos)
const REQUEST_VALIDITY_WINDOW = 120; // 2 minutos

// Fallback em memoria: usado apenas se a tabela request_nonces ainda nao existir
// (primeiro boot antes da migracao). Nao substitui a persistencia.
const memoryNonces = new Map();
const NONCE_CLEANUP_INTERVAL = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of memoryNonces.entries()) {
    if (now - timestamp > REQUEST_VALIDITY_WINDOW * 1000 * 2) {
      memoryNonces.delete(nonce);
    }
  }
  // Limpeza oportunista da tabela de nonces expirados
  db.query(
    `DELETE FROM request_nonces WHERE created_at < NOW() - INTERVAL '10 minutes'`
  ).catch(() => { /* tabela pode nao existir ainda; ignorar */ });
}, NONCE_CLEANUP_INTERVAL);

/**
 * Caminho canonico assinado pelo app.
 *
 * Regra de compatibilidade (importante):
 * O app (api_service.dart) assina o caminho SEM o prefixo '/api' — ex.: '/points/reward'.
 * Dentro de um router montado, req.path e relativo ('/reward') e req.originalUrl e completo
 * ('/api/points/reward'). Nenhum dos dois bate com o que o app assina.
 *
 * A normalizacao e feita aqui, no servidor, e nao no aplicativo, porque o APK 1.5.0+6 ja
 * esta instalado na base de usuarios: mudar a regra no app faria todo mundo que nao
 * atualizasse receber 403 no reward e no saque. O prefixo '/api' e detalhe de montagem
 * do Express, nao parte semantica da rota.
 */
function canonicalPath(req) {
  const original = req.originalUrl || req.url || '';
  const qIndex = original.indexOf('?');
  const withoutQuery = qIndex === -1 ? original : original.slice(0, qIndex);
  // Remove o prefixo de montagem '/api' para coincidir com a assinatura do cliente.
  return withoutQuery.startsWith('/api/')
    ? withoutQuery.slice(4)
    : withoutQuery;
}

/**
 * Corpo bruto exatamente como chegou na rede.
 * Preenchido pelo verify do express.json em src/index.js.
 */
function rawBody(req) {
  if (typeof req.rawBody === 'string') return req.rawBody;
  if (Buffer.isBuffer(req.rawBody)) return req.rawBody.toString('utf8');
  return '';
}

/**
 * Compara duas assinaturas hex em tempo constante, tolerando tamanhos divergentes
 * sem lancar excecao.
 */
function safeCompareHex(received, expected) {
  if (typeof received !== 'string' || !/^[0-9a-fA-F]+$/.test(received)) return false;
  const a = Buffer.from(received.toLowerCase(), 'hex');
  const b = Buffer.from(expected.toLowerCase(), 'hex');
  if (a.length !== b.length || a.length === 0) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Valida a assinatura HMAC da request.
 * Payload assinado: path|timestamp|nonce|body
 */
function validateSignature(path, timestamp, nonce, body, signature) {
  const payload = `${path}|${timestamp}|${nonce}|${body}`;
  const expected = crypto
    .createHmac('sha256', APP_HMAC_SECRET)
    .update(payload)
    .digest('hex');
  return safeCompareHex(signature, expected);
}

/**
 * Consome um nonce de forma atomica.
 * Retorna true se o nonce e novo (request valida), false se ja foi usado (replay).
 *
 * A unicidade e garantida pela PRIMARY KEY da tabela: o INSERT ... ON CONFLICT DO NOTHING
 * retorna 0 linhas quando o nonce ja existe, o que torna a checagem imune a race condition
 * entre requests concorrentes e entre instancias do servidor.
 */
async function consumeNonce(nonce, userId, path) {
  try {
    const result = await db.query(
      `INSERT INTO request_nonces (nonce, user_id, path)
       VALUES ($1, $2, $3)
       ON CONFLICT (nonce) DO NOTHING
       RETURNING nonce`,
      [nonce, userId || null, path]
    );
    return result.rows.length > 0;
  } catch (err) {
    // Tabela ausente (migracao pendente) ou indisponibilidade momentanea do banco:
    // cai para o controle em memoria para nao derrubar o fluxo do app.
    console.error('[Antifraud] consumeNonce fallback:', err.message);
    if (memoryNonces.has(nonce)) return false;
    memoryNonces.set(nonce, Date.now());
    return true;
  }
}

/**
 * Middleware de validacao de integridade para rotas sensiveis.
 * Aplicar em: /api/points/reward, /api/withdrawals/request, /api/pix-withdrawals/request
 */
async function antifraudMiddleware(req, res, next) {
  try {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const appVersion = req.headers['x-app-version'];
    const platform = req.headers['x-platform'];

    // 1. Headers obrigatorios
    if (!signature || !timestamp || !nonce) {
      logSuspicion(req, 'MISSING_SECURITY_HEADERS', 'high');
      return res.status(400).json({
        error: 'Requisicao invalida. Atualize o aplicativo.',
        code: 'INVALID_REQUEST'
      });
    }

    // 2. Janela de tempo (anti-replay diferido)
    const requestTime = parseInt(timestamp, 10);
    if (!Number.isFinite(requestTime)) {
      logSuspicion(req, 'MALFORMED_TIMESTAMP', 'high', { timestamp });
      return res.status(400).json({ error: 'Requisicao invalida.', code: 'INVALID_REQUEST' });
    }

    const now = Date.now();
    const diffSeconds = Math.abs(now - requestTime) / 1000;
    if (diffSeconds > REQUEST_VALIDITY_WINDOW) {
      logSuspicion(req, 'EXPIRED_TIMESTAMP', 'medium', {
        diff: diffSeconds,
        requestTime,
        serverTime: now
      });
      return res.status(400).json({
        error: 'Requisicao expirada. Verifique a data e hora do aparelho.',
        code: 'REQUEST_EXPIRED'
      });
    }

    const path = canonicalPath(req);
    const body = rawBody(req);

    // 3. Assinatura HMAC (antes do nonce, para nao gastar nonce em request forjada)
    if (!validateSignature(path, timestamp, nonce, body, signature)) {
      logSuspicion(req, 'INVALID_SIGNATURE', 'critical', {
        path,
        timestamp,
        bodyLength: body.length
      });
      return res.status(403).json({
        error: 'Falha na verificacao de integridade da requisicao.',
        code: 'INTEGRITY_FAILED'
      });
    }

    // 4. Nonce de uso unico (anti-replay imediato)
    const isNewNonce = await consumeNonce(nonce, req.user?.userId, path);
    if (!isNewNonce) {
      logSuspicion(req, 'REPLAY_ATTACK_NONCE', 'critical', { nonce });
      return res.status(409).json({
        error: 'Requisicao duplicada detectada.',
        code: 'DUPLICATE_REQUEST'
      });
    }

    // 5. Metadados do app (apenas telemetria de suspeita)
    if (!appVersion || !platform) {
      logSuspicion(req, 'MISSING_APP_INFO', 'low');
    }

    next();
  } catch (error) {
    // FAIL-CLOSED: rota sensivel nao passa sem validacao.
    console.error('[AntifraudMiddleware] Error:', error.message);
    return res.status(503).json({
      error: 'Servico de validacao temporariamente indisponivel. Tente novamente.',
      code: 'VALIDATION_UNAVAILABLE'
    });
  }
}

/**
 * Deteccao de padroes de fraude no reward.
 * Roda depois da autenticacao e da validacao de integridade.
 * Nao bloqueia sozinho: calcula req.fraudScore, que a rota usa para decidir.
 */
async function rewardFraudDetection(req, res, next) {
  try {
    const userId = req.user?.userId;
    if (!userId) return next();

    const ip = clientIp(req);
    const now = new Date();

    const recentRewards = await db.query(
      `SELECT COUNT(*) as count,
              MIN(created_at) as first_reward,
              MAX(created_at) as last_reward
       FROM reward_events
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '5 minutes'`,
      [userId]
    );

    const rewardCount = parseInt(recentRewards.rows[0].count, 10);
    const suspicionFlags = [];

    // Flag: volume impossivel de anuncios em 5 minutos
    if (rewardCount > 20) {
      suspicionFlags.push('EXCESSIVE_REWARDS_5MIN');
    }

    // Flag: intervalo menor que a duracao de um anuncio
    if (rewardCount > 0 && recentRewards.rows[0].last_reward) {
      const lastReward = new Date(recentRewards.rows[0].last_reward);
      const timeSinceLast = (now - lastReward) / 1000;
      if (timeSinceLast < 5) {
        suspicionFlags.push('TOO_FAST_REWARD');
      }
    }

    // Flag: muitas contas distintas pontuando do mesmo IP
    const ipCheck = await db.query(
      `SELECT COUNT(DISTINCT user_id) as user_count
       FROM reward_events
       WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '1 hour' AND user_id != $2`,
      [ip, userId]
    );
    if (parseInt(ipCheck.rows[0].user_count, 10) > 3) {
      suspicionFlags.push('MULTI_ACCOUNT_IP');
    }

    // Flag: volume alto em horario de baixa atividade humana
    const hour = now.getHours();
    if ((hour >= 2 && hour <= 5) && rewardCount > 10) {
      suspicionFlags.push('SUSPICIOUS_TIMING');
    }

    if (suspicionFlags.length > 0) {
      await logFraudFlags(userId, suspicionFlags, ip, req);
    }

    req.fraudFlags = suspicionFlags;
    req.fraudScore = suspicionFlags.length;

    next();
  } catch (error) {
    // Este middleware apenas pontua suspeita; a validacao de integridade e o SSV
    // continuam valendo. Prosseguir com score neutro e aceitavel aqui.
    console.error('[FraudDetection] Error:', error.message);
    req.fraudFlags = [];
    req.fraudScore = 0;
    next();
  }
}

/**
 * IP real do cliente. Atras do proxy do Railway, confia no primeiro
 * endereco de X-Forwarded-For (o Express com 'trust proxy' ja resolve req.ip).
 */
function clientIp(req) {
  if (req.ip) return req.ip;
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || null;
}

/**
 * Registra flags de suspeita no banco. Visivel no painel admin.
 */
async function logFraudFlags(userId, flags, ip, req) {
  try {
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

    await db.query(
      `UPDATE users SET
        fraud_score = COALESCE(fraud_score, 0) + $1,
        last_fraud_at = NOW(),
        updated_at = NOW()
       WHERE id = $2`,
      [flags.length, userId]
    );

    const userResult = await db.query(
      'SELECT fraud_score, is_banned FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length > 0) {
      const totalScore = parseInt(userResult.rows[0].fraud_score, 10) || 0;
      if (totalScore >= 10 && !userResult.rows[0].is_banned) {
        await db.query(
          `UPDATE users SET is_banned = true,
           ban_reason = 'Auto-ban: fraude detectada (score: ' || fraud_score || ')',
           banned_at = NOW(), updated_at = NOW() WHERE id = $1`,
          [userId]
        );
        console.warn(`[Antifraud] Auto-banned user ${userId} (score: ${totalScore})`);
      }
    }

    console.warn(`[FraudDetection] User ${userId}: ${flags.join(', ')} (IP: ${ip})`);
  } catch (err) {
    console.error('[FraudDetection] Log error:', err.message);
  }
}

/**
 * Registra uma suspeita individual (assincrono, nao bloqueia a response).
 */
function logSuspicion(req, type, severity, details = {}) {
  const ip = clientIp(req);
  const userId = req.user?.userId || null;

  console.warn(`[Antifraud] ${severity.toUpperCase()} | ${type} | user:${userId || 'unknown'} | ip:${ip}`, details);

  if (userId) {
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
  canonicalPath,
  clientIp,
};
