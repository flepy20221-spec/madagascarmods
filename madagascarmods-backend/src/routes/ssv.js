/**
 * CashPix — AdMob Server-Side Verification (SSV) Callback
 * 
 * Esta rota recebe callbacks diretamente do Google quando um usuário
 * assiste um anúncio rewarded completo. É a forma mais segura de
 * validar que o anúncio foi realmente assistido.
 * 
 * URL a configurar no AdMob: 
 * https://madagascarmods-production.up.railway.app/api/ssv/callback
 */
const crypto = require('crypto');
const express = require('express');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const db = require('../models/db');
const {
  validateSsvCallback,
  fetchGoogleKeys,
  verifySsvSignature,
} = require('../utils/admobSsv');
const { drawRewardPoints, POINT_VALUES } = require('../utils/pointsRandom');

const router = express.Router();

/**
 * custom_data v2: `<user_uuid>:<reward_session_uuid>`.
 *
 * APKs antigos enviam apenas o UUID do usuario; eles continuam aceitos, mas nao
 * possuem correlacao de sessao e usam o endpoint legado de confirmacao.
 */
function parseSsvIdentity(customData, fallbackUserId) {
  const raw = String(customData || fallbackUserId || '').trim();
  if (!raw) return null;

  const parts = raw.split(':');
  if (parts.length === 1 && uuidValidate(parts[0])) {
    return { userId: parts[0], rewardSessionId: null, version: 1 };
  }

  if (parts.length === 2 && uuidValidate(parts[0]) && uuidValidate(parts[1])) {
    return { userId: parts[0], rewardSessionId: parts[1], version: 2 };
  }

  return null;
}

/**
 * Descreve a ESTRUTURA de uma query crua de SSV sem expor PII nem material de
 * assinatura. Usado apenas quando a verificação falha, para diagnosticar ordem
 * de parâmetros, parâmetros inesperados e normalização feita por proxies.
 *
 * Campos sensíveis viram metadados: comprimento, presença de percent-encoding e
 * um prefixo curto. Nunca o valor completo.
 */
function redactRawQuery(rawQueryString) {
  if (typeof rawQueryString !== 'string' || rawQueryString.length === 0) {
    return { present: false };
  }

  const SENSITIVE = new Set(['signature', 'custom_data', 'user_id']);
  const pairs = rawQueryString.split('&');

  return {
    present: true,
    totalLength: rawQueryString.length,
    paramCount: pairs.length,
    // Ordem exata das chaves — revela se signature/key_id são os dois últimos.
    keyOrder: pairs.map((pair) => {
      const eq = pair.indexOf('=');
      return eq >= 0 ? pair.slice(0, eq) : pair;
    }),
    params: pairs.map((pair) => {
      const eq = pair.indexOf('=');
      const key = eq >= 0 ? pair.slice(0, eq) : pair;
      const value = eq >= 0 ? pair.slice(eq + 1) : '';

      const meta = {
        key,
        valueLength: value.length,
        hasPercentEncoding: /%[0-9A-Fa-f]{2}/.test(value),
        hasPlus: value.includes('+'),
      };

      if (!SENSITIVE.has(key)) {
        meta.value = value;
      } else {
        meta.prefix = value.slice(0, 8);
      }

      return meta;
    }),
  };
}

/**
 * Descreve a MENSAGEM CANÔNICA que foi submetida à verificação ECDSA e testa
 * variantes de normalização comuns de proxy. Objetivo: descobrir se algum byte
 * de `req.originalUrl` difere do que o Google assinou.
 *
 * Não expõe a mensagem completa. Expõe o SHA-256 dela (permite comparar sem
 * revelar conteúdo) e sinalizadores de normalização.
 */
function describeCanonicalMessage(rawQueryString) {
  if (typeof rawQueryString !== 'string' || rawQueryString.length === 0) {
    return { present: false };
  }

  const marker = '&signature=';
  const idx = rawQueryString.lastIndexOf(marker);
  if (idx <= 0) {
    return { present: true, hasSignatureMarker: false };
  }

  const message = rawQueryString.slice(0, idx);

  // Percent-encodings encontrados, com o caso original preservado. O Google
  // assina os bytes exatos; se o proxy trocar %3A por %3a a assinatura quebra.
  const escapes = message.match(/%[0-9A-Fa-f]{2}/g) || [];
  const uniqueEscapes = Array.from(new Set(escapes));

  return {
    present: true,
    hasSignatureMarker: true,
    messageLength: message.length,
    // Hash permite comparar mensagens entre tentativas sem expor conteúdo.
    sha256: crypto.createHash('sha256').update(message, 'utf8').digest('hex'),
    // Detecção de normalização de caixa no percent-encoding.
    escapes: uniqueEscapes,
    hasLowercaseEscape: uniqueEscapes.some((e) => /%[0-9a-f]*[a-f]/.test(e)),
    hasUppercaseEscape: uniqueEscapes.some((e) => /%[0-9A-F]*[A-F]/.test(e)),
    // Caracteres fora do ASCII imprimível indicariam corrupção de encoding.
    hasNonAscii: /[^\x20-\x7E]/.test(message),
    hasSpace: message.includes(' '),
    // Primeiros e últimos bytes ajudam a detectar prefixo/sufixo inesperado.
    head: message.slice(0, 24),
    tail: message.slice(-24),
  };
}

/**
 * TESTE DEFINITIVO: tenta verificar a assinatura real contra VARIANTES da
 * mensagem canônica, direto no servidor.
 *
 * Estado do diagnóstico que motiva esta função: chave (`key_id=3335741209`,
 * P-256), digest (SHA-256), formato da assinatura (DER base64url), ordem dos
 * parâmetros e o corte antes de `&signature=` foram TODOS verificados e estão
 * corretos — o comprimento da canônica (244) e o total (368) conferem
 * aritmeticamente com a soma dos campos. Ainda assim a verificação falha.
 *
 * Logo, a assinatura não corresponde à string que reconstruímos. Esta função
 * enumera as variações plausíveis e reporta qual delas (se alguma) valida.
 * Roda apenas no caminho de falha, e não expõe a assinatura nem `custom_data`.
 */

/**
 * Cache do keyset resolvido, populado no caminho de falha. Evita tornar o probe
 * assíncrono e manter o keyset em memória por requisição.
 */
let probeKeysCache = null;

function verifyWithKeyId(message, signature, keyId) {
  if (!probeKeysCache) return 'keys unavailable';
  const entry = probeKeysCache.find((k) => String(k.keyId) === String(keyId));
  if (!entry) return `key ${keyId} not in keyset`;
  return verifySsvSignature(message, signature, entry);
}

function probeSignatureVariants(rawQueryString, queryParams) {
  try {
    const marker = '&signature=';
    const idx = rawQueryString.lastIndexOf(marker);
    if (idx <= 0) return { probed: false, reason: 'no signature marker' };

    const base = rawQueryString.slice(0, idx);
    const signature = queryParams.signature;
    const keyId = queryParams.key_id;
    if (!signature || !keyId) return { probed: false, reason: 'missing signature/key_id' };

    const variants = {
      // 1. Exatamente como recebido (o que falha hoje).
      asReceived: base,
      // 2. `user_id` vazio anexado: o Google pode assinar o par mesmo sem valor.
      userIdEmptyAppended: `${base}&user_id=`,
      // 3. `user_id` vazio na posição canônica (após transaction_id, antes de signature).
      //    A ordem documentada é alfabética, e `user_id` viria depois de `transaction_id`.
      userIdEmptyCanonical: base.replace(
        /(&transaction_id=[^&]*)/,
        '$1&user_id='
      ),
      // 4. Percent-encoding em minúsculas (caso algum proxy intermediário normalize).
      lowercaseEscapes: base.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toLowerCase()),
      // 5. Percent-encoding em maiúsculas.
      uppercaseEscapes: base.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toUpperCase()),
      // 6. `custom_data` decodificado (`%3A` -> `:`), caso o Google assine o valor cru.
      decodedCustomData: base.replace(/%3A/gi, ':'),
      // 7. Query inteira decodificada.
      fullyDecoded: (() => {
        try { return decodeURIComponent(base); } catch { return base; }
      })(),
      // 8. Prefixada com o caminho, caso a assinatura cubra mais que a query.
      withPathPrefix: `/api/ssv/callback?${base}`,
    };

    const results = {};
    for (const [name, message] of Object.entries(variants)) {
      try {
        // Reaproveita o verificador real do módulo para evitar divergência de
        // implementação entre o diagnóstico e o caminho de produção.
        results[name] = verifyWithKeyId(message, signature, keyId);
      } catch (err) {
        results[name] = `error: ${err.message}`;
      }
    }

    const winner = Object.entries(results).find(([, v]) => v === true);
    return {
      probed: true,
      results,
      matchingVariant: winner ? winner[0] : null,
    };
  } catch (err) {
    return { probed: false, reason: err.message };
  }
}

// GET /api/ssv/callback - AdMob SSV callback (chamado pelo Google)
// O Google envia via GET com query params assinados
router.get('/callback', async (req, res) => {
  try {
    const queryParams = req.query;

    // Registrar somente metadados operacionais; a assinatura completa e os dados
    // do usuário não devem aparecer nos logs de produção.
    console.log('[SSV] Callback received', {
      adUnit: queryParams.ad_unit || null,
      transactionId: queryParams.transaction_id || null,
      keyId: queryParams.key_id || null,
      hasUserData: Boolean(queryParams.custom_data || queryParams.user_id)
    });

    // A verificação criptográfica precisa dos bytes exatos da query antes de
    // `&signature=`. `req.query` já foi decodificado pelo Express e não serve
    // como fonte canônica quando há percent-encoding em custom_data/user_id.
    const queryStart = req.originalUrl.indexOf('?');
    const rawQueryString = queryStart >= 0 ? req.originalUrl.slice(queryStart + 1) : '';
    const validation = await validateSsvCallback(queryParams, rawQueryString);

    if (!validation.valid) {
      console.warn('[SSV] Invalid callback:', validation.error);
      // Diagnóstico estrutural (sem PII) para falhas de assinatura. Sem estes
      // dados é impossível distinguir ordem de parâmetros de normalização do proxy.
      if (validation.error === 'Signature verification failed') {
        console.warn('[SSV] Diagnostic', JSON.stringify(redactRawQuery(rawQueryString)));
        console.warn('[SSV] Canonical', JSON.stringify(describeCanonicalMessage(rawQueryString)));
        // Teste de variantes: revela se ALGUMA forma da mensagem valida com a
        // assinatura recebida. Se nenhuma validar, o problema não está na
        // construção da mensagem e sim na origem do callback.
        try {
          probeKeysCache = await fetchGoogleKeys();
        } catch (err) {
          probeKeysCache = null;
          console.warn('[SSV] Probe keyset fetch failed:', err.message);
        }
        console.warn(
          '[SSV] Probe',
          JSON.stringify(probeSignatureVariants(rawQueryString, queryParams))
        );
      }
      // Retornar 200 mesmo em caso de erro para o Google não retentar
      return res.status(200).json({ success: false, error: validation.error });
    }

    const { data } = validation;

    // `messageForm` indica se a assinatura validou sobre a query crua ou sobre a
    // decodificada. Em callbacks com `custom_data` percent-encoded o esperado é
    // `decoded`, conforme a implementação de referência do AdMob.
    console.log('[SSV] Signature verified', { messageForm: validation.messageForm });

    // Extrair identidade e sessao do custom_data. O formato v2 permite ao app
    // consultar exatamente o anuncio atual; o formato v1 preserva APKs existentes.
    const identity = parseSsvIdentity(data.customData, data.userId);
    if (!identity) {
      console.warn('[SSV] Missing or malformed user/session identity');
      return res.status(200).json({ success: false, error: 'Invalid user identity' });
    }
    const { userId, rewardSessionId } = identity;

    // Verificar transaction_id e sessao antes da transacao para responder de forma
    // idempotente. Os indices UNIQUE continuam sendo a protecao atomica definitiva.
    if (data.transactionId || rewardSessionId) {
      const existing = await db.query(
        `SELECT id FROM reward_events
          WHERE ($1::text IS NOT NULL AND ssv_transaction_id = $1)
             OR ($2::uuid IS NOT NULL AND reward_session_id = $2)
          LIMIT 1`,
        [data.transactionId || null, rewardSessionId]
      );

      if (existing.rows.length > 0) {
        console.log('[SSV] Duplicate callback ignored');
        return res.status(200).json({ success: true, message: 'Already processed' });
      }
    }

    // Verificar se o usuário existe e não está banido
    const userCheck = await db.query(
      'SELECT id, is_banned, is_active FROM users WHERE id = $1',
      [userId]
    );

    if (userCheck.rows.length === 0) {
      console.warn('[SSV] User not found:', userId);
      return res.status(200).json({ success: false, error: 'User not found' });
    }

    if (userCheck.rows[0].is_banned || !userCheck.rows[0].is_active) {
      console.warn('[SSV] User banned/inactive:', userId);
      return res.status(200).json({ success: false, error: 'User banned' });
    }

    // Sortear pontos
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key = 'reward_points_multiplier'"
    );
    const multiplier = configResult.rows.length > 0 
      ? Number(JSON.parse(configResult.rows[0].value)) || 1 
      : 1;

    const draw = drawRewardPoints({ multiplier });
    const pointsToAward = draw.points;

    // Creditar pontos via SSV (verificado pelo Google)
    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      // Registrar evento de reward com SSV verificado
      const eventId = uuidv4();
      await client.query(
        `INSERT INTO reward_events
           (id, user_id, ad_type, ad_network, ad_unit_id, points_awarded,
            ssv_token, ssv_verified, ssv_transaction_id, reward_session_id, ip_address)
         VALUES ($1, $2, 'rewarded', $3, $4, $5, $6, true, $7, $8, $9)`,
        [
          eventId, userId,
          data.adNetwork || 'admob',
          data.adUnit || null,
          pointsToAward,
          JSON.stringify(queryParams),
          data.transactionId || null,
          rewardSessionId,
          req.headers['x-forwarded-for'] || req.socket.remoteAddress
        ]
      );

      // Creditar no ledger
      const ledgerId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, $3, 'REWARD_SSV', $4, 'Rewarded ad (SSV verified)')`,
        [ledgerId, userId, pointsToAward, eventId]
      );

      await client.query('COMMIT');

      console.log('[SSV] Reward credited', {
        points: pointsToAward,
        sessionCorrelated: Boolean(rewardSessionId),
        customDataVersion: identity.version
      });

      // Retornar 200 para o Google saber que processamos
      res.status(200).json({ success: true, pointsAwarded: pointsToAward });
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '23505') {
        console.log('[SSV] Concurrent duplicate callback ignored');
        return res.status(200).json({ success: true, message: 'Already processed' });
      }
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('[SSV] Callback error:', error);
    // Sempre retornar 200 para o Google não retentar indefinidamente
    res.status(200).json({ success: false, error: 'Internal error' });
  }
});

// GET /api/ssv/verify - Verificar se SSV está funcionando (health check)
router.get('/verify', async (req, res) => {
  try {
    const { fetchGoogleKeys } = require('../utils/admobSsv');
    const keys = await fetchGoogleKeys();
    res.json({
      success: true,
      message: 'SSV verification endpoint is active',
      googleKeysLoaded: keys.length,
      keysUrl: 'https://www.gstatic.com/admob/reward/verifier-keys.json'
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
module.exports.parseSsvIdentity = parseSsvIdentity;
module.exports.redactRawQuery = redactRawQuery;
