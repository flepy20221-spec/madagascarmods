/**
 * AdMob Server-Side Verification (SSV)
 * 
 * Valida que um anúncio rewarded foi realmente assistido pelo usuário.
 * O Google assina um callback com chaves ECDSA públicas que são rotacionadas.
 * 
 * Fluxo:
 * 1. Usuário assiste anúncio no app
 * 2. AdMob envia callback para nosso servidor com assinatura
 * 3. Servidor valida a assinatura usando chaves públicas do Google
 * 4. Se válido, credita os pontos
 * 
 * Referência: https://developers.google.com/admob/android/ssv
 */
const crypto = require('crypto');
const https = require('https');

// URL das chaves públicas do Google para verificação SSV
const GOOGLE_KEYS_URL = 'https://www.gstatic.com/admob/reward/verifier-keys.json';

// Cache das chaves públicas (rotacionadas pelo Google periodicamente)
let cachedKeys = null;
let cacheExpiry = 0;
const CACHE_DURATION_MS = 24 * 60 * 60 * 1000; // 24 horas

/**
 * Busca as chaves públicas do Google para verificação SSV.
 * Usa cache de 24h para evitar requisições desnecessárias.
 */
async function fetchGoogleKeys() {
  const now = Date.now();
  if (cachedKeys && now < cacheExpiry) {
    return cachedKeys;
  }

  return new Promise((resolve, reject) => {
    https.get(GOOGLE_KEYS_URL, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          cachedKeys = parsed.keys || [];
          cacheExpiry = now + CACHE_DURATION_MS;
          resolve(cachedKeys);
        } catch (err) {
          reject(new Error(`Failed to parse Google SSV keys: ${err.message}`));
        }
      });
    }).on('error', (err) => {
      reject(new Error(`Failed to fetch Google SSV keys: ${err.message}`));
    });
  });
}

/**
 * Converte uma chave pública base64 do Google para formato PEM.
 */
function base64ToPem(base64Key) {
  const lines = base64Key.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Valida um callback SSV do AdMob.
 * 
 * O callback vem como query string com parâmetros:
 * - ad_network, ad_unit, custom_data, reward_amount, reward_item, 
 *   timestamp, transaction_id, user_id, signature, key_id
 * 
 * @param {Object} queryParams - Parâmetros do callback (req.query)
 * @returns {Object} { valid: boolean, data: object, error?: string }
 */
async function validateSsvCallback(queryParams) {
  try {
    const { signature, key_id, ...params } = queryParams;

    if (!signature || !key_id) {
      return { valid: false, error: 'Missing signature or key_id' };
    }

    // Buscar chaves públicas do Google
    const keys = await fetchGoogleKeys();
    const keyEntry = keys.find(k => String(k.keyId) === String(key_id));

    if (!keyEntry) {
      return { valid: false, error: `Key ID ${key_id} not found in Google's public keys` };
    }

    // Construir a mensagem que foi assinada (todos os params exceto signature e key_id, na ordem da URL)
    // O Google assina a query string completa antes de signature e key_id
    const message = buildVerificationMessage(queryParams);

    // Decodificar a assinatura (base64url -> buffer)
    const signatureBuffer = Buffer.from(
      signature.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );

    // Verificar assinatura ECDSA
    const pem = base64ToPem(keyEntry.pem || keyEntry.base64);
    const verifier = crypto.createVerify('SHA256');
    verifier.update(message);

    const isValid = verifier.verify(pem, signatureBuffer);

    if (isValid) {
      return {
        valid: true,
        data: {
          adNetwork: params.ad_network,
          adUnit: params.ad_unit,
          customData: params.custom_data,
          rewardAmount: params.reward_amount,
          rewardItem: params.reward_item,
          timestamp: params.timestamp,
          transactionId: params.transaction_id,
          userId: params.user_id,
        }
      };
    }

    return { valid: false, error: 'Signature verification failed' };
  } catch (err) {
    return { valid: false, error: `SSV validation error: ${err.message}` };
  }
}

/**
 * Constrói a mensagem de verificação a partir dos query params.
 * O Google assina a query string na ordem em que aparece na URL,
 * excluindo signature e key_id.
 */
function buildVerificationMessage(queryParams) {
  // A mensagem é a query string completa sem signature e key_id
  const parts = [];
  const excludeKeys = ['signature', 'key_id'];

  for (const [key, value] of Object.entries(queryParams)) {
    if (!excludeKeys.includes(key)) {
      parts.push(`${key}=${value}`);
    }
  }

  return parts.join('&');
}

/**
 * Valida um token SSV enviado pelo app (modo inline).
 * 
 * Neste modo, o app envia a URL completa do callback SSV como token,
 * e o servidor extrai os parâmetros e valida.
 * 
 * @param {string} ssvUrl - URL completa do callback SSV
 * @returns {Object} { valid: boolean, data: object, error?: string }
 */
async function validateSsvToken(ssvUrl) {
  try {
    if (!ssvUrl || typeof ssvUrl !== 'string') {
      return { valid: false, error: 'Empty or invalid SSV token' };
    }

    // Extrair query params da URL
    const url = new URL(ssvUrl);
    const params = Object.fromEntries(url.searchParams.entries());

    return await validateSsvCallback(params);
  } catch (err) {
    return { valid: false, error: `SSV token parse error: ${err.message}` };
  }
}

/**
 * Verifica se um transaction_id já foi usado (proteção contra replay).
 * 
 * @param {Object} db - Instância do pool de banco de dados
 * @param {string} transactionId - ID da transação do AdMob
 * @returns {boolean} true se já foi usado
 */
async function isTransactionUsed(db, transactionId) {
  if (!transactionId) return false;

  const result = await db.query(
    `SELECT id FROM reward_events WHERE ssv_token LIKE $1 LIMIT 1`,
    [`%transaction_id=${transactionId}%`]
  );

  return result.rows.length > 0;
}

module.exports = {
  validateSsvCallback,
  validateSsvToken,
  isTransactionUsed,
  fetchGoogleKeys,
};
