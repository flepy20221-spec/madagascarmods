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
 * Constrói uma KeyObject a partir da entrada oficial do Google.
 *
 * O campo `pem` já contém cabeçalho e rodapé completos. Embrulhá-lo novamente
 * produz um PEM inválido e faz o OpenSSL retornar DECODER routines::unsupported.
 * O campo `base64` é mantido somente como fallback DER/SPKI.
 */
function publicKeyFromEntry(keyEntry) {
  if (typeof keyEntry?.pem === 'string' &&
      keyEntry.pem.includes('-----BEGIN PUBLIC KEY-----')) {
    return crypto.createPublicKey(keyEntry.pem);
  }

  if (typeof keyEntry?.base64 === 'string' && keyEntry.base64.length > 0) {
    return crypto.createPublicKey({
      key: Buffer.from(keyEntry.base64, 'base64'),
      format: 'der',
      type: 'spki'
    });
  }

  throw new Error('Google SSV key has no usable pem or base64 value');
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
async function validateSsvCallback(queryParams, rawQueryString = null, keyOverride = null) {
  try {
    const { signature, key_id, ...params } = queryParams;

    if (!signature || !key_id) {
      return { valid: false, error: 'Missing signature or key_id' };
    }

    // Buscar chaves públicas do Google (keyOverride existe apenas para testes).
    const keys = Array.isArray(keyOverride) ? keyOverride : await fetchGoogleKeys();
    const keyEntry = keys.find(k => String(k.keyId) === String(key_id));

    if (!keyEntry) {
      return { valid: false, error: `Key ID ${key_id} not found in Google's public keys` };
    }

    // Construir a mensagem que foi assinada (todos os params exceto signature e
    // key_id, na ordem exata em que chegaram na URL).
    const rawMessage = buildVerificationMessage(queryParams, rawQueryString);

    // A implementação de referência do AdMob monta o conteúdo assinado a partir
    // de `URI.getQuery()`, que em Java devolve a query DECODIFICADA
    // (`getRawQuery()` é a variante crua). A própria documentação avisa, na
    // seção "Custom data": "The custom reward string is percent escaped and
    // might require decoding when parsed from the SSV callback."
    //
    // Enquanto `custom_data` não contém caracteres escapados, a forma crua e a
    // decodificada são idênticas e a verificação passa nas duas. No formato
    // `<user_uuid>%3A<session_uuid>` elas divergem em 2 bytes por `%3A`, e a
    // verificação sobre os bytes crus falha sempre.
    //
    // Testamos as duas formas: ambas derivam dos mesmos bytes recebidos, então
    // aceitar qualquer uma não enfraquece a segurança — a assinatura só valida
    // para a mensagem que o Google realmente assinou.
    const candidates = [rawMessage];
    const decodedMessage = safeDecodeMessage(rawMessage);
    if (decodedMessage !== null && decodedMessage !== rawMessage) {
      candidates.push(decodedMessage);
    }

    let isValid = false;
    let matchedForm = null;
    for (const candidate of candidates) {
      if (verifySsvSignature(candidate, signature, keyEntry)) {
        isValid = true;
        matchedForm = candidate === rawMessage ? 'raw' : 'decoded';
        break;
      }
    }

    if (isValid) {
      return {
        valid: true,
        messageForm: matchedForm,
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
 * Decodifica percent-encoding de forma tolerante.
 *
 * `decodeURIComponent` lança URIError em sequências mal formadas (ex.: um `%`
 * literal não escapado). Como a mensagem é apenas um candidato de verificação,
 * uma falha de decodificação não deve derrubar o callback: devolvemos null e o
 * chamador segue usando somente a forma crua.
 */
function safeDecodeMessage(message) {
  if (typeof message !== 'string' || !message.includes('%')) {
    return null;
  }
  try {
    return decodeURIComponent(message);
  } catch (err) {
    return null;
  }
}

/**
 * Verifica uma assinatura ECDSA SHA-256 do AdMob.
 */
function verifySsvSignature(message, signature, keyEntry) {
  if (typeof message !== 'string' || !message) {
    throw new Error('SSV verification message is empty');
  }
  if (typeof signature !== 'string' || !signature) {
    throw new Error('SSV signature is empty');
  }

  // A assinatura usa Base64 URL-safe e codificação ECDSA DER.
  const signatureBuffer = Buffer.from(signature, 'base64url');
  const publicKey = publicKeyFromEntry(keyEntry);
  const verifier = crypto.createVerify('SHA256');
  verifier.update(message, 'utf8');
  verifier.end();
  return verifier.verify(publicKey, signatureBuffer);
}

/**
 * Constrói a mensagem de verificação a partir dos query params.
 * O Google assina a query string na ordem em que aparece na URL,
 * excluindo signature e key_id.
 */
function buildVerificationMessage(queryParams, rawQueryString = null) {
  // O Google exige os bytes exatos recebidos antes de `&signature=`. Usar a
  // query crua evita alterar ordem, percent-encoding, espaços ou caracteres
  // especiais de custom_data/user_id durante o parse do Express.
  //
  // Documentação oficial: os dois últimos parâmetros são sempre `signature` e
  // `key_id`, nessa ordem. Porém proxies e integrações podem anexar parâmetros
  // extras depois deles (ex.: `?...&signature=X&key_id=Y&utm_source=Z`). Nesse
  // caso, cortar apenas "tudo antes de &signature" mantém o conteúdo assinado
  // correto, mas se `signature` NÃO for o penúltimo parâmetro é preciso remover
  // cirurgicamente os pares `signature` e `key_id` preservando todo o resto.
  if (typeof rawQueryString === 'string' && rawQueryString.length > 0) {
    const signatureMarker = '&signature=';
    const signatureIndex = rawQueryString.lastIndexOf(signatureMarker);

    if (signatureIndex <= 0) {
      throw new Error('Raw SSV query has no signature marker');
    }

    const beforeSignature = rawQueryString.slice(0, signatureIndex);
    const afterSignature = rawQueryString.slice(signatureIndex + 1);

    // Caso canônico: `signature=...&key_id=...` encerra a query.
    const trailingPairs = afterSignature.split('&');
    const isCanonicalTail =
      trailingPairs.length === 2 &&
      trailingPairs[0].startsWith('signature=') &&
      trailingPairs[1].startsWith('key_id=');

    if (isCanonicalTail) {
      return beforeSignature;
    }

    // Cauda inesperada: reconstruir preservando os bytes originais de cada par,
    // descartando somente `signature` e `key_id`.
    const preserved = rawQueryString
      .split('&')
      .filter((pair) => {
        const eq = pair.indexOf('=');
        const key = eq >= 0 ? pair.slice(0, eq) : pair;
        return key !== 'signature' && key !== 'key_id';
      });

    return preserved.join('&');
  }

  // Fallback para chamadas internas/testes antigos que fornecem apenas objeto.
  // Os callbacks oficiais são enviados em ordem e o objeto preserva a ordem de
  // inserção em Node.js, mas a rota HTTP sempre deve passar a query crua.
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

    return await validateSsvCallback(params, url.search.slice(1));
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
  // Exportações pequenas e determinísticas para testes criptográficos locais.
  buildVerificationMessage,
  publicKeyFromEntry,
  verifySsvSignature,
};
