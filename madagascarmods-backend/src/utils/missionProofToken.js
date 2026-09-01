const crypto = require('crypto');
const { APP_HMAC_SECRET } = require('../config/secrets');

const PURPOSE = 'cashpix-manus-proof';
const TOKEN_TTL_SECONDS = 6 * 60 * 60;

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signatureFor(encodedPayload) {
  return crypto
    .createHmac('sha256', APP_HMAC_SECRET)
    .update(encodedPayload)
    .digest('base64url');
}

function createMissionProofToken({ userId, missionId, now = Date.now() }) {
  const issuedAt = Math.floor(now / 1000);
  const payload = {
    purpose: PURPOSE,
    userId,
    missionId,
    iat: issuedAt,
    exp: issuedAt + TOKEN_TTL_SECONDS,
    nonce: crypto.randomBytes(12).toString('base64url'),
  };
  const encodedPayload = encodeJson(payload);
  return `${encodedPayload}.${signatureFor(encodedPayload)}`;
}

function verifyMissionProofToken(token, { now = Date.now() } = {}) {
  if (typeof token !== 'string' || token.length < 40 || token.length > 2048) {
    const error = new Error('Link de identificacao ausente ou invalido.');
    error.code = 'INVALID_PROOF_TOKEN';
    throw error;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    const error = new Error('Link de identificacao invalido.');
    error.code = 'INVALID_PROOF_TOKEN';
    throw error;
  }

  const [encodedPayload, receivedSignature] = parts;
  const expectedSignature = signatureFor(encodedPayload);
  const received = Buffer.from(receivedSignature);
  const expected = Buffer.from(expectedSignature);
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    const error = new Error('Link de identificacao adulterado.');
    error.code = 'INVALID_PROOF_TOKEN';
    throw error;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch (_) {
    const error = new Error('Link de identificacao invalido.');
    error.code = 'INVALID_PROOF_TOKEN';
    throw error;
  }

  const nowSeconds = Math.floor(now / 1000);
  if (
    payload?.purpose !== PURPOSE
    || typeof payload.userId !== 'string'
    || typeof payload.missionId !== 'string'
    || !Number.isInteger(payload.iat)
    || !Number.isInteger(payload.exp)
    || payload.iat > nowSeconds + 60
  ) {
    const error = new Error('Link de identificacao invalido.');
    error.code = 'INVALID_PROOF_TOKEN';
    throw error;
  }
  if (payload.exp < nowSeconds) {
    const error = new Error('Este link expirou. Volte ao CashPix e abra a missao novamente.');
    error.code = 'EXPIRED_PROOF_TOKEN';
    throw error;
  }

  return payload;
}

function appendProofToken(baseUrl, token) {
  const url = new URL(baseUrl);
  url.searchParams.set('access', token);
  return url.toString();
}

function proofTokenRateKey(token) {
  if (typeof token !== 'string' || token.length === 0) return 'missing-proof-token';
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  TOKEN_TTL_SECONDS,
  appendProofToken,
  createMissionProofToken,
  proofTokenRateKey,
  verifyMissionProofToken,
};
