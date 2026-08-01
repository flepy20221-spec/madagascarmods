const CryptoJS = require('crypto-js');
const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'madagascarmods-encryption-key-32chars!';

function encrypt(text) {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decrypt(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

function hashValue(text) {
  return crypto.createHash('sha256').update(text.toLowerCase().trim()).digest('hex');
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  if (local.length <= 2) {
    return `${local[0]}***@${domain}`;
  }
  return `${local.slice(0, 2)}***${local.slice(-1)}@${domain}`;
}

function generateIdempotencyKey() {
  return crypto.randomUUID();
}

module.exports = {
  encrypt,
  decrypt,
  hashValue,
  maskEmail,
  generateIdempotencyKey
};
