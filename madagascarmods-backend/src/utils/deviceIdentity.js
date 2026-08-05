const DEVICE_ACCOUNT_KEY_PATTERN = /^[a-f0-9]{64}$/;

function normalizeDeviceAccountKey(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return DEVICE_ACCOUNT_KEY_PATTERN.test(normalized) ? normalized : null;
}

function buildDeviceAccountEmail(deviceAccountKey) {
  const normalized = normalizeDeviceAccountKey(deviceAccountKey);
  if (!normalized) {
    throw new TypeError('Invalid device account key');
  }

  // A coluna users.email permanece NOT NULL por compatibilidade com o painel e JWTs
  // legados. O valor abaixo e um identificador tecnico interno, nao um e-mail pessoal.
  return `device-${normalized.slice(0, 32)}@cashpix.local`;
}

module.exports = {
  DEVICE_ACCOUNT_KEY_PATTERN,
  normalizeDeviceAccountKey,
  buildDeviceAccountEmail,
};
