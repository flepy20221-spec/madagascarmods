const crypto = require('crypto');

const DEVICE_ACCOUNT_KEY_PATTERN = /^[a-f0-9]{64}$/;

/**
 * Estados de instalacao aceitos no payload de /auth/device.
 *
 * ============================================================================
 * POR QUE ESTE CAMPO EXISTE
 *
 * A rota tinha apenas duas saidas quando nenhuma prova localizava a conta:
 * criar um usuario novo ou recusar. Como o cliente nao informava nada sobre o
 * historico da instalacao, o servidor sempre escolhia criar. Foi assim que o
 * mesmo Moto G60 acumulou varias contas: cada reinstalacao ou troca de
 * certificado de assinatura parecia um aparelho novo.
 *
 * `upgraded_without_proof` da ao servidor a informacao que faltava. Note a
 * assimetria deliberada: o campo somente RESTRINGE o que o servidor faz. Ele
 * nunca concede acesso, nunca identifica conta e nunca substitui prova de posse.
 * Um cliente adulterado que mentisse esse valor apenas se impediria de criar
 * conta — nao ganharia acesso a conta alguma.
 * ============================================================================
 */
const INSTALLATION_STATE = {
  FRESH_INSTALL: 'fresh_install',
  EXISTING_INSTALL: 'existing_install',
  UPGRADED_WITHOUT_PROOF: 'upgraded_without_proof',
};

const VALID_INSTALLATION_STATES = new Set(Object.values(INSTALLATION_STATE));

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

/**
 * Normaliza o estado de instalacao informado pelo cliente.
 *
 * Builds anteriores a 1.7.3 nao enviam este campo. A ausencia e tratada como
 * `fresh_install` para nao alterar o comportamento desses builds: eles continuam
 * criando conta quando nenhuma prova e encontrada, como sempre fizeram.
 */
function normalizeInstallationState(value) {
  if (typeof value !== 'string') return INSTALLATION_STATE.FRESH_INSTALL;
  const normalized = value.trim().toLowerCase();
  return VALID_INSTALLATION_STATES.has(normalized)
    ? normalized
    : INSTALLATION_STATE.FRESH_INSTALL;
}

/**
 * Gera um token de vinculo de dispositivo com 256 bits de entropia.
 *
 * Usa crypto.randomBytes, nao Math.random: o valor e uma credencial de longa
 * duracao capaz de reassociar uma conta com saldo, e precisa ser imprevisivel.
 */
function generateDeviceBindingToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Calcula o hash armazenado do token de vinculo.
 *
 * Somente o hash e persistido em users.device_binding_token_hash. Assim, um
 * vazamento do banco nao permite reassociar dispositivos, pelo mesmo motivo que
 * um hash de senha nao permite autenticar.
 */
function hashDeviceBindingToken(token) {
  if (typeof token !== 'string' || token.trim().length < 32) {
    throw new TypeError('Invalid device binding token');
  }
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

module.exports = {
  DEVICE_ACCOUNT_KEY_PATTERN,
  INSTALLATION_STATE,
  normalizeDeviceAccountKey,
  buildDeviceAccountEmail,
  normalizeInstallationState,
  generateDeviceBindingToken,
  hashDeviceBindingToken,
};
