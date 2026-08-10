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

/**
 * Normaliza o alias secundario derivado do ANDROID_ID.
 *
 * ============================================================================
 * POR QUE EXISTE UM SEGUNDO IDENTIFICADOR DO MESMO APARELHO
 *
 * `device_account_key` e o SHA-256 de uma string que inclui um numero de versao
 * de escopo:
 *
 *     sha256('cashpix|com.madagascarmods|v2|' + androidId)
 *
 * Esse `v2` cumpre um proposito legitimo (permitir invalidar chaves antigas de
 * proposito), mas cria um efeito colateral indesejado: toda evolucao do formato
 * troca a identidade de TODOS os aparelhos de uma vez. Foi assim que a base
 * chegou a 537 contas com zero aliases secundarios — nenhuma conta jamais foi
 * reconhecida por uma chave anterior, porque nao havia caminho alternativo.
 *
 * `android_id_key` remove o numero de versao do escopo:
 *
 *     sha256('cashpix-android-id|' + androidId)
 *
 * O valor continua sendo um hash: o ANDROID_ID bruto nunca e transmitido nem
 * gravado, e o hash nao permite reconstrui-lo.
 *
 * LIMITE QUE PRECISA ESTAR CLARO: quando a chave de assinatura do APK muda, o
 * proprio ANDROID_ID muda (comportamento do Android 8+), e os DOIS hashes mudam
 * juntos. Este alias nao protege contra troca de keystore. Ele protege contra
 * mudanca de escopo do aplicativo, que era o unico dos dois casos que estava sob
 * o controle deste codigo.
 * ============================================================================
 */
function normalizeAndroidIdKey(value) {
  // Mesmo formato e mesma validacao da chave principal: 64 caracteres hex. A
  // funcao e separada em vez de reaproveitar normalizeDeviceAccountKey para que
  // a intencao apareca na chamada e para que os dois formatos possam divergir no
  // futuro sem alterar o comportamento de um ao mexer no outro.
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
  normalizeAndroidIdKey,
  buildDeviceAccountEmail,
  normalizeInstallationState,
  generateDeviceBindingToken,
  hashDeviceBindingToken,
};
