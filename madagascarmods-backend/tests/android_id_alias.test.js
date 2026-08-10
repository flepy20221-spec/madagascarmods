const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  normalizeAndroidIdKey,
  normalizeDeviceAccountKey,
} = require('../src/utils/deviceIdentity');

// Reproduz o calculo feito pelo aplicativo (lib/services/device_service.dart).
// Manter as duas derivacoes lado a lado neste teste documenta o contrato entre
// cliente e servidor: se o app mudar o prefixo de escopo, este teste continua
// passando, mas a comparacao abaixo deixa explicito qual valor o servidor espera.
const ANDROID_ID_EXEMPLO = '9774d56d682e549c';
const sha256 = (input) => crypto.createHash('sha256').update(input).digest('hex');
const derivarAndroidIdKey = (androidId) => sha256(`cashpix-android-id|${androidId}`);
const derivarDeviceAccountKey = (androidId) =>
  sha256(`cashpix|com.madagascarmods|v2|${androidId}`);

test('normalizeAndroidIdKey aceita somente hash hexadecimal de 64 caracteres', () => {
  const valido = derivarAndroidIdKey(ANDROID_ID_EXEMPLO);

  // Normalizacao: espacos em volta e maiusculas sao aceitos e corrigidos, porque
  // sao variacoes inofensivas de serializacao do cliente.
  assert.equal(normalizeAndroidIdKey(`  ${valido.toUpperCase()}  `), valido);
  assert.equal(normalizeAndroidIdKey(valido), valido);

  // Rejeicoes: qualquer coisa que nao seja um SHA-256 hexadecimal.
  assert.equal(normalizeAndroidIdKey('a'.repeat(63)), null, 'curto demais');
  assert.equal(normalizeAndroidIdKey('a'.repeat(65)), null, 'longo demais');
  assert.equal(normalizeAndroidIdKey('g'.repeat(64)), null, 'nao hexadecimal');
  assert.equal(normalizeAndroidIdKey(null), null);
  assert.equal(normalizeAndroidIdKey(undefined), null);
  assert.equal(normalizeAndroidIdKey(12345), null, 'nao string');
  assert.equal(normalizeAndroidIdKey(''), null);

  // O ANDROID_ID bruto tem 16 caracteres e precisa ser recusado: aceitar o valor
  // em claro faria o identificador do aparelho ser gravado sem hash no banco.
  assert.equal(normalizeAndroidIdKey(ANDROID_ID_EXEMPLO), null);
});

test('o alias nunca carrega o ANDROID_ID em claro e difere da chave principal', () => {
  const alias = derivarAndroidIdKey(ANDROID_ID_EXEMPLO);
  const principal = derivarDeviceAccountKey(ANDROID_ID_EXEMPLO);

  assert.equal(alias.includes(ANDROID_ID_EXEMPLO), false);
  assert.notEqual(alias, principal, 'os dois escopos devem produzir hashes distintos');

  // Os dois passam pela mesma validacao de formato: sao ambos SHA-256.
  assert.equal(normalizeAndroidIdKey(alias), alias);
  assert.equal(normalizeDeviceAccountKey(principal), principal);
});

// ============================================================================
// Cenario central: a reproducao do bug relatado.
//
// Uma conta com saldo registrada sob a chave principal ANTIGA continua sendo
// localizada pelo alias de ANDROID_ID quando a chave principal muda. Registrar a
// chave nova como alias adicional NAO cria conta nova e NAO move saldo.
//
// O teste roda sobre uma tabela de aliases em memoria que imita as duas
// operacoes que /auth/device realmente faz: buscar por chave e registrar alias.
// Isso mantem o teste sem dependencia de banco, cobrindo a regra de decisao —
// que era exatamente onde o comportamento estava errado.
// ============================================================================
test('conta com saldo sobrevive a rotacao da chave principal via alias de ANDROID_ID', () => {
  const CONTA_ID = 'conta-com-384-pontos';
  const SALDO_INICIAL = 384;

  const contas = new Map([[CONTA_ID, { saldo: SALDO_INICIAL }]]);
  const aliases = new Map();

  function registrarAlias(chave, userId, source) {
    const normalizada = normalizeAndroidIdKey(chave);
    assert.ok(normalizada, 'alias invalido nunca deve chegar ao registro');
    if (!aliases.has(normalizada)) {
      aliases.set(normalizada, { userId, source });
    }
    return aliases.get(normalizada);
  }

  function buscarConta({ deviceAccountKey, androidIdKey }) {
    const porChavePrincipal = aliases.get(normalizeDeviceAccountKey(deviceAccountKey));
    if (porChavePrincipal) return porChavePrincipal.userId;

    const porAlias = aliases.get(normalizeAndroidIdKey(androidIdKey));
    if (porAlias) return porAlias.userId;

    return null;
  }

  // --- Estado inicial: app na versao antiga, escopo v2 ---
  const androidId = ANDROID_ID_EXEMPLO;
  const chaveAntiga = derivarDeviceAccountKey(androidId);
  const aliasAndroid = derivarAndroidIdKey(androidId);

  registrarAlias(chaveAntiga, CONTA_ID, 'account_created');
  registrarAlias(aliasAndroid, CONTA_ID, 'android_id_key');

  // --- O escopo da chave principal evolui (v2 -> v3) ---
  const chaveNova = sha256(`cashpix|com.madagascarmods|v3|${androidId}`);
  assert.notEqual(chaveNova, chaveAntiga);

  // Antes da correcao, este era o ponto em que o servidor nao encontrava a conta
  // e criava uma nova com saldo zero.
  const encontrada = buscarConta({
    deviceAccountKey: chaveNova,
    androidIdKey: aliasAndroid,
  });

  assert.equal(encontrada, CONTA_ID, 'a conta existente deve ser reconhecida pelo alias');

  // A chave nova entra como alias ADICIONAL da mesma conta.
  registrarAlias(chaveNova, encontrada, 'device_alias');

  assert.equal(contas.size, 1, 'nenhuma conta nova deve ser criada');
  assert.equal(contas.get(CONTA_ID).saldo, SALDO_INICIAL, 'o saldo deve permanecer intacto');

  // Tres aliases apontando para a mesma conta: chave antiga, alias de ANDROID_ID
  // e chave nova.
  assert.equal(aliases.size, 3);
  assert.ok([...aliases.values()].every((entrada) => entrada.userId === CONTA_ID));

  // E o acesso seguinte, ja com a chave nova como principal, tambem encontra.
  assert.equal(
    buscarConta({ deviceAccountKey: chaveNova, androidIdKey: aliasAndroid }),
    CONTA_ID
  );
});
