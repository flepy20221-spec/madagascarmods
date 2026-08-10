/**
 * CashPix — Piso de seguranca dos limites de rede por IP
 *
 * Defeito coberto aqui:
 * O commit que elevou os tetos de IP (CGNAT) corrigiu o CODIGO, mas o bloqueio continuou
 * em producao porque a variavel de ambiente tem precedencia sobre o padrao e o servico
 * ainda carregava MAX_ACCOUNTS_PER_IP_24H=8 da configuracao original. O usuario seguia
 * recebendo "Muitas contas criadas nesta rede" sem que nada disso aparecesse no diff.
 *
 * A garantia testada: um valor de ambiente abaixo do piso e RECUSADO, e o valor em uso
 * passa a ser o piso. Configuracao nao pode reintroduzir silenciosamente um defeito
 * ja corrigido no codigo.
 *
 * Nao depende de PostgreSQL: o alvo e a resolucao dos limiares no carregamento do modulo.
 *
 * Execucao:
 *   node --test tests/ip_limit_floor.test.js
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = process.env.APP_HMAC_SECRET || 'test_hmac_secret_com_mais_de_32_caracteres';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/unused_in_this_test';

/**
 * Recarrega um modulo do zero com as variaveis de ambiente informadas.
 *
 * Os limiares sao resolvidos uma unica vez, no carregamento (const de topo de modulo),
 * exatamente como acontece no boot do servidor. Reproduzir isso exige limpar o cache do
 * require, e nao apenas alterar process.env.
 */
function loadWithEnv(relativePath, env) {
  const resolved = require.resolve(path.join('..', relativePath));
  const saved = {};

  for (const [key, value] of Object.entries(env)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = String(value);
  }

  // Limpa o modulo e suas dependencias internas para forcar reavaliacao das constantes.
  for (const key of Object.keys(require.cache)) {
    if (key.includes(`${path.sep}src${path.sep}`)) delete require.cache[key];
  }

  try {
    return require(resolved);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('MAX_ACCOUNTS_PER_IP_24H herdado com valor 8 e recusado pelo piso', () => {
  // Exatamente a configuracao encontrada em producao.
  const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: 8 });

  assert.ok(authRoutes.limits, 'A rota de auth deve expor os limites vigentes.');
  assert.strictEqual(
    authRoutes.limits.maxAccountsPerIp24h,
    200,
    'Um valor abaixo do piso deve ser elevado ao piso (200), nao aplicado como 8.'
  );
  assert.strictEqual(
    authRoutes.limits.configuredValue,
    '8',
    'O valor configurado deve permanecer visivel para diagnostico, mesmo recusado.'
  );
});

test('valor de ambiente acima do piso e respeitado', () => {
  const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: 900 });

  assert.strictEqual(
    authRoutes.limits.maxAccountsPerIp24h,
    900,
    'Operacao legitima deve poder elevar o teto acima do padrao.'
  );
});

test('ambiente sem a variavel usa o padrao calibrado para CGNAT', () => {
  const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: undefined });

  assert.strictEqual(
    authRoutes.limits.maxAccountsPerIp24h,
    500,
    'Sem configuracao explicita, o padrao do codigo (500) deve valer.'
  );
});

test('valor invalido nao zera o limite nem desliga a protecao', () => {
  // Um valor nao numerico produzia NaN. Em comparacao com NaN, `devicesFromIp >= NaN` e
  // sempre falso, o que desligaria o freio por IP de forma silenciosa.
  for (const invalid of ['abc', '', '-5', '0']) {
    const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: invalid });
    assert.strictEqual(
      authRoutes.limits.maxAccountsPerIp24h,
      500,
      `Valor invalido (${JSON.stringify(invalid)}) deve cair no padrao 500.`
    );
  }
});

// ---------------------------------------------------------------------------------------
// Regra de rajada: a trava que substituiu o teto acumulado de 24h.
// ---------------------------------------------------------------------------------------

test('o limite de rajada usa o padrao calibrado com os dados de producao', () => {
  const authRoutes = loadWithEnv('src/routes/auth.js', {
    IP_BURST_LIMIT: undefined,
    IP_BURST_OBSERVE_LIMIT: undefined,
  });

  assert.strictEqual(authRoutes.limits.ipBurstLimit, 40, 'Teto de rajada padrao: 40.');
  assert.strictEqual(authRoutes.limits.ipBurstWindowMinutes, 10, 'Janela padrao: 10 minutos.');
  assert.ok(
    authRoutes.limits.ipBurstObserveLimit < authRoutes.limits.ipBurstLimit,
    'A faixa de observacao deve ficar abaixo da faixa de bloqueio.'
  );
});

test('IP_BURST_LIMIT abaixo do piso e recusado', () => {
  // Um valor baixo aqui reproduziria o incidente original, agora numa janela curta.
  const authRoutes = loadWithEnv('src/routes/auth.js', { IP_BURST_LIMIT: 3 });

  assert.strictEqual(
    authRoutes.limits.ipBurstLimit,
    25,
    'Valor abaixo do piso (25) deve ser recusado.'
  );
  assert.strictEqual(authRoutes.limits.ipBurstConfigured, '3', 'Configurado permanece visivel.');
});

test('a faixa de observacao nunca alcanca a de bloqueio, mesmo se configurada acima', () => {
  // Se observacao >= bloqueio, o registro antecipado se tornaria inalcancavel e o sistema
  // perderia justamente o aviso que essa faixa existe para dar.
  const authRoutes = loadWithEnv('src/routes/auth.js', {
    IP_BURST_LIMIT: 30,
    IP_BURST_OBSERVE_LIMIT: 999,
  });

  assert.ok(
    authRoutes.limits.ipBurstObserveLimit < authRoutes.limits.ipBurstLimit,
    `observacao (${authRoutes.limits.ipBurstObserveLimit}) deve ser menor que `
    + `bloqueio (${authRoutes.limits.ipBurstLimit}).`
  );
});

test('a regra de rajada nao teria bloqueado o trafego legitimo observado em producao', () => {
  // Dados medidos no audit_log e na tabela users antes da correcao:
  //   - 70 aparelhos distintos no mesmo IP em 24h  (bloqueado pela regra antiga, teto 60)
  //   - pico real de 3 cadastros no mesmo minuto
  //   - pico real de 24 cadastros na hora mais movimentada
  // A regra nova mede 10 minutos. Mesmo concentrando a hora de pico inteira numa unica
  // janela, 24 < 25 e o cadastro passa.
  const authRoutes = loadWithEnv('src/routes/auth.js', {
    IP_BURST_LIMIT: undefined,
    MAX_ACCOUNTS_PER_IP_24H: undefined,
  });

  const PICO_HORA_OBSERVADO = 24;
  const APARELHOS_24H_OBSERVADO = 70;

  // Exige folga, nao apenas aprovacao: um teto alcancado raspando volta a bloquear usuario
  // legitimo no primeiro dia de divulgacao mais intensa.
  assert.ok(
    PICO_HORA_OBSERVADO <= authRoutes.limits.ipBurstLimit * 0.7,
    `O pico horario real (${PICO_HORA_OBSERVADO}) deve ficar com folga sob o teto de rajada `
    + `(${authRoutes.limits.ipBurstLimit}), senao o falso positivo se repete.`
  );

  assert.ok(
    APARELHOS_24H_OBSERVADO < authRoutes.limits.maxAccountsPerIp24h,
    `O volume real de 24h (${APARELHOS_24H_OBSERVADO}) deve ficar bem abaixo da rede de `
    + `seguranca (${authRoutes.limits.maxAccountsPerIp24h}).`
  );
});

test('LOGIN_IP_HARD_LIMIT herdado com valor 5 e recusado pelo piso', () => {
  // Era esta a trava mais agressiva: barrava a partir do 6o aparelho da operadora em
  // 10 minutos e atingia tambem quem JA tinha conta e saldo.
  const botDetection = loadWithEnv('src/middleware/botDetection.js', { LOGIN_IP_HARD_LIMIT: 5 });

  assert.strictEqual(
    botDetection.loginIpLimits.hardLimit,
    100,
    'O limite rigido de login deve ser elevado ao piso (100).'
  );
  assert.strictEqual(
    botDetection.loginIpLimits.configuredHardLimit,
    '5',
    'O valor configurado deve continuar visivel para diagnostico.'
  );
});

test('AUTH_RATE_LIMIT_MAX herdado com valor 10 e recusado pelo piso do fallback', () => {
  // MUDANCA DE SEMANTICA, e o motivo desta assercao ter sido reescrita:
  // o limiter de /api/auth/* passou a contar por APARELHO (device_account_key), nao por IP.
  // A justificativa completa esta no cabecalho de src/middleware/rateLimits.js, e o
  // comportamento novo e coberto por tests/device_rate_limit.test.js.
  //
  // AUTH_RATE_LIMIT_MAX conservou o nome por causa da variavel ja configurada no Railway, mas
  // governa apenas o FALLBACK por IP, aplicado quando a requisicao nao identifica o aparelho.
  // O piso desse fallback subiu de 60 para 300: um bucket compartilhado por um gateway inteiro
  // de CGNAT nao pode operar com o teto que faz sentido para um aparelho isolado.
  const rateLimits = loadWithEnv('src/middleware/rateLimits.js', { AUTH_RATE_LIMIT_MAX: 10 });

  assert.strictEqual(
    rateLimits.authRateLimit.ipFallback.max,
    300,
    'O teto do fallback por IP deve ser elevado ao piso (300).'
  );
  assert.strictEqual(
    rateLimits.authRateLimit.ipFallback.configuredValue,
    '10',
    'O valor configurado deve permanecer visivel para diagnostico, mesmo recusado.'
  );

  // O teto por aparelho e independente dessa variavel e permanece no padrao calibrado.
  assert.strictEqual(
    rateLimits.authRateLimit.max,
    30,
    'O teto por aparelho nao deve ser afetado por AUTH_RATE_LIMIT_MAX.'
  );
  assert.strictEqual(
    rateLimits.authRateLimit.keyedBy,
    'device_account_key',
    'O /health deve declarar SOBRE O QUE o limite conta, nao apenas quanto.'
  );
});

test('a faixa de observacao nunca ultrapassa a faixa de bloqueio', () => {
  // Se o limite de observacao ficasse acima do de bloqueio, a faixa que apenas registra
  // se tornaria inalcancavel e o sistema perderia a visibilidade que ela existe para dar.
  const botDetection = loadWithEnv('src/middleware/botDetection.js', {
    LOGIN_IP_SOFT_LIMIT: undefined,
    LOGIN_IP_HARD_LIMIT: undefined,
  });

  assert.ok(
    botDetection.loginIpLimits.softLimit < botDetection.loginIpLimits.hardLimit,
    'O limite de observacao deve ser menor que o de bloqueio.'
  );
});

// Os modulos carregados aqui registram setInterval de limpeza (nonces em antiFraud,
// burstTracker em botDetection) e um pool do PostgreSQL. Nenhum deles e usado por estes
// testes, mas sozinhos mantem o event loop ocupado e deixam o runner pendurado no CI.
test('encerra handles abertos pelos modulos carregados', async () => {
  try {
    const db = require('../src/models/db');
    await db.pool?.end?.();
  } catch (_) { /* pool pode nao ter sido inicializado */ }

  setImmediate(() => process.exit(0));
});
