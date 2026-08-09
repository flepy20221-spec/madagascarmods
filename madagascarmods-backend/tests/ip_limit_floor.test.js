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
    30,
    'Um valor abaixo do piso deve ser elevado ao piso (30), nao aplicado como 8.'
  );
  assert.strictEqual(
    authRoutes.limits.configuredValue,
    '8',
    'O valor configurado deve permanecer visivel para diagnostico, mesmo recusado.'
  );
});

test('valor de ambiente acima do piso e respeitado', () => {
  const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: 150 });

  assert.strictEqual(
    authRoutes.limits.maxAccountsPerIp24h,
    150,
    'Operacao legitima deve poder elevar o teto acima do padrao.'
  );
});

test('ambiente sem a variavel usa o padrao calibrado para CGNAT', () => {
  const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: undefined });

  assert.strictEqual(
    authRoutes.limits.maxAccountsPerIp24h,
    60,
    'Sem configuracao explicita, o padrao do codigo (60) deve valer.'
  );
});

test('valor invalido nao zera o limite nem desliga a protecao', () => {
  // Um valor nao numerico produzia NaN. Em comparacao com NaN, `devicesFromIp >= NaN` e
  // sempre falso, o que desligaria o freio por IP de forma silenciosa.
  for (const invalid of ['abc', '', '-5', '0']) {
    const authRoutes = loadWithEnv('src/routes/auth.js', { MAX_ACCOUNTS_PER_IP_24H: invalid });
    assert.strictEqual(
      authRoutes.limits.maxAccountsPerIp24h,
      60,
      `Valor invalido (${JSON.stringify(invalid)}) deve cair no padrao 60.`
    );
  }
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

test('AUTH_RATE_LIMIT_MAX herdado com valor 10 e recusado pelo piso', () => {
  const rateLimits = loadWithEnv('src/middleware/rateLimits.js', { AUTH_RATE_LIMIT_MAX: 10 });

  assert.strictEqual(
    rateLimits.authRateLimit.max,
    60,
    'O teto de requisicoes em /api/auth/ deve ser elevado ao piso (60).'
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
