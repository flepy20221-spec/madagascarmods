/**
 * CashPix — Limite de autenticacao contado por APARELHO, nao por IP
 *
 * ============================================================================================
 * DEFEITO COBERTO
 *
 * O limiter de /api/auth/* contava por IP. Sob CGNAT de operadora movel, centenas de aparelhos
 * compartilham um mesmo IPv4: medido em producao, 273 das 604 contas ativas estavam em dois IPs
 * (136 e 137 aparelhos cada). Cada usuario novo consumia a cota dos vizinhos, e o app era
 * punido por crescer. Qualquer teto fixo por IP e alcancado por uso legitimo em semanas.
 *
 * Um segundo defeito, independente e invisivel no codigo: o mesmo limiter era aplicado DUAS
 * vezes na cadeia (uma vez em app.use('/api/auth/'), outra na propria rota), e cada requisicao
 * consumia dois hits do mesmo bucket. O teto efetivo era metade do configurado.
 *
 * GARANTIAS TESTADAS
 *
 *   1. Aparelhos distintos no MESMO IP nao interferem entre si.
 *   2. O mesmo aparelho e barrado ao exceder o proprio teto (30/15min).
 *   3. Trocar de IP NAO reinicia a cota de um aparelho (o modo aviao deixa de funcionar como
 *      forma de reset).
 *   4. Requisicao sem identificacao de aparelho cai no fallback por IP, com teto tolerante.
 *   5. Cada requisicao consome exatamente UM hit (ausencia de contagem dupla).
 *   6. A ordem de precedencia das ancoras e device_account_key > android_id_key > legado.
 *
 * Nao depende de PostgreSQL: o alvo e a politica de contagem do middleware, exercitada por um
 * servidor Express minimo. As rotas reais de negocio nao sao chamadas.
 *
 * Execucao:
 *   node --test tests/device_rate_limit.test.js
 * ============================================================================================
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = process.env.APP_HMAC_SECRET || 'test_hmac_secret_com_mais_de_32_caracteres';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/unused_in_this_test';

/**
 * Recarrega o modulo de limites com variaveis de ambiente controladas.
 *
 * Os tetos sao resolvidos uma unica vez, no carregamento do modulo, exatamente como no boot do
 * servidor. Reproduzir isso exige limpar o cache do require, e nao apenas alterar process.env.
 */
function loadRateLimits(env = {}) {
  const saved = {};
  for (const [key, value] of Object.entries(env)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = String(value);
  }
  for (const key of Object.keys(require.cache)) {
    if (key.includes(`${path.sep}src${path.sep}`)) delete require.cache[key];
  }
  try {
    return require('../src/middleware/rateLimits');
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/**
 * Sobe um app com a MESMA montagem de producao: json parser antes do limiter (o limiter le o
 * corpo para extrair a chave do aparelho) e o limiter declarado apenas na rota.
 */
async function startServer(authLimiter) {
  const app = express();
  // Confia em um salto de proxy, como no Railway, para que req.ip venha do X-Forwarded-For.
  app.set('trust proxy', 1);
  app.use(express.json());
  const router = express.Router();
  router.post('/device', authLimiter, (req, res) => res.json({ success: true }));
  app.use('/api/auth', router);

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address();
  return {
    port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/**
 * Requisicao de bootstrap. `ip` viaja em X-Forwarded-For porque, com trust proxy ativo, e dele
 * que req.ip e derivado — e assim o teste consegue simular aparelhos distintos atras do mesmo
 * gateway de CGNAT e o mesmo aparelho trocando de rede.
 */
async function bootstrap(port, { deviceKey, androidIdKey, legacyDeviceId, ip }) {
  const body = {};
  if (deviceKey) body.device_account_key = deviceKey;
  if (androidIdKey) body.android_id_key = androidIdKey;
  if (legacyDeviceId) body.legacy_device_id = legacyDeviceId;

  const response = await fetch(`http://127.0.0.1:${port}/api/auth/device`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': ip,
    },
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    limit: Number(response.headers.get('ratelimit-limit')),
    remaining: Number(response.headers.get('ratelimit-remaining')),
    body: await response.json().catch(() => null),
  };
}

/** Chave de aparelho valida: 64 caracteres hexadecimais, como o SHA-256 enviado pelo app. */
function deviceKeyFor(seed) {
  return String(seed).padStart(2, '0').repeat(32).slice(0, 64);
}

test('aparelhos distintos no mesmo IP de CGNAT nao consomem a cota um do outro', async () => {
  // O teto por aparelho fica no piso (10) de proposito: o teste precisa que o volume total no
  // IP passe MUITO do teto individual sem que ninguem seja bloqueado. Usar um valor abaixo do
  // piso faria o modulo eleva-lo silenciosamente e o teste passaria por motivo errado.
  const { authLimiter, authRateLimit } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 10 });
  assert.equal(authRateLimit.max, 10, 'pre-condicao: teto por aparelho em uso e 10');

  const server = await startServer(authLimiter);
  const cgnatIp = '152.233.23.194';

  try {
    // Cento e quarenta aparelhos atras do mesmo IPv4, como os 137 medidos em producao, com tres
    // requisicoes cada: 420 requisicoes no mesmo IP, quarenta e duas vezes o teto individual e
    // muito acima dos 300 que o desenho anterior permitia. Nenhum aparelho pode ser bloqueado.
    for (let device = 1; device <= 140; device += 1) {
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        const res = await bootstrap(server.port, {
          deviceKey: deviceKeyFor(device),
          ip: cgnatIp,
        });
        assert.equal(
          res.status,
          200,
          `aparelho ${device}, tentativa ${attempt}: bloqueado indevidamente`
        );
        assert.equal(res.limit, 10, 'o teto reportado deve ser o do aparelho');
      }
    }
  } finally {
    await server.close();
  }
});

test('o mesmo aparelho e barrado ao exceder o proprio teto', async () => {
  const { authLimiter } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 10 });
  const server = await startServer(authLimiter);
  const deviceKey = deviceKeyFor(7);

  try {
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const res = await bootstrap(server.port, { deviceKey, ip: '152.233.23.194' });
      assert.equal(res.status, 200, `tentativa ${attempt} deveria passar`);
      assert.equal(res.limit, 10, 'o teto reportado deve ser o do aparelho');
    }

    const blocked = await bootstrap(server.port, { deviceKey, ip: '152.233.23.194' });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.code, 'AUTH_RATE_LIMIT');
  } finally {
    await server.close();
  }
});

test('trocar de IP nao reinicia a cota do aparelho (modo aviao deixa de funcionar)', async () => {
  const { authLimiter, authRateLimit } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 10 });
  assert.equal(authRateLimit.max, 10);
  const server = await startServer(authLimiter);
  const deviceKey = deviceKeyFor(9);

  try {
    // Esgota a cota alternando de rede a cada requisicao, que era a forma de reset no desenho
    // por IP: dados moveis, Wi-Fi, VPN. Aqui isso nao ajuda.
    const ips = ['152.233.23.194', '189.40.1.7', '10.0.0.5', '79.127.4.4', '89.222.9.9'];
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const res = await bootstrap(server.port, {
        deviceKey,
        ip: ips[attempt % ips.length],
      });
      assert.equal(res.status, 200, `tentativa ${attempt + 1} deveria passar`);
    }

    const blocked = await bootstrap(server.port, { deviceKey, ip: '203.0.113.9' });
    assert.equal(
      blocked.status,
      429,
      'a cota do aparelho deve persistir mesmo em um IP inedito'
    );
  } finally {
    await server.close();
  }
});

test('requisicao sem identificacao de aparelho cai no fallback por IP', async () => {
  const { authLimiter, authRateLimit } = loadRateLimits({
    DEVICE_AUTH_RATE_LIMIT_MAX: 10,
    AUTH_RATE_LIMIT_MAX: 300,
  });
  assert.equal(authRateLimit.max, 10);
  assert.equal(authRateLimit.ipFallback.max, 300);

  const server = await startServer(authLimiter);

  try {
    // Build antigo, ou sondagem direta da API: corpo sem qualquer ancora de aparelho.
    const first = await bootstrap(server.port, { ip: '152.233.47.65' });
    assert.equal(first.status, 200);
    assert.equal(
      first.limit,
      300,
      'sem aparelho, o teto aplicado deve ser o tolerante do fallback por IP'
    );

    // O teto estreito do aparelho nao pode vazar para o caminho anonimo: a decima primeira
    // requisicao (que excederia DEVICE_AUTH_RATE_LIMIT_MAX=10) precisa continuar passando.
    for (let attempt = 2; attempt <= 15; attempt += 1) {
      const res = await bootstrap(server.port, { ip: '152.233.47.65' });
      assert.equal(res.status, 200, `tentativa anonima ${attempt} deveria passar`);
    }
  } finally {
    await server.close();
  }
});

test('cada requisicao consome exatamente um hit (sem contagem dupla)', async () => {
  const { authLimiter } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 10 });
  const server = await startServer(authLimiter);
  const deviceKey = deviceKeyFor(11);

  try {
    const first = await bootstrap(server.port, { deviceKey, ip: '152.233.23.194' });
    // Com a aplicacao duplicada que existia (app.use + rota), este valor era 8.
    assert.equal(
      first.remaining,
      9,
      'a primeira requisicao deve consumir um unico hit do bucket'
    );

    const second = await bootstrap(server.port, { deviceKey, ip: '152.233.23.194' });
    assert.equal(second.remaining, 8);
  } finally {
    await server.close();
  }
});

test('precedencia das ancoras: device_account_key vence android_id_key e legado', async () => {
  const { deviceIdentifierFromBody } = loadRateLimits();

  const accountKey = deviceKeyFor(21);
  const androidKey = deviceKeyFor(22);

  assert.equal(
    deviceIdentifierFromBody({
      body: {
        device_account_key: accountKey,
        android_id_key: androidKey,
        legacy_device_id: 'legado-antigo-1234',
      },
    }),
    `dev:${accountKey}`
  );

  assert.equal(
    deviceIdentifierFromBody({
      body: { android_id_key: androidKey, legacy_device_id: 'legado-antigo-1234' },
    }),
    `aid:${androidKey}`
  );

  assert.equal(
    deviceIdentifierFromBody({ body: { legacy_device_id: 'legado-antigo-1234' } }),
    'leg:legado-antigo-1234'
  );

  // Chave malformada nao pode virar bucket: cairia no fallback por IP, que e o comportamento
  // seguro. Um valor curto como "1" agruparia aparelhos diferentes no mesmo balde.
  assert.equal(deviceIdentifierFromBody({ body: { device_account_key: 'abc' } }), null);
  assert.equal(deviceIdentifierFromBody({ body: { legacy_device_id: '123' } }), null);
  assert.equal(deviceIdentifierFromBody({ body: {} }), null);
  assert.equal(deviceIdentifierFromBody({}), null);
});

test('o piso de seguranca recusa um teto por aparelho baixo demais', async () => {
  // Um valor herdado de configuracao antiga nao pode transformar o limite por aparelho em
  // bloqueio de usuario legitimo: o app faz varias requisicoes por abertura.
  const { authRateLimit } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 2 });
  assert.equal(authRateLimit.max, 10, 'abaixo do piso, vale o piso');

  // O fallback por IP tem piso proprio, muito mais alto, porque o bucket e compartilhado.
  const { authRateLimit: withLowIp } = loadRateLimits({ AUTH_RATE_LIMIT_MAX: 10 });
  assert.equal(withLowIp.ipFallback.max, 300);

  // Valores validos acima do piso passam intactos.
  const { authRateLimit: custom } = loadRateLimits({ DEVICE_AUTH_RATE_LIMIT_MAX: 45 });
  assert.equal(custom.max, 45);

  // O padrao do codigo, sem nenhuma variavel de ambiente.
  const { authRateLimit: defaults } = loadRateLimits({
    DEVICE_AUTH_RATE_LIMIT_MAX: undefined,
    AUTH_RATE_LIMIT_MAX: undefined,
  });
  assert.equal(defaults.max, 30);
  assert.equal(defaults.keyedBy, 'device_account_key');
  assert.equal(defaults.ipFallback.max, 600);
});
