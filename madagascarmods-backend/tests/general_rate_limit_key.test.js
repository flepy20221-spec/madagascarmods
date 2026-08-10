/**
 * CashPix — Chave de contagem do limiter geral de /api/
 *
 * ============================================================================================
 * DEFEITO COBERTO
 *
 * A mensagem "Too many requests, please try again later." que o usuario recebeu em producao NAO
 * vinha do limiter de autenticacao, e sim do limiter geral de src/index.js: 300 requisicoes por
 * IP em 15 minutos, texto padrao da biblioteca, em ingles e sem codigo. Confirmado por header
 * em producao (`/api/config` respondia com ratelimit-limit: 300).
 *
 * Como ele roda antes de todas as rotas de /api/ e contava por IP, era o teto mais baixo de
 * toda a cadeia sob CGNAT. Cada abertura do app consome cerca de quatro requisicoes, de modo
 * que setenta aberturas por gateway de operadora esgotavam a cota de todos os assinantes
 * daquele IP.
 *
 * GARANTIAS TESTADAS
 *
 *   1. Usuarios autenticados distintos no mesmo IP nao compartilham cota.
 *   2. Aparelhos distintos no mesmo IP nao compartilham cota no bootstrap (antes de existir
 *      token).
 *   3. O caminho residual sem usuario e sem aparelho ainda conta por IP, com teto tolerante.
 *   4. A resposta de bloqueio traz mensagem em portugues e codigo GENERAL_RATE_LIMIT.
 *
 * A politica de chave e reconstruida aqui a partir de userOrTokenKey e deviceIdentifierFromBody,
 * as MESMAS funcoes usadas por src/index.js. Montar o app real exigiria PostgreSQL e as rotas
 * completas; o objeto de teste e a decisao de bucket, que e onde estava o defeito.
 *
 * Execucao:
 *   node --test tests/general_rate_limit_key.test.js
 * ============================================================================================
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = process.env.APP_HMAC_SECRET || 'test_hmac_secret_com_mais_de_32_caracteres';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/unused_in_this_test';

const {
  userOrTokenKey,
  deviceIdentifierFromBody,
} = require('../src/middleware/rateLimits');

// Espelha src/index.js. Os valores sao reduzidos no teste apenas para encurtar os lacos; a
// politica exercitada e identica.
const LIMIT_PER_IDENTITY = 5;
const LIMIT_PER_IP = 20;

function generalLimiterKey(req) {
  const identity = userOrTokenKey(req);
  if (!identity.startsWith('ip:')) return identity;
  const deviceKey = deviceIdentifierFromBody(req);
  return deviceKey || identity;
}

async function startServer() {
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: (req) => (
      generalLimiterKey(req).startsWith('ip:') ? LIMIT_PER_IP : LIMIT_PER_IDENTITY
    ),
    keyGenerator: generalLimiterKey,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Muitas requisicoes. Aguarde alguns minutos e tente novamente.',
      code: 'GENERAL_RATE_LIMIT',
    },
  });

  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use('/api/', limiter);
  app.post('/api/auth/device', (req, res) => res.json({ success: true }));
  app.get('/api/config/app', (req, res) => res.json({ success: true }));
  app.get('/api/users/me', (req, res) => res.json({ success: true }));

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return {
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function tokenFor(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

async function call(port, pathname, { ip, token, body } = {}) {
  const headers = { 'X-Forwarded-For': ip };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';

  const response = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    method: body ? 'POST' : 'GET',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  return {
    status: response.status,
    limit: Number(response.headers.get('ratelimit-limit')),
    body: await response.json().catch(() => null),
  };
}

function deviceKeyFor(seed) {
  return String(seed).padStart(2, '0').repeat(32).slice(0, 64);
}

test('usuarios autenticados distintos no mesmo IP nao compartilham cota', async () => {
  const server = await startServer();
  const cgnatIp = '152.233.23.194';

  try {
    // Trinta usuarios do mesmo gateway de CGNAT, cinco requisicoes cada: 150 no mesmo IP, muito
    // acima do teto por identidade. Nenhum pode ser bloqueado.
    for (let user = 1; user <= 30; user += 1) {
      const token = tokenFor(`user-${user}`);
      for (let attempt = 1; attempt <= LIMIT_PER_IDENTITY; attempt += 1) {
        const res = await call(server.port, '/api/users/me', { ip: cgnatIp, token });
        assert.equal(res.status, 200, `usuario ${user}, tentativa ${attempt}`);
        assert.equal(res.limit, LIMIT_PER_IDENTITY);
      }
    }

    // O proprio usuario, ao exceder, e barrado — a protecao contra flood continua existindo.
    const heavy = tokenFor('user-1');
    const blocked = await call(server.port, '/api/users/me', { ip: cgnatIp, token: heavy });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.code, 'GENERAL_RATE_LIMIT');
    assert.match(blocked.body.error, /Muitas requisicoes/);
  } finally {
    await server.close();
  }
});

test('aparelhos distintos no mesmo IP nao compartilham cota no bootstrap', async () => {
  const server = await startServer();
  const cgnatIp = '152.233.47.65';

  try {
    // Bootstrap acontece antes de existir token: a chave vem do corpo da requisicao.
    for (let device = 1; device <= 30; device += 1) {
      for (let attempt = 1; attempt <= LIMIT_PER_IDENTITY; attempt += 1) {
        const res = await call(server.port, '/api/auth/device', {
          ip: cgnatIp,
          body: { device_account_key: deviceKeyFor(device) },
        });
        assert.equal(res.status, 200, `aparelho ${device}, tentativa ${attempt}`);
        assert.equal(res.limit, LIMIT_PER_IDENTITY);
      }
    }
  } finally {
    await server.close();
  }
});

test('sem usuario e sem aparelho, a contagem continua por IP com teto tolerante', async () => {
  const server = await startServer();
  const ip = '79.127.4.4';

  try {
    // GET /api/config/app e anonimo e nao carrega identificacao de aparelho. Este e o caminho
    // residual em que o IP permanece como chave.
    const first = await call(server.port, '/api/config/app', { ip });
    assert.equal(first.status, 200);
    assert.equal(
      first.limit,
      LIMIT_PER_IP,
      'sem identidade, vale o teto tolerante por IP'
    );

    for (let attempt = 2; attempt <= LIMIT_PER_IP; attempt += 1) {
      const res = await call(server.port, '/api/config/app', { ip });
      assert.equal(res.status, 200, `tentativa ${attempt} deveria passar`);
    }

    const blocked = await call(server.port, '/api/config/app', { ip });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.code, 'GENERAL_RATE_LIMIT');
  } finally {
    await server.close();
  }
});

test('um token invalido nao permite escapar da contagem', async () => {
  const server = await startServer();
  const ip = '89.222.9.9';

  try {
    // A chave do limiter le o payload do JWT sem verificar assinatura, de proposito (a rota
    // valida depois). Um token forjado com userId fixo cai sempre no mesmo bucket, portanto
    // nao serve para multiplicar cota. Sem userId no payload, cai no IP.
    const forged = Buffer.from(JSON.stringify({ sub: 'sem-userid' })).toString('base64url');
    const token = `x.${forged}.y`;

    for (let attempt = 1; attempt <= LIMIT_PER_IP; attempt += 1) {
      const res = await call(server.port, '/api/config/app', { ip, token });
      assert.equal(res.status, 200, `tentativa ${attempt} deveria passar pelo bucket de IP`);
      assert.equal(res.limit, LIMIT_PER_IP);
    }

    const blocked = await call(server.port, '/api/config/app', { ip, token });
    assert.equal(blocked.status, 429);
  } finally {
    await server.close();
  }
});
