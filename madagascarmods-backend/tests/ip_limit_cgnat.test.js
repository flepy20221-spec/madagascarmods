/**
 * CashPix — Regressao do bloqueio indevido por rede (CGNAT)
 *
 * Defeito reproduzido aqui:
 * Usuarios legitimos recebiam "Muitas contas criadas nesta rede" ao instalar o app.
 * A causa era o teto de 8 contas por IP em 24h combinado ao CGNAT das operadoras
 * moveis brasileiras, onde milhares de celulares distintos compartilham um mesmo
 * IPv4 publico (faixas observadas em producao: 152.233.47.66, 89.222.103.193).
 *
 * O teste exercita a rota real POST /api/auth/device contra PostgreSQL, sem mocks,
 * porque o defeito estava na consulta SQL e no limiar, nao na camada HTTP.
 *
 * Requer:
 *   DATABASE_URL=postgresql://postgres:testpass@127.0.0.1:5432/cashpix_test \
 *     node --test tests/ip_limit_cgnat.test.js
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = process.env.APP_HMAC_SECRET || 'test_hmac_secret_com_mais_de_32_caracteres';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL nao definida. Teste ignorado.');
  process.exit(0);
}

const db = require('../src/models/db');

// IP publico de operadora observado no painel de producao compartilhado por
// varios usuarios distintos. Serve como IP de CGNAT do cenario.
const CGNAT_IP = '152.233.47.66';

function deviceKey() {
  return crypto.createHash('sha256').update(crypto.randomUUID()).digest('hex');
}

/**
 * Monta o app Express real com as rotas de autenticacao, forcando o IP do cliente
 * para simular o CGNAT. Sobrescrever req.ip e necessario porque o socket local
 * sempre reporta 127.0.0.1, que a correcao trata como IP nao confiavel.
 */
function buildApp(forcedIp) {
  const express = require('express');
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf && buf.length ? buf.toString('utf8') : '';
    }
  }));
  app.use((req, _res, next) => {
    Object.defineProperty(req, 'ip', { get: () => forcedIp, configurable: true });
    next();
  });
  app.use('/api/auth', require('../src/routes/auth'));
  return app;
}

/**
 * Assina a requisicao exatamente como api_service.dart do app Flutter:
 *   payload = '$path|$timestamp|$nonce|$body'  com path SEM o prefixo '/api'.
 * A rota /auth/device passa por antifraudMiddleware, portanto sem estes headers
 * a resposta seria 400 INVALID_REQUEST e o teste nunca alcancaria a regra de IP.
 */
function signedHeaders(path, body) {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();
  const signature = crypto
    .createHmac('sha256', process.env.APP_HMAC_SECRET)
    .update(`${path}|${timestamp}|${nonce}|${body}`)
    .digest('hex');
  return {
    'x-signature': signature,
    'x-timestamp': timestamp,
    'x-nonce': nonce,
    'x-app-version': '1.7.3',
    'x-platform': 'android',
  };
}

function postDevice(server, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1',
      port: server.address().port,
      path: '/api/auth/device',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...signedHeaders('/auth/device', payload),
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch (_) { parsed = { raw: data }; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function cleanup() {
  await db.query('DELETE FROM device_account_aliases WHERE user_id IN (SELECT id FROM users WHERE ip_address = $1)', [CGNAT_IP]);
  await db.query('DELETE FROM audit_log WHERE ip_address = $1', [CGNAT_IP]);
  await db.query('DELETE FROM users WHERE ip_address = $1', [CGNAT_IP]);
}

test('aparelhos distintos atras do mesmo IP de CGNAT conseguem criar conta', async (t) => {
  await cleanup();
  t.after(async () => { await cleanup(); });

  const app = buildApp(CGNAT_IP);
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  t.after(() => new Promise((r) => server.close(r)));

  // Doze aparelhos fisicamente distintos, todos saindo pelo mesmo IP da operadora.
  // Antes da correcao, do nono em diante a resposta era 429 IP_ACCOUNT_LIMIT.
  const total = 12;
  const results = [];

  for (let i = 0; i < total; i++) {
    const res = await postDevice(server, {
      device_account_key: deviceKey(),
      installation_state: 'fresh_install',
      device_model: `Galaxy Test ${i}`,
      app_version: '1.7.3',
    });
    results.push(res);
  }

  const blocked = results.filter((r) => r.body?.code === 'IP_ACCOUNT_LIMIT');
  assert.strictEqual(
    blocked.length,
    0,
    `Nenhum aparelho legitimo deve receber IP_ACCOUNT_LIMIT, mas ${blocked.length} receberam.`
  );

  const created = results.filter((r) => r.status === 200 || r.status === 201);
  assert.strictEqual(
    created.length,
    total,
    `Todos os ${total} aparelhos deveriam criar conta. Criados: ${created.length}. ` +
    `Respostas: ${JSON.stringify(results.map((r) => ({ s: r.status, c: r.body?.code })))}`
  );

  // O anti-farm por aparelho continua valendo: cada conta e unica por device.
  const distinct = await db.query(
    `SELECT COUNT(DISTINCT device_account_key) AS keys, COUNT(*) AS rows
       FROM users WHERE ip_address = $1`,
    [CGNAT_IP]
  );
  assert.strictEqual(
    Number(distinct.rows[0].keys),
    Number(distinct.rows[0].rows),
    'Cada conta criada deve corresponder a exatamente um device_account_key.'
  );
});

test('o mesmo aparelho reabrindo o app nao consome cota do IP', async (t) => {
  await cleanup();
  t.after(async () => { await cleanup(); });

  const app = buildApp(CGNAT_IP);
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  t.after(() => new Promise((r) => server.close(r)));

  const key = deviceKey();

  // Vinte aberturas do MESMO aparelho. A contagem por aparelhos distintos garante
  // que reinstalacoes nao esgotem a cota da rede inteira.
  for (let i = 0; i < 20; i++) {
    const res = await postDevice(server, {
      device_account_key: key,
      installation_state: 'fresh_install',
      device_model: 'Galaxy Repeat',
      app_version: '1.7.3',
    });
    assert.notStrictEqual(
      res.body?.code,
      'IP_ACCOUNT_LIMIT',
      `Reabertura ${i + 1} do mesmo aparelho nao deve ser bloqueada por limite de rede.`
    );
  }

  const rows = await db.query('SELECT COUNT(*) AS count FROM users WHERE ip_address = $1', [CGNAT_IP]);
  assert.strictEqual(Number(rows.rows[0].count), 1, 'O mesmo aparelho deve ter exatamente uma conta.');
});

// Encerra o pool apos o ultimo teste; sem isto o processo do runner nao finaliza.
test('encerra conexoes', async () => {
  await db.pool?.end?.();
  // O middleware antiFraud mantem um setInterval de limpeza de nonces em memoria,
  // que sozinho impede o event loop de esvaziar. Encerrar explicitamente evita
  // que a suite fique pendurada no CI.
  setImmediate(() => process.exit(0));
});
