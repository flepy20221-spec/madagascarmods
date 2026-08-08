/**
 * CashPix — Totais da listagem de usuarios no painel administrativo
 *
 * Defeito reproduzido aqui:
 * Os cards do painel eram calculados no cliente a partir do array recebido de
 * GET /api/admin/users, que chega truncado pelo LIMIT. Com uma base maior que o
 * teto de paginacao, "Usuarios listados" exibia o proprio teto (100) como se
 * fosse o total, e "Pontos em circulacao" somava apenas a primeira pagina,
 * subestimando o passivo em pontos do sistema.
 *
 * O teste cria 137 usuarios com saldo conhecido e exige que os agregados
 * retornados descrevam a base inteira, nao a pagina.
 *
 * Requer:
 *   DATABASE_URL=postgresql://postgres:testpass@127.0.0.1:5432/cashpix_test \
 *     node --test tests/admin_users_totals.test.js
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

const jwt = require('jsonwebtoken');
const db = require('../src/models/db');

// Volume deliberadamente acima do teto de 100 registros por pagina.
const TOTAL_USERS = 137;
const BANNED_USERS = 9;
const POINTS_EACH = 500;
const TAG = 'totals-test';

function buildApp() {
  const express = require('express');
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use('/api/admin', require('../src/routes/admin'));
  return app;
}

function get(server, path, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: server.address().port,
      path,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
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
    req.end();
  });
}

async function seed() {
  // Admin real: authenticateAdmin exige o registro ativo em admin_users e o
  // token deve carregar isAdmin e userId (ver src/middleware/auth.js).
  const adminId = crypto.randomUUID();
  await db.query(
    `INSERT INTO admin_users (id, email, password_hash, name, role, is_active)
     VALUES ($1, $2, $3, 'Totals Test', 'super_admin', true)`,
    [adminId, `${TAG}-admin@example.com`, 'x'.repeat(60)]
  );

  for (let i = 0; i < TOTAL_USERS; i++) {
    const userId = crypto.randomUUID();
    const isBanned = i < BANNED_USERS;
    await db.query(
      `INSERT INTO users (id, email, support_code, device_account_key, device_id,
                          ip_address, app_version, is_active, is_banned, created_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, '152.233.10.10', '1.7.3', true, $6, NOW(), NOW())`,
      [
        userId,
        `${TAG}-${i}@example.com`,
        `CP-TEST-${String(i).padStart(4, '0')}-0000`,
        crypto.createHash('sha256').update(`${TAG}-${i}`).digest('hex'),
        `dev-${TAG}-${i}`,
        isBanned,
      ]
    );
    // Saldo identico em todos: o total esperado fica exato e a falha, obvia.
    await db.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'admin_adjustment', 'seed totals test')`,
      [crypto.randomUUID(), userId, POINTS_EACH]
    );
  }

  return jwt.sign(
    { userId: adminId, email: `${TAG}-admin@example.com`, role: 'super_admin', isAdmin: true },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function cleanup() {
  await db.query(`DELETE FROM points_ledger WHERE user_id IN (SELECT id FROM users WHERE email LIKE $1)`, [`${TAG}-%`]);
  await db.query(`DELETE FROM users WHERE email LIKE $1`, [`${TAG}-%`]);
  await db.query(`DELETE FROM admin_users WHERE email LIKE $1`, [`${TAG}-%`]);
}

test('os totais descrevem a base inteira, nao a pagina retornada', async (t) => {
  await cleanup();
  const token = await seed();
  t.after(async () => { await cleanup(); });

  const server = buildApp().listen(0);
  await new Promise((r) => server.once('listening', r));
  t.after(() => new Promise((r) => server.close(r)));

  const res = await get(server, '/api/admin/users?page=1&limit=50', token);
  assert.strictEqual(res.status, 200, `esperado 200, recebido ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);

  // A pagina continua limitada: e o comportamento desejado.
  assert.strictEqual(res.body.users.length, 50, 'a pagina deve respeitar o limit solicitado');

  const totals = res.body.totals;
  assert.ok(totals, 'a resposta deve incluir o objeto totals');

  assert.strictEqual(
    totals.users,
    TOTAL_USERS,
    `total de usuarios deve ser ${TOTAL_USERS} (a base inteira), nao ${totals.users}`
  );
  assert.strictEqual(
    totals.banned,
    BANNED_USERS,
    `banidos deve ser ${BANNED_USERS}; contar so a pagina esconderia os que ficam fora dela`
  );
  assert.strictEqual(
    Number(totals.points),
    TOTAL_USERS * POINTS_EACH,
    `pontos em circulacao deve somar toda a base (${TOTAL_USERS * POINTS_EACH})`
  );

  // Somar apenas a pagina daria 50 * 500 = 25000, valor que o painel exibia antes.
  assert.notStrictEqual(
    Number(totals.points),
    50 * POINTS_EACH,
    'os pontos nao devem corresponder apenas a pagina retornada'
  );

  assert.strictEqual(res.body.pagination.total, TOTAL_USERS);
  assert.strictEqual(res.body.pagination.totalPages, Math.ceil(TOTAL_USERS / 50));
  assert.strictEqual(res.body.pagination.hasMore, true);
});

test('a paginacao alcanca o ultimo registro e encerra corretamente', async (t) => {
  await cleanup();
  const token = await seed();
  t.after(async () => { await cleanup(); });

  const server = buildApp().listen(0);
  await new Promise((r) => server.once('listening', r));
  t.after(() => new Promise((r) => server.close(r)));

  const seen = new Set();
  let page = 1;
  let hasMore = true;

  while (hasMore && page <= 20) {
    const res = await get(server, `/api/admin/users?page=${page}&limit=50`, token);
    assert.strictEqual(res.status, 200);
    for (const user of res.body.users) seen.add(user.id);
    // Os totais nao podem oscilar conforme a pagina navegada.
    assert.strictEqual(res.body.totals.users, TOTAL_USERS, `totals.users mudou na pagina ${page}`);
    hasMore = res.body.pagination.hasMore;
    page++;
  }

  assert.strictEqual(
    seen.size,
    TOTAL_USERS,
    `navegando as paginas deve alcancar os ${TOTAL_USERS} usuarios; alcancados: ${seen.size}`
  );
  // 137 registros em paginas de 50 => 3 paginas; hasMore falso na ultima.
  assert.strictEqual(page - 1, 3, 'devem existir exatamente 3 paginas');
  assert.strictEqual(hasMore, false, 'hasMore deve ser falso na ultima pagina');
});

test('os totais respeitam o filtro aplicado', async (t) => {
  await cleanup();
  const token = await seed();
  t.after(async () => { await cleanup(); });

  const server = buildApp().listen(0);
  await new Promise((r) => server.once('listening', r));
  t.after(() => new Promise((r) => server.close(r)));

  const res = await get(server, '/api/admin/users?status=banned&limit=50', token);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(
    res.body.totals.users,
    BANNED_USERS,
    'ao filtrar por banidos, o total deve refletir o subconjunto filtrado'
  );
  assert.strictEqual(
    Number(res.body.totals.points),
    BANNED_USERS * POINTS_EACH,
    'os pontos tambem devem respeitar o filtro'
  );
  assert.strictEqual(res.body.pagination.hasMore, false);
});

// Encerra o pool e o timer de limpeza de nonces do antiFraud.
test('encerra conexoes', async () => {
  await db.pool?.end?.();
  setImmediate(() => process.exit(0));
});
