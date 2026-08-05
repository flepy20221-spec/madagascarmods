/**
 * Simulacao end-to-end do cenario reportado: o mesmo aparelho, apos a troca da chave de
 * assinatura do APK (1.6.0+8 -> 1.7.0+9), envia um device_account_key diferente.
 *
 * Antes da correcao a rota criava uma segunda conta. Aqui validamos, contra um Postgres real,
 * que a conta original e reencontrada e que ambas as chaves permanecem resolviveis.
 *
 * Uso: NODE_ENV=test DATABASE_URL=... node scripts/simulate_signing_rotation.js
 */
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

// Os middlewares criam timers de limpeza ao serem importados; em script isolado eles
// mantem o processo vivo se nao forem unref.
const originalSetInterval = global.setInterval;
global.setInterval = (...args) => {
  const timer = originalSetInterval(...args);
  timer.unref?.();
  return timer;
};
const db = require('../src/models/db');
const authRouter = require('../src/routes/auth');
global.setInterval = originalSetInterval;

function deviceHandler() {
  const layer = authRouter.stack.find(
    (item) => item.route?.path === '/device' && item.route.methods.post
  );
  assert.ok(layer, 'POST /auth/device deve existir');
  return layer.route.stack.at(-1).handle;
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

async function callDevice(body) {
  const req = { body, headers: {}, socket: { remoteAddress: '10.20.30.40' } };
  const res = responseRecorder();
  await deviceHandler()(req, res);
  return res;
}

const hash = (seed) => crypto.createHash('sha256').update(seed).digest('hex');

async function cleanup(keys) {
  const users = await db.query(
    `SELECT id FROM users
      WHERE device_account_key = ANY($1::varchar[])
         OR device_id = ANY($1::varchar[])
         OR id IN (SELECT user_id FROM device_account_aliases WHERE device_account_key = ANY($1::varchar[]))`,
    [keys]
  );
  for (const row of users.rows) {
    await db.query('DELETE FROM audit_log WHERE target_id = $1 OR actor_id = $1', [row.id]);
    await db.query('DELETE FROM users WHERE id = $1', [row.id]);
  }
}

async function main() {
  const stamp = Date.now();
  const oldKey = hash(`rotation-old-${stamp}`);
  const newKey = hash(`rotation-new-${stamp}`);
  await cleanup([oldKey, newKey]);

  // 1) Instalacao 1.6.0+8: primeira abertura cria a conta.
  const first = await callDevice({
    device_account_key: oldKey,
    device_model: 'motorola moto g60',
    app_version: '1.6.0+8',
  });
  assert.equal(first.statusCode, 201, `esperado 201 no cadastro, recebido ${first.statusCode}`);
  const userId = first.body.user.id;
  const refreshToken = first.body.refreshToken;

  // 2) Atualizacao para 1.7.0+9 com keystore propria: o ANDROID_ID muda e, com ele, a chave.
  //    O app envia a sessao salva como prova de posse da conta.
  const rotated = await callDevice({
    device_account_key: newKey,
    migration_refresh_token: refreshToken,
    legacy_device_id: oldKey,
    device_model: 'motorola moto g60',
    app_version: '1.7.0+9',
  });
  assert.equal(rotated.statusCode, 200, `esperado 200 na rotacao, recebido ${rotated.statusCode}`);
  assert.equal(rotated.body.accountCreated, false, 'nenhuma conta nova pode ser criada');
  assert.equal(rotated.body.user.id, userId, 'a conta precisa ser a mesma');

  // 3) A chave antiga continua resolvivel como alias: um downgrade ou uma reinstalacao da
  //    versao antiga volta para a mesma conta, sem duplicar.
  const oldKeyAgain = await callDevice({ device_account_key: oldKey, app_version: '1.6.0+8' });
  assert.equal(oldKeyAgain.statusCode, 200);
  assert.equal(oldKeyAgain.body.user.id, userId, 'a chave antiga precisa resolver na conta principal');

  const aliases = await db.query(
    'SELECT device_account_key, source FROM device_account_aliases WHERE user_id = $1 ORDER BY first_seen_at',
    [userId]
  );
  const total = await db.query(
    `SELECT COUNT(*)::int AS count FROM users
      WHERE device_account_key = ANY($1::varchar[])
         OR id IN (SELECT user_id FROM device_account_aliases WHERE device_account_key = ANY($1::varchar[]))`,
    [[oldKey, newKey]]
  );
  const support = await db.query('SELECT support_code FROM users WHERE id = $1', [userId]);

  console.log(JSON.stringify({
    success: true,
    userId,
    supportCode: support.rows[0].support_code,
    aliases: aliases.rows,
    totalAccountsForDevice: total.rows[0].count,
  }, null, 2));

  assert.equal(total.rows[0].count, 1, 'o aparelho nao pode ter mais de uma conta');
  assert.equal(aliases.rows.length, 2, 'as duas chaves precisam estar registradas');

  await cleanup([oldKey, newKey]);
  await db.pool.end();
}

main().catch(async (error) => {
  console.error(error);
  try { await db.pool.end(); } catch (_) { /* pool ja encerrado */ }
  process.exit(1);
});
