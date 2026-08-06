const test = require('node:test');
const assert = require('node:assert/strict');

// Os middlewares criam timers de limpeza ao serem importados. Em teste, eles
// devem ser unref para nao manter o processo vivo depois das assercoes.
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

test('duas aberturas do mesmo aparelho criam uma unica conta', async (t) => {
  const originalGetClient = db.getClient;
  const key = 'b'.repeat(64);
  let storedUser = null;
  let userInsertCount = 0;

  const fakeClient = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();

      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(normalized)) {
        return { rows: [] };
      }
      if (normalized.startsWith('SELECT pg_advisory_xact_lock')) {
        return { rows: [] };
      }
      if (normalized.includes('FROM users') && normalized.includes('device_account_key = $1')) {
        return { rows: storedUser ? [{ ...storedUser }] : [] };
      }
      if (normalized.startsWith('SELECT COUNT(*) AS count FROM users')) {
        return { rows: [{ count: '0' }] };
      }
      if (normalized.startsWith('INSERT INTO users')) {
        userInsertCount += 1;
        storedUser = {
          id: params[0],
          email: params[1],
          is_active: true,
          is_banned: false,
          device_account_key: params[2],
        };
        return { rows: [{ ...storedUser }] };
      }
      if (normalized.startsWith('UPDATE users SET device_model')) {
        return { rows: [] };
      }
      if (normalized.startsWith('UPDATE users SET token')) {
        return { rows: [] };
      }
      if (normalized.startsWith('INSERT INTO audit_log')) {
        return { rows: [] };
      }

      throw new Error(`Consulta inesperada: ${normalized}`);
    },
    release() {},
  };

  db.getClient = async () => fakeClient;
  t.after(async () => {
    db.getClient = originalGetClient;
    await db.pool.end();
  });

  const request = {
    body: {
      device_account_key: key,
      device_model: 'CashPix Test Device',
      app_version: '1.6.0+8',
    },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  };

  const first = responseRecorder();
  await deviceHandler()(request, first);
  assert.equal(first.statusCode, 201);
  assert.equal(first.body.success, true);
  assert.equal(first.body.accountCreated, true);
  const firstUserId = first.body.user.id;

  const second = responseRecorder();
  await deviceHandler()(request, second);
  assert.equal(second.statusCode, 200);
  assert.equal(second.body.success, true);
  assert.equal(second.body.accountCreated, false);
  assert.equal(second.body.user.id, firstUserId);
  assert.equal(userInsertCount, 1);
});
