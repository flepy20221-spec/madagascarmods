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

function deviceRequest(deviceAccountKey, extra = {}) {
  return {
    body: {
      device_account_key: deviceAccountKey,
      device_model: 'CashPix Test Device',
      app_version: '1.7.1+10',
      ...extra,
    },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  };
}

function createFakeDatabase() {
  const users = new Map();
  const aliases = new Map();
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
      if (normalized.includes('FROM device_account_aliases a')) {
        const userId = aliases.get(params[0]);
        const user = userId ? users.get(userId) : null;
        return { rows: user ? [{ ...user, alias_source: 'test' }] : [] };
      }
      if (normalized.includes('WHERE id = $1 AND refresh_token = $2')) {
        const user = users.get(params[0]);
        return {
          rows: user && user.refresh_token === params[1] ? [{ ...user }] : [],
        };
      }
      if (normalized.includes('WHERE device_id = $1')) {
        return {
          rows: [...users.values()]
            .filter((user) => user.device_id === params[0])
            .map((user) => ({ ...user })),
        };
      }
      if (normalized.startsWith('SELECT COUNT(*) AS count FROM users')) {
        return { rows: [{ count: '0' }] };
      }
      if (normalized.startsWith('INSERT INTO users')) {
        userInsertCount += 1;
        const user = {
          id: params[0],
          email: params[1],
          is_active: true,
          is_banned: false,
          device_id: params[2],
          device_account_key: params[2],
          support_code: `CP-TEST-${String(userInsertCount).padStart(4, '0')}`,
          refresh_token: null,
        };
        users.set(user.id, user);
        return { rows: [{ ...user }] };
      }
      if (normalized.startsWith('INSERT INTO device_account_aliases')) {
        const [key, userId] = params;
        const owner = aliases.get(key);
        if (owner && owner !== userId) return { rows: [] };
        aliases.set(key, userId);
        return { rows: [{ user_id: userId }] };
      }
      if (normalized.startsWith('UPDATE users SET device_id = $1')) {
        const user = users.get(params[4]);
        user.device_id = params[0];
        user.device_account_key = params[0];
        return { rows: [] };
      }
      if (normalized.startsWith('UPDATE users SET token = $1')) {
        const user = users.get(params[2]);
        user.token = params[0];
        user.refresh_token = params[1];
        return { rows: [] };
      }
      if (normalized.startsWith('INSERT INTO audit_log')) {
        return { rows: [] };
      }

      throw new Error(`Consulta inesperada: ${normalized}`);
    },
    release() {},
  };

  return {
    fakeClient,
    users,
    aliases,
    get userInsertCount() {
      return userInsertCount;
    },
  };
}

test('duas aberturas do mesmo aparelho criam uma unica conta', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();
  const key = 'b'.repeat(64);

  db.getClient = async () => state.fakeClient;
  t.after(async () => {
    db.getClient = originalGetClient;
    await db.pool.end();
  });

  const first = responseRecorder();
  await deviceHandler()(deviceRequest(key), first);
  assert.equal(first.statusCode, 201);
  assert.equal(first.body.success, true);
  assert.equal(first.body.accountCreated, true);

  const second = responseRecorder();
  await deviceHandler()(deviceRequest(key), second);
  assert.equal(second.statusCode, 200);
  assert.equal(second.body.success, true);
  assert.equal(second.body.accountCreated, false);
  assert.equal(second.body.user.id, first.body.user.id);
  assert.equal(state.userInsertCount, 1);
  assert.equal(state.aliases.get(key), first.body.user.id);
});

test('rotacao da assinatura usa a sessao salva e registra as duas chaves como aliases', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();
  const oldKey = 'a'.repeat(64);
  const newKey = 'c'.repeat(64);

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const first = responseRecorder();
  await deviceHandler()(deviceRequest(oldKey), first);

  const rotated = responseRecorder();
  await deviceHandler()(
    deviceRequest(newKey, { migration_refresh_token: first.body.refreshToken }),
    rotated
  );

  assert.equal(rotated.statusCode, 200);
  assert.equal(rotated.body.accountCreated, false);
  assert.equal(rotated.body.accountMigrated, true);
  assert.equal(rotated.body.user.id, first.body.user.id);
  assert.equal(state.userInsertCount, 1);
  assert.equal(state.aliases.get(oldKey), first.body.user.id);
  assert.equal(state.aliases.get(newKey), first.body.user.id);

  const oldBuildAgain = responseRecorder();
  await deviceHandler()(deviceRequest(oldKey), oldBuildAgain);
  assert.equal(oldBuildAgain.statusCode, 200);
  assert.equal(oldBuildAgain.body.user.id, first.body.user.id);
  assert.equal(state.userInsertCount, 1);
});
