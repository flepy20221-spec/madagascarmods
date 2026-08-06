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
const {
  generateDeviceBindingToken,
  hashDeviceBindingToken,
  normalizeInstallationState,
  INSTALLATION_STATE,
} = require('../src/utils/deviceIdentity');
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
      device_model: 'Motorola moto g60',
      app_version: '1.7.3+12',
      installation_state: 'fresh_install',
      ...extra,
    },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  };
}

function createFakeDatabase() {
  const users = new Map();
  const aliases = new Map();
  const auditLog = [];
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
      if (normalized.startsWith('SELECT device_binding_token_hash FROM users')) {
        const user = users.get(params[0]);
        return {
          rows: user
            ? [{ device_binding_token_hash: user.device_binding_token_hash || null }]
            : [],
        };
      }
      if (normalized.includes('WHERE device_binding_token_hash = $1')) {
        const user = [...users.values()].find(
          (item) => item.device_binding_token_hash === params[0]
        );
        return { rows: user ? [{ ...user }] : [] };
      }
      if (normalized.startsWith('UPDATE users SET device_binding_token_hash = $1')) {
        const user = users.get(params[1]);
        if (user) user.device_binding_token_hash = params[0];
        return { rows: [] };
      }
      if (normalized.startsWith('SELECT support_code FROM users')) {
        const user = users.get(params[0]);
        return { rows: user ? [{ support_code: user.support_code }] : [] };
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
          device_binding_token_hash: null,
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
        auditLog.push({ action: params[1], payload: params[2] });
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
    auditLog,
    get userInsertCount() {
      return userInsertCount;
    },
  };
}

test('primeiro acesso emite um token de vinculo e devolve o codigo de suporte', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();
  const key = 'a'.repeat(64);

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const res = responseRecorder();
  await deviceHandler()(deviceRequest(key), res);

  assert.equal(res.statusCode, 201);
  assert.equal(res.body.accountCreated, true);
  assert.match(res.body.deviceBindingToken, /^[a-f0-9]{64}$/);
  assert.equal(res.body.user.supportCode, 'CP-TEST-0001');

  // O banco deve guardar apenas o hash. Um vazamento nao pode revelar o token.
  const user = state.users.get(res.body.user.id);
  assert.equal(
    user.device_binding_token_hash,
    hashDeviceBindingToken(res.body.deviceBindingToken)
  );
  assert.notEqual(user.device_binding_token_hash, res.body.deviceBindingToken);
});

test('token de vinculo reassocia a conta quando o ANDROID_ID muda', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();
  const oldKey = 'b'.repeat(64);
  const newKey = 'c'.repeat(64);

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const first = responseRecorder();
  await deviceHandler()(deviceRequest(oldKey), first);
  const bindingToken = first.body.deviceBindingToken;
  assert.ok(bindingToken);

  // Cenario exato do Moto G60: chave de assinatura trocada, ANDROID_ID diferente,
  // refresh token local ausente. Apenas o token de vinculo sobreviveu.
  const rotated = responseRecorder();
  await deviceHandler()(
    deviceRequest(newKey, {
      device_binding_token: bindingToken,
      installation_state: 'upgraded_without_proof',
    }),
    rotated
  );

  assert.equal(rotated.statusCode, 200);
  assert.equal(rotated.body.accountCreated, false);
  assert.equal(rotated.body.accountMigrated, true);
  assert.equal(rotated.body.migrationMethod, 'binding_token');
  assert.equal(rotated.body.user.id, first.body.user.id);

  // O ponto central: nenhuma conta adicional foi criada.
  assert.equal(state.userInsertCount, 1);

  // As duas chaves resolvem a mesma conta.
  assert.equal(state.aliases.get(oldKey), first.body.user.id);
  assert.equal(state.aliases.get(newKey), first.body.user.id);
});

test('o token de vinculo nao e rotacionado a cada acesso', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();
  const key = 'd'.repeat(64);

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const first = responseRecorder();
  await deviceHandler()(deviceRequest(key), first);
  const originalHash = state.users.get(first.body.user.id)
    .device_binding_token_hash;

  const second = responseRecorder();
  await deviceHandler()(
    deviceRequest(key, {
      device_binding_token: first.body.deviceBindingToken,
      installation_state: 'existing_install',
    }),
    second
  );

  assert.equal(second.statusCode, 200);
  // Nenhum token novo e devolvido: o aplicativo continua com o que ja tem salvo.
  assert.equal(second.body.deviceBindingToken, undefined);
  assert.equal(
    state.users.get(first.body.user.id).device_binding_token_hash,
    originalHash
  );
});

test('estado ambiguo sem prova nao cria conta nova', async (t) => {
  const originalGetClient = db.getClient;
  const originalQuery = db.query;
  const state = createFakeDatabase();

  db.getClient = async () => state.fakeClient;

  // logAuthEvent grava pelo pool (db.query), nao pelo client da transacao, porque
  // o bloqueio acontece depois do ROLLBACK e a escrita precisa sobreviver a ele.
  db.query = async (sql, params = []) => {
    const normalized = String(sql).replace(/\s+/g, ' ').trim();
    if (normalized.startsWith('INSERT INTO audit_log')) {
      state.auditLog.push({ action: params[1], payload: params[3] });
      return { rows: [] };
    }
    return { rows: [] };
  };

  t.after(() => {
    db.getClient = originalGetClient;
    db.query = originalQuery;
  });

  // Conta preexistente do aparelho, criada por um build anterior.
  const existing = responseRecorder();
  await deviceHandler()(deviceRequest('e'.repeat(64)), existing);
  assert.equal(state.userInsertCount, 1);

  // Reinstalacao limpa: chave nova, nenhuma prova, mas o app sabe que ja rodou
  // neste aparelho. Este e o caso que produzia a conta duplicada com saldo zero.
  const ambiguous = responseRecorder();
  await deviceHandler()(
    deviceRequest('f'.repeat(64), {
      installation_state: 'upgraded_without_proof',
    }),
    ambiguous
  );

  assert.equal(ambiguous.statusCode, 409);
  assert.equal(ambiguous.body.code, 'DEVICE_RECOVERY_REQUIRED');
  assert.ok(ambiguous.body.supportEmail);

  // Nenhuma conta adicional. O saldo da conta original permanece intocado.
  assert.equal(state.userInsertCount, 1);

  const blocked = state.auditLog.find(
    (entry) => entry.action === 'DEVICE_ACCOUNT_CREATION_BLOCKED_AMBIGUOUS'
  );
  assert.ok(blocked, 'o bloqueio deve ser auditado');
});

test('instalacao realmente nova continua criando conta', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const res = responseRecorder();
  await deviceHandler()(
    deviceRequest('1'.repeat(64), { installation_state: 'fresh_install' }),
    res
  );

  assert.equal(res.statusCode, 201);
  assert.equal(res.body.accountCreated, true);
  assert.equal(state.userInsertCount, 1);
});

test('build antigo sem installation_state continua funcionando', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  // Compatibilidade retroativa: um APK 1.7.2+11 instalado nao envia o campo.
  // Ele nao pode ser bloqueado por causa da correcao.
  const req = deviceRequest('2'.repeat(64));
  delete req.body.installation_state;

  const res = responseRecorder();
  await deviceHandler()(req, res);

  assert.equal(res.statusCode, 201);
  assert.equal(res.body.accountCreated, true);
});

test('token de vinculo desconhecido nao sequestra conta alheia', async (t) => {
  const originalGetClient = db.getClient;
  const state = createFakeDatabase();

  db.getClient = async () => state.fakeClient;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  // Conta legitima da vitima.
  const victim = responseRecorder();
  await deviceHandler()(deviceRequest('3'.repeat(64)), victim);
  const victimId = victim.body.user.id;

  // Atacante em outro aparelho apresenta um token inventado, com o mesmo modelo
  // e o mesmo IP da vitima. Nem modelo nem IP podem associar contas.
  const attacker = responseRecorder();
  await deviceHandler()(
    deviceRequest('4'.repeat(64), {
      device_binding_token: generateDeviceBindingToken(),
      installation_state: 'fresh_install',
    }),
    attacker
  );

  assert.equal(attacker.statusCode, 201);
  assert.notEqual(attacker.body.user.id, victimId);

  // O token da vitima permanece intacto: nada foi sobrescrito.
  assert.ok(state.users.get(victimId).device_binding_token_hash);
});

test('normalizacao de installation_state rejeita valores arbitrarios', () => {
  assert.equal(
    normalizeInstallationState('upgraded_without_proof'),
    INSTALLATION_STATE.UPGRADED_WITHOUT_PROOF
  );
  assert.equal(
    normalizeInstallationState('existing_install'),
    INSTALLATION_STATE.EXISTING_INSTALL
  );
  // Qualquer valor invalido, ausente ou malicioso cai no comportamento antigo,
  // que e o unico seguro por omissao.
  assert.equal(
    normalizeInstallationState('qualquer_coisa'),
    INSTALLATION_STATE.FRESH_INSTALL
  );
  assert.equal(
    normalizeInstallationState(undefined),
    INSTALLATION_STATE.FRESH_INSTALL
  );
  assert.equal(normalizeInstallationState(42), INSTALLATION_STATE.FRESH_INSTALL);
});

test('hash do token de vinculo e deterministico e nao reversivel', () => {
  const token = generateDeviceBindingToken();
  assert.match(token, /^[a-f0-9]{64}$/);

  const hash = hashDeviceBindingToken(token);
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.equal(hashDeviceBindingToken(token), hash);
  assert.notEqual(hash, token);

  assert.throws(() => hashDeviceBindingToken('curto'), TypeError);
  assert.throws(() => hashDeviceBindingToken(null), TypeError);
});
