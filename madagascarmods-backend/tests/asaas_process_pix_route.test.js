const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const db = require('../src/models/db');

// ---------------------------------------------------------------------------
// Mock do modulo utils/asaas (usado pelo admin.js) para nao chamar a API real.
// ---------------------------------------------------------------------------
let asaasMockResult = { success: true, transferId: 'tx_mock_001', value: 10.5, message: 'Transferencia PIX Asaas criada: tx_mock_001' };
let asaasCalls = 0;
let asaasLastParams = null;

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  const resolved = originalResolveFilename.call(this, request, parent, ...rest);
  if (request === '../utils/asaas' && parent && /routes\/admin\.js$/.test(parent.filename)) {
    return '/__fake_asaas__/index.js';
  }
  return resolved;
};
const fakeAsaas = {
  sendPixPayment: async (params) => {
    asaasCalls += 1;
    asaasLastParams = params;
    return asaasMockResult;
  },
  getBalance: async () => ({ success: true, balance: 0 }),
};
Module._cache['/__fake_asaas__/index.js'] = {
  id: '/__fake_asaas__/index.js',
  filename: '/__fake_asaas__/index.js',
  loaded: true,
  exports: fakeAsaas,
};

// O admin.js carrega utils/asaas no topo; instalamos o hijack antes para que ele
// receba o modulo fake, e invalidamos o cache para garantir o recarregamento.
delete require.cache[require.resolve('../src/routes/admin')];
const adminRouter = require('../src/routes/admin');

function findHandler(path, method = 'post') {
  const routeLayer = adminRouter.stack.find(
    (layer) => layer.route?.path === path && layer.route.methods[method]
  );
  assert.ok(routeLayer, `Rota ${method.toUpperCase()} ${path} deve existir`);
  return routeLayer.route.stack.at(-1).handle;
}

const processPixHandler = findHandler('/withdrawals/:id/process-pix');

// ---------------------------------------------------------------------------
// Mock do banco de dados.
// ---------------------------------------------------------------------------
function makeDbMocks(overrides = {}) {
  const originalGetClient = db.getClient;
  const originalQuery = db.query;

  const withdrawal = Object.prototype.hasOwnProperty.call(overrides, 'withdrawal') ? overrides.withdrawal : {
    id: '11111111-1111-4111-8111-111111111111',
    user_id: '22222222-2222-4222-8222-222222222222',
    status: 'APPROVED',
    amount: '10.50',
    payment_method: 'pix',
    crypto_address: JSON.stringify({
      pix_account_id: '33333333-3333-4333-8333-333333333333',
      cpf: '52998224725',
      full_name: 'Pessoa Teste',
      pix_key_type: 'email',
      pix_key_value: 'pix@example.invalid',
    }),
  };

  const updates = [];
  const inserts = [];
  const fakeClient = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      if (normalized === 'BEGIN' || normalized === 'COMMIT' || normalized === 'ROLLBACK') return { rows: [] };
      if (normalized.startsWith('SELECT w.id')) return { rows: withdrawal ? [withdrawal] : [] };
      if (normalized.startsWith('UPDATE withdrawals')) {
        updates.push({ sql: normalized, params });
        if (normalized.includes("status = 'PROCESSING'")) return { rows: withdrawal ? [{ id: withdrawal.id }] : [] };
        return { rows: [] };
      }
      throw new Error(`Consulta inesperada no cliente: ${normalized}`);
    },
    release() {},
  };
  db.getClient = async () => fakeClient;
  db.query = async (sql, params = []) => {
    const normalized = String(sql).replace(/\s+/g, ' ').trim();
    if (normalized.startsWith('UPDATE withdrawals')) {
      updates.push({ sql: normalized, params });
      return { rows: [] };
    }
    if (normalized.startsWith('INSERT INTO audit_log')) {
      inserts.push({ sql: normalized, params });
      return { rows: [] };
    }
    throw new Error(`Consulta externa inesperada no teste: ${normalized}`);
  };

  return {
    updates,
    inserts,
    restore() {
      db.getClient = originalGetClient;
      db.query = originalQuery;
      updates.length = 0;
      inserts.length = 0;
    },
  };
}

function makeReqRes(id) {
  const req = {
    params: { id },
    admin: { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', email: 'admin@test.local', role: 'finance' },
    headers: { 'x-forwarded-for': '127.0.0.1' },
    socket: { remoteAddress: '127.0.0.1' },
  };
  let responseStatus = 200;
  let responseBody;
  const res = {
    status(code) {
      responseStatus = code;
      return res;
    },
    json(body) {
      responseBody = body;
      return res;
    },
  };
  return { req, res, getRes: () => ({ responseStatus, responseBody }) };
}

test('POST /process-pix paga via Asaas e marca o saque como PAID', async (t) => {
  const mocks = makeDbMocks();
  t.after(() => mocks.restore());
  asaasMockResult = { success: true, transferId: 'tx_ok', value: 10.5, message: 'ok' };
  asaasCalls = 0;
  asaasLastParams = null;

  const { req, res, getRes } = makeReqRes('11111111-1111-4111-8111-111111111111');
  await processPixHandler(req, res);
  const { responseStatus, responseBody } = getRes();

  assert.equal(responseStatus, 200, JSON.stringify(responseBody));
  assert.equal(responseBody.success, true);
  assert.equal(responseBody.status, 'completed');
  assert.equal(responseBody.transfer_id, 'tx_ok');
  assert.equal(asaasCalls, 1);
  assert.equal(asaasLastParams.pixKeyValue, 'pix@example.invalid');
  assert.equal(asaasLastParams.pixKeyType, 'email');
  assert.equal(asaasLastParams.amountBRL, 10.5);
  assert.equal(asaasLastParams.withdrawalId, '11111111-1111-4111-8111-111111111111');
  assert.equal(asaasLastParams.holderName, 'Pessoa Teste');

  const paidUpdate = mocks.updates.find((u) => u.sql.includes("status = 'PAID'"));
  assert.ok(paidUpdate, 'deve existir UPDATE para PAID');
  assert.equal(paidUpdate.params[0], 10.5);
  assert.equal(paidUpdate.params[1], 'tx_ok');

  const auditEntry = mocks.inserts.find((i) => i.sql.includes('ASAAS_PIX_PAYMENT_SUCCESS'));
  assert.ok(auditEntry, 'deve registrar auditoria do pagamento');
});

test('POST /process-pix rejeita saque que nao e PIX', async (t) => {
  const mocks = makeDbMocks({
    withdrawal: {
      id: '11111111-1111-4111-8111-111111111111',
      user_id: '22222222-2222-4222-8222-222222222222',
      status: 'APPROVED',
      amount: '5',
      payment_method: 'faucetpay',
      crypto_address: 'ltc_addr',
    },
  });
  t.after(() => mocks.restore());
  asaasCalls = 0;

  const { req, res, getRes } = makeReqRes('11111111-1111-4111-8111-111111111111');
  await processPixHandler(req, res);
  const { responseStatus, responseBody } = getRes();

  assert.equal(responseStatus, 409);
  assert.equal(responseBody.code, 'INVALID_PAYMENT_METHOD');
  assert.equal(asaasCalls, 0);
});

test('POST /process-pix volta para PENDING quando a Asaas recusa', async (t) => {
  const mocks = makeDbMocks();
  t.after(() => mocks.restore());
  asaasMockResult = { success: false, message: 'Saldo insuficiente', errorCode: 'insufficient_funds' };
  asaasCalls = 0;

  const { req, res, getRes } = makeReqRes('11111111-1111-4111-8111-111111111111');
  await processPixHandler(req, res);
  const { responseStatus, responseBody } = getRes();

  assert.equal(responseStatus, 200);
  assert.equal(responseBody.success, false);
  assert.equal(responseBody.status, 'failed');
  assert.equal(asaasCalls, 1);

  const revertUpdate = mocks.updates.find((u) => u.sql.includes("status = 'PENDING'"));
  assert.ok(revertUpdate, 'deve reverter para PENDING');

  const auditEntry = mocks.inserts.find((i) => i.sql.includes('ASAAS_PIX_PAYMENT_FAILED'));
  assert.ok(auditEntry, 'deve registrar auditoria da recusa');
});

test('POST /process-pix rejeita status invalido', async (t) => {
  const mocks = makeDbMocks({
    withdrawal: {
      id: '11111111-1111-4111-8111-111111111111',
      user_id: '22222222-2222-4222-8222-222222222222',
      status: 'PAID',
      amount: '5',
      payment_method: 'pix',
      crypto_address: '{}',
    },
  });
  t.after(() => mocks.restore());
  asaasCalls = 0;

  const { req, res, getRes } = makeReqRes('11111111-1111-4111-8111-111111111111');
  await processPixHandler(req, res);
  const { responseStatus, responseBody } = getRes();

  assert.equal(responseStatus, 409);
  assert.equal(responseBody.code, 'INVALID_STATUS');
  assert.equal(asaasCalls, 0);
});

test('POST /process-pix retorna 404 para saque inexistente', async (t) => {
  const mocks = makeDbMocks({ withdrawal: null });
  t.after(() => mocks.restore());
  asaasCalls = 0;

  const { req, res, getRes } = makeReqRes('99999999-9999-4999-8999-999999999999');
    await processPixHandler(req, res);
  const { responseStatus, responseBody } = getRes();
  assert.equal(responseStatus, 404);
  assert.equal(asaasCalls, 0);
});
