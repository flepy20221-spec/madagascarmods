'use strict';

/**
 * Testes da rota POST /api/asaas/auth-webhook (validacao de saques da Asaas).
 *
 * O modulo db e mockado via atribuicao direta no exports ANTES do carregamento
 * do router, de modo que todas as consultas SQL fiquem em memoria (sem banco
 * real). O fakeQuery e definido como funcao nomeada no escopo do modulo para
 * garantir identidade estavel.
 */
process.env.DATABASE_URL='postgres://u:p@localhost:5432/x';
const { test } = require('node:test');
const assert = require('node:assert');

// ---------------------------------------------------------------------------
// Mock do modulo db (src/models/db)
// ---------------------------------------------------------------------------
const dbModule = require('../src/models/db');
const originalQuery = dbModule.query;
const originalGetClient = dbModule.getClient;

const inserts = [];

async function fakeQuery(sql, params) {
  if (!/asaas_pending_transfers/i.test(sql)) {
    throw new Error('Consulta externa: ' + sql);
  }
  if (/INSERT/i.test(sql)) {
    inserts.push({ sql, params });
    return { rows: [], rowCount: 1 };
  }
  if (/UPDATE/i.test(sql)) {
    inserts.push({ sql, params });
    return { rows: [], rowCount: 1 };
  }
  // SELECT por transfer_id: retorna o registro mockado (default).
  const rows = mockPending ? [mockPending] : [];
  return { rows, rowCount: rows.length };
}

const fakeClient = { query: fakeQuery, release: () => {} };

// Atribuicao direta: qualquer require('../models/db') passado para o handler
// enxerga estas mesmas funcoes.
dbModule.query = fakeQuery;
dbModule.getClient = async () => fakeClient;

// ---------------------------------------------------------------------------
// Router (carregado depois do hijack)
// ---------------------------------------------------------------------------
const router = require('../src/routes/asaas_webhook');

function findHandler(path) {
  for (const layer of router.stack) {
    if (layer.route && layer.route.path === path) {
      return layer.route.stack.at(-1).handle;
    }
  }
  return null;
}

const webhookHandler = findHandler('/asaas/auth-webhook');
assert.ok(webhookHandler, 'Handler POST /asaas/auth-webhook deve existir');

let mockPending = {
  id: 1,
  transfer_id: '11111111-1111-1111-1111-111111111111',
  withdrawal_id: '22222222-2222-2222-2222-222222222222',
  value_cents: 130,
  pix_address_key: '06646281505',
  used: false,
};

function makeReqRes(body, headers = {}) {
  let statusCode;
  let responseBody;
  const res = {
    status: (s) => {
      statusCode = s;
      return res;
    },
    json: (b) => {
      responseBody = b;
      return res;
    },
  };
  const req = { body, headers, path: '/asaas/auth-webhook' };
  return {
    req,
    res,
    get: () => ({ statusCode: statusCode ?? 200, responseBody }),
  };
}

async function call(body, headers) {
  const { req, res, get } = makeReqRes(body, headers);
  await webhookHandler(req, res);
  return get();
}

const basePayload = {
  type: 'TRANSFER',
  transfer: {
    id: '11111111-1111-1111-1111-111111111111',
    status: 'PENDING',
    value: 1.3,
    operationType: 'PIX',
    pixAddressKey: '06646281505',
  },
};

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

test('aprova transferencia conhecida com valor e chave corretos', async () => {
  const out = await call(basePayload);
  assert.strictEqual(out.statusCode, 200);
  assert.strictEqual(out.responseBody.status, 'APPROVED');
  const upd = inserts.find((i) => /UPDATE/i.test(i.sql));
  assert.ok(upd, 'Deve registrar a aprovacao (UPDATE used)');
  assert.strictEqual(upd.params[0], basePayload.transfer.id);
});

test('recusa transferencia desconhecida', async () => {
  const out = await call({
    type: 'TRANSFER',
    transfer: { id: '99999999-9999-9999-9999-999999999999', value: 5.0 },
  });
  assert.strictEqual(out.statusCode, 200);
  assert.strictEqual(out.responseBody.status, 'REFUSED');
});

test('recusa payload sem type TRANSFER ou sem id', async () => {
  const out1 = await call({ type: 'PIX_RECEIVED' });
  assert.strictEqual(out1.responseBody.status, 'REFUSED');
  const out2 = await call({ type: 'TRANSFER', transfer: {} });
  assert.strictEqual(out2.responseBody.status, 'REFUSED');
  const out3 = await call({});
  assert.strictEqual(out3.responseBody.status, 'REFUSED');
});

test('recusa quando o valor diverge do registrado', async () => {
  const out = await call({
    type: 'TRANSFER',
    transfer: { id: basePayload.transfer.id, value: 9.99, pixAddressKey: '06646281505' },
  });
  assert.strictEqual(out.responseBody.status, 'REFUSED');
  assert.match(out.responseBody.refuseReason || '', /divergente|valor/i);
});

test('recusa quando a chave PIX diverge do registrado', async () => {
  const out = await call({
    type: 'TRANSFER',
    transfer: { id: basePayload.transfer.id, value: 1.3, pixAddressKey: '01234567890' },
  });
  assert.strictEqual(out.responseBody.status, 'REFUSED');
  assert.match(out.responseBody.refuseReason || '', /divergente|chave/i);
});

test('valida o token de autenticacao quando ASAAS_AUTH_TOKEN esta configurada', async () => {
  process.env.ASAAS_AUTH_TOKEN = 'token-secreto-do-teste';
  try {
    // Sem token: recusa (sem status => Asaas conta como falha)
    const out1 = await call(basePayload);
    assert.strictEqual(out1.statusCode, 200);
    assert.strictEqual(out1.responseBody.status, 'REFUSED');

    // Token errado: recusa
    const out2 = await call(basePayload, { 'asaas-access-token': 'errado' });
    assert.strictEqual(out2.responseBody.status, 'REFUSED');

    // Token correto: aprova
    const out3 = await call(basePayload, { 'asaas-access-token': 'token-secreto-do-teste' });
    assert.strictEqual(out3.responseBody.status, 'APPROVED');
  } finally {
    delete process.env.ASAAS_AUTH_TOKEN;
  }
});

test('aceita o token tanto no header normalizado quanto no original', async () => {
  process.env.ASAAS_AUTH_TOKEN = 'token2';
  try {
    const out1 = await call(basePayload, { 'asaas-access-token': 'token2' });
    assert.strictEqual(out1.responseBody.status, 'APPROVED');
    const out2 = await call(basePayload, { 'asaasaccesstoken': 'token2' });
    assert.strictEqual(out2.responseBody.status, 'APPROVED');
  } finally {
    delete process.env.ASAAS_AUTH_TOKEN;
  }
});
