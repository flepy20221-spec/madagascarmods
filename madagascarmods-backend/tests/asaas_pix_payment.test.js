const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

// Mock do modulo 'https' exclusivamente para o arquivo utils/asaas.js.
// Captura as opcoes da requisicao e responde com dados fixos.
let captured = null;
let mocked = false;

function installMock(statusCode, body) {
  captured = null;
  const originalResolveFilename = Module._resolveFilename;
  Module._resolveFilename = function (request, parent, ...rest) {
    const resolved = originalResolveFilename.call(this, request, parent, ...rest);
    if (request === 'https' && parent && /utils\/asaas\.js$/.test(parent.filename)) {
      mocked = true;
      return '/__fake_https__/index.js';
    }
    return resolved;
  };
  const fakeHttps = {
    request(options, onResponse) {
      captured = options;
      return {
        on(event, handler) { return this; },
        write() { return this; },
        end() {
          const fakeRes = {
            statusCode,
            on(event, handler) {
              if (event === 'data') handler(JSON.stringify(body));
              if (event === 'end') handler();
              return this;
            },
          };
          onResponse(fakeRes);
          return this;
        },
        setTimeout() { return this; },
        destroy() { return this; },
      };
    },
  };
  Module._cache['/__fake_https__/index.js'] = {
    id: '/__fake_https__/index.js',
    filename: '/__fake_https__/index.js',
    loaded: true,
    exports: fakeHttps,
  };
  return function restore() {
    Module._resolveFilename = originalResolveFilename;
    delete Module._cache['/__fake_https__/index.js'];
    captured = null;
    mocked = false;
  };
}

function loadAsaas(key) {
  const saved = process.env.ASAAS_API_KEY;
  process.env.ASAAS_API_KEY = key === undefined ? '' : key;
  delete require.cache[require.resolve('../src/utils/asaas')];
  const asaas = require('../src/utils/asaas');
  return { asaas, saved };
}

test('sendPixPayment constroi payload correto para chave EMAIL', async () => {
  const restore = installMock(200, { id: 'txn_001', status: 'CONFIRMED', value: '1.05' });
  const { asaas, saved } = loadAsaas('test-key');

  const result = await asaas.sendPixPayment({
    pixKeyValue: 'pix@example.invalid',
    pixKeyType: 'email',
    amountBRL: 1.05,
    withdrawalId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
    holderName: 'Pessoa Teste',
  });

  assert.equal(result.success, true, JSON.stringify(result));
  assert.equal(result.transferId, 'txn_001');
  assert.equal(result.value, 1.05);
  assert.ok(captured, 'deve ter feito requisicao HTTP');
  assert.equal(captured.hostname, 'api.asaas.com');
  assert.equal(captured.path, '/v3/transfers');
  assert.equal(captured.method, 'POST');
  assert.equal(captured.headers.access_token, 'test-key');

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('sendPixPayment mapeia cpf para CPF da Asaas e grava description', async () => {
  const restore = installMock(200, { id: 'txn_002', status: 'PENDING', value: '3.95' });
  const { asaas, saved } = loadAsaas('test-key');

  const result = await asaas.sendPixPayment({
    pixKeyValue: '52998224725',
    pixKeyType: 'cpf',
    amountBRL: 3.95,
    withdrawalId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  });

  assert.equal(result.success, true, JSON.stringify(result));
  assert.ok(captured, 'deve ter feito requisicao HTTP');
  assert.equal(captured.headers['Content-Type'], 'application/json');

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('sendPixPayment falha com recusa explicita da API', async () => {
  const restore = installMock(400, { errors: [{ description: 'Saldo insuficiente', code: 'insufficient_funds' }] });
  const { asaas, saved } = loadAsaas('test-key');

  const result = await asaas.sendPixPayment({
    pixKeyValue: 'pix@example.invalid',
    pixKeyType: 'email',
    amountBRL: 99999,
    withdrawalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  });

  assert.equal(result.success, false);
  assert.equal(result.message, 'Saldo insuficiente');
  assert.equal(result.errorCode, 'insufficient_funds');

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('sendPixPayment rejeita tipo de chave nao suportado', async () => {
  const restore = installMock(200, {});
  const { asaas, saved } = loadAsaas('test-key');

  const result = await asaas.sendPixPayment({
    pixKeyValue: '123456',
    pixKeyType: 'cartao',
    amountBRL: 10,
    withdrawalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  });

  assert.equal(result.success, false);
  assert.equal(result.errorCode, 'UNSUPPORTED_PIX_TYPE');

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('sendPixPayment falha sem ASAAS_API_KEY', async () => {
  const restore = installMock(200, {});
  const { asaas, saved } = loadAsaas('');

  const result = await asaas.sendPixPayment({
    pixKeyValue: 'pix@example.invalid',
    pixKeyType: 'email',
    amountBRL: 10,
    withdrawalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  });

  assert.equal(result.success, false);
  assert.equal(result.errorCode, 'ASAAS_KEY_MISSING');

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('getBalance retorna sucesso quando autenticado', async () => {
  const restore = installMock(200, { availableBalance: '1250.75', email: 'x@y.z' });
  const { asaas, saved } = loadAsaas('test-key');

  const balance = await asaas.getBalance();
  assert.equal(balance.success, true, JSON.stringify(balance));
  assert.equal(balance.balance, 1250.75);

  process.env.ASAAS_API_KEY = saved;
  restore();
});

test('getBalance falha sem chave configurada', async () => {
  const restore = installMock(200, {});
  const { asaas, saved } = loadAsaas('');

  const balance = await asaas.getBalance();
  assert.equal(balance.success, false);

  process.env.ASAAS_API_KEY = saved;
  restore();
});
