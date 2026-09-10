'use strict';

/**
 * Testes de regressão para a correção do bug de payment_method ausente no RETURNING
 * da rota POST /api/admin/withdrawals/:id/approve.
 *
 * Bug original: o UPDATE...RETURNING não incluía payment_method, fazendo com que
 * w.payment_method fosse undefined e isPix fosse sempre false — todo saque tentava
 * chamar faucetpay.sendPayment(), inclusive saques PIX.
 *
 * Correção: adicionado payment_method ao RETURNING.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const adminJsContent = fs.readFileSync(
  path.join(ROOT, 'src/routes/admin.js'),
  'utf8'
);

// ─── Teste 1: SQL RETURNING inclui payment_method ────────────────────────────

test('RETURNING do UPDATE /approve inclui payment_method', () => {
  // Localiza a cláusula RETURNING dentro da rota de aprovação
  const approveRouteMatch = adminJsContent.match(
    /router\.post\('\/withdrawals\/:id\/approve'[\s\S]*?RETURNING\s+([\w,\s]+)`/
  );

  assert.ok(
    approveRouteMatch,
    'Não foi possível localizar a cláusula RETURNING na rota /approve'
  );

  const returningClause = approveRouteMatch[1];
  assert.ok(
    returningClause.includes('payment_method'),
    `RETURNING não contém payment_method. Cláusula encontrada: "${returningClause.trim()}"`
  );
});

// ─── Teste 2: isPix usa w.payment_method (não hardcoded) ─────────────────────

test('isPix é derivado de w.payment_method no approve', () => {
  assert.ok(
    adminJsContent.includes("const isPix = w.payment_method === 'pix'"),
    "Expressão 'const isPix = w.payment_method === 'pix'' não encontrada na rota /approve"
  );
});

// ─── Teste 3: lógica de roteamento faucetpay vs pix está presente ─────────────

test('Rota /approve roteia corretamente entre FaucetPay e PIX', () => {
  // Verifica que o bloco if/else de roteamento existe
  assert.ok(
    adminJsContent.includes('if (isPix && pixData)'),
    "Bloco 'if (isPix && pixData)' não encontrado — roteamento PIX/FaucetPay ausente"
  );
  assert.ok(
    adminJsContent.includes('faucetpay.sendPayment('),
    "Chamada faucetpay.sendPayment() não encontrada na rota /approve"
  );
  assert.ok(
    adminJsContent.includes('asaas.sendPixPayment('),
    "Chamada asaas.sendPixPayment() não encontrada na rota /approve"
  );
});

// ─── Teste 4: simulação da lógica de roteamento com payment_method correto ───

test('Simulação: payment_method faucetpay → isPix = false → FaucetPay chamado', () => {
  // Simula o objeto retornado pelo banco APÓS a correção
  const w = {
    id: 'test-id',
    user_id: 'user-id',
    status: 'PROCESSING',
    amount: '1.00',
    points_debited: 2000,
    crypto_address: 'usuario@email.com',
    crypto_currency: 'LTC',
    payment_method: 'faucetpay',  // ← campo agora presente no RETURNING
  };

  const isPix = w.payment_method === 'pix';
  assert.equal(isPix, false, 'isPix deve ser false para payment_method=faucetpay');

  // Com isPix=false, o fluxo deve chamar faucetpay.sendPayment
  const shouldCallFaucetPay = !isPix;
  assert.equal(shouldCallFaucetPay, true, 'Deve chamar FaucetPay para saques faucetpay');
});

test('Simulação: payment_method pix → isPix = true → PIX/Asaas chamado', () => {
  const w = {
    id: 'test-id-pix',
    user_id: 'user-id',
    status: 'PROCESSING',
    amount: '1.00',
    points_debited: 2000,
    crypto_address: JSON.stringify({
      pix_key_type: 'email',
      pix_key_value: 'usuario@email.com',
      full_name: 'Usuario Teste',
      cpf: '529.982.247-25',
    }),
    crypto_currency: 'BRL',
    payment_method: 'pix',  // ← campo agora presente no RETURNING
  };

  const isPix = w.payment_method === 'pix';
  assert.equal(isPix, true, 'isPix deve ser true para payment_method=pix');

  // Com isPix=true, o fluxo deve chamar asaas.sendPixPayment
  const shouldCallAsaas = isPix;
  assert.equal(shouldCallAsaas, true, 'Deve chamar Asaas/PIX para saques pix');
});

test('Simulação: payment_method undefined (bug original) → isPix = false → FaucetPay chamado incorretamente', () => {
  // Reproduz o comportamento ANTES da correção (sem payment_method no RETURNING)
  const w = {
    id: 'test-id-bug',
    user_id: 'user-id',
    status: 'PROCESSING',
    amount: '1.00',
    points_debited: 2000,
    crypto_address: 'usuario@email.com',
    crypto_currency: 'LTC',
    // payment_method: undefined  ← campo ausente, como era antes da correção
  };

  const isPix = w.payment_method === 'pix';
  assert.equal(isPix, false, 'Com payment_method undefined, isPix é false (comportamento do bug)');
  // Este teste documenta o bug: mesmo um saque PIX seria roteado para FaucetPay
  // porque w.payment_method seria undefined sem o campo no RETURNING.
  // Após a correção, este cenário não ocorre mais em produção.
});

// ─── Teste 5: PAYMENT_UNCONFIRMED é tratado no catch ─────────────────────────

test('Rota /approve marca PAYMENT_UNCONFIRMED quando o gateway lança exceção', () => {
  assert.ok(
    adminJsContent.includes("status = 'PAYMENT_UNCONFIRMED'"),
    "Status PAYMENT_UNCONFIRMED não encontrado no tratamento de exceção da rota /approve"
  );
  assert.ok(
    adminJsContent.includes('requiresManualCheck: true'),
    "Flag requiresManualCheck não encontrada — admin não será alertado para verificar manualmente"
  );
});

// ─── Teste 6: FAUCETPAY_API_KEY ausente lança erro claro ─────────────────────

test('faucetpay.sendPayment lança erro claro quando FAUCETPAY_API_KEY está ausente', () => {
  const faucetpayContent = fs.readFileSync(
    path.join(ROOT, 'src/utils/faucetpay.js'),
    'utf8'
  );

  assert.ok(
    faucetpayContent.includes("throw new Error('FAUCETPAY_API_KEY não configurada"),
    "Verificação de FAUCETPAY_API_KEY ausente no sendPayment"
  );
});
