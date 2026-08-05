const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../src/models/db');
const pixWithdrawalRouter = require('../src/routes/pix_withdrawals');

function findRequestHandler() {
  const routeLayer = pixWithdrawalRouter.stack.find(
    (layer) => layer.route?.path === '/request' && layer.route.methods.post
  );

  assert.ok(routeLayer, 'POST /request PIX deve existir');
  return routeLayer.route.stack.at(-1).handle;
}

test('saque PIX grava payout_destination_id NULL e preserva snapshot da conta PIX', async (t) => {
  const originalGetClient = db.getClient;
  const originalQuery = db.query;

  const pixAccountId = '22222222-2222-4222-8222-222222222222';
  const userId = '11111111-1111-4111-8111-111111111111';
  let withdrawalInsert = null;
  let committed = false;

  const fakeClient = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();

      if (normalized === 'BEGIN') return { rows: [] };
      if (normalized === 'COMMIT') {
        committed = true;
        return { rows: [] };
      }
      if (normalized === 'ROLLBACK') return { rows: [] };
      if (normalized.startsWith('SELECT pg_advisory_xact_lock')) return { rows: [] };
      if (normalized.startsWith('SELECT 1 FROM withdrawals WHERE idempotency_key')) return { rows: [] };
      if (normalized.includes('FROM system_config')) {
        return {
          rows: [
            { key: 'withdrawal_min_points', value: '2000' },
            { key: 'points_per_real', value: '2000' },
            { key: 'pix_withdrawal_enabled', value: 'true' },
          ],
        };
      }
      if (normalized.includes('SUM(amount)') && normalized.includes('points_ledger')) {
        return { rows: [{ balance: '2000' }] };
      }
      if (normalized.includes('COUNT(*) as ssv_count')) {
        return { rows: [{ ssv_count: '1' }] };
      }
      if (normalized.includes('COUNT(*) as admin_count')) {
        return { rows: [{ admin_count: '0' }] };
      }
      if (normalized.includes('FROM pix_accounts')) {
        return {
          rows: [
            {
              id: pixAccountId,
              cpf: '52998224725',
              full_name: 'Pessoa Teste',
              pix_key_type: 'email',
              pix_key_value: 'pix@example.invalid',
              pix_key_masked: 'p***@example.invalid',
            },
          ],
        };
      }
      if (normalized.includes("status IN ('PENDING', 'PROCESSING')")) {
        return { rows: [] };
      }
      if (normalized.startsWith('INSERT INTO points_ledger')) return { rows: [] };
      if (normalized.startsWith('INSERT INTO withdrawals')) {
        withdrawalInsert = { sql: normalized, params };
        return { rows: [] };
      }
      if (normalized.startsWith('INSERT INTO audit_log')) return { rows: [] };

      throw new Error(`Consulta inesperada no teste PIX: ${normalized}`);
    },
    release() {},
  };

  db.getClient = async () => fakeClient;
  db.query = async (sql) => {
    const normalized = String(sql).replace(/\s+/g, ' ').trim();
    if (normalized.startsWith('SELECT 1 FROM withdrawals WHERE idempotency_key')) {
      return { rows: [] };
    }
    throw new Error(`Consulta externa inesperada no teste PIX: ${normalized}`);
  };

  t.after(async () => {
    db.getClient = originalGetClient;
    db.query = originalQuery;
    await db.pool.end();
  });

  const req = {
    body: {
      idempotency_key: '33333333-3333-4333-8333-333333333333',
      points_amount: 2000,
    },
    user: { userId },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  };

  let responseStatus = 200;
  let responseBody;
  const res = {
    status(code) {
      responseStatus = code;
      return this;
    },
    json(body) {
      responseBody = body;
      return this;
    },
  };

  await findRequestHandler()(req, res);

  assert.equal(responseStatus, 201);
  assert.equal(responseBody?.success, true);
  assert.equal(committed, true);
  assert.ok(withdrawalInsert, 'INSERT do saque PIX deve ser executado');
  assert.match(withdrawalInsert.sql, /VALUES \(\$1, \$2, NULL, \$3, \$4, 'pix'/);
  assert.equal(withdrawalInsert.params.length, 7);
  assert.equal(withdrawalInsert.params[1], userId);
  assert.equal(withdrawalInsert.params[2], 1);
  assert.equal(withdrawalInsert.params[3], 2000);

  const pixSnapshot = JSON.parse(withdrawalInsert.params[4]);
  assert.equal(pixSnapshot.pix_account_id, pixAccountId);
  assert.equal(pixSnapshot.pix_key_value, 'pix@example.invalid');
  assert.notEqual(withdrawalInsert.params[2], pixAccountId);
});
