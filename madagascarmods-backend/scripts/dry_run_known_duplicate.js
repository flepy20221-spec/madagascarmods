const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { Client } = require('pg');
const { mergeUserAccounts } = require('../src/services/userMerge');

async function balance(client, userId) {
  const result = await client.query(
    'SELECT COALESCE(SUM(amount), 0)::int AS balance FROM points_ledger WHERE user_id = $1',
    [userId]
  );
  return result.rows[0].balance;
}

async function main() {
  const connectionString = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_PUBLIC_URL/DATABASE_URL ausente');

  const client = new Client({ connectionString });
  await client.connect();
  await client.query('BEGIN');

  try {
    const migration = fs.readFileSync(
      path.join(__dirname, '../migrations/008_device_aliases_and_support_codes.sql'),
      'utf8'
    );
    await client.query(migration);

    const accounts = await client.query(
      `SELECT id, email, support_code, device_account_key, app_version
         FROM users
        WHERE email IN (
          'device-4bb884b3ce517e885c7253352aeaf76a@cashpix.local',
          'device-5909b0bc5744f12e18bc4eb147cf67df@cashpix.local'
        )
        FOR UPDATE`
    );

    assert.equal(accounts.rows.length, 2, 'As duas contas do print precisam existir');
    const target = accounts.rows.find((row) => row.email.startsWith('device-4bb884'));
    const source = accounts.rows.find((row) => row.email.startsWith('device-5909'));
    assert.ok(target, 'Conta antiga principal nao encontrada');
    assert.ok(source, 'Conta nova duplicada nao encontrada');

    const admin = await client.query(
      `SELECT id FROM admin_users
        WHERE is_active = true AND role = 'super_admin'
        ORDER BY created_at ASC LIMIT 1`
    );
    assert.equal(admin.rows.length, 1, 'Super admin ativo nao encontrado');

    const targetBalanceBefore = await balance(client, target.id);
    const sourceBalanceBefore = await balance(client, source.id);

    const merged = await mergeUserAccounts({
      client,
      sourceUserId: source.id,
      targetUserId: target.id,
      adminId: admin.rows[0].id,
      reason: 'Rotacao comprovada da chave de assinatura entre 1.6.0+8 e 1.7.0+9',
      requestIp: '127.0.0.1',
      confirmSupportCode: target.support_code,
    });

    assert.equal(
      Number(merged.target.balance),
      targetBalanceBefore + sourceBalanceBefore,
      'O saldo consolidado precisa ser a soma das duas contas'
    );

    const archived = await client.query(
      `SELECT is_active, merged_into_user_id, device_id, device_account_key
         FROM users WHERE id = $1`,
      [source.id]
    );
    assert.equal(archived.rows[0].is_active, false);
    assert.equal(archived.rows[0].merged_into_user_id, target.id);
    assert.equal(archived.rows[0].device_id, null);
    assert.equal(archived.rows[0].device_account_key, null);

    const aliases = await client.query(
      `SELECT device_account_key FROM device_account_aliases
        WHERE user_id = $1
          AND device_account_key = ANY($2::varchar[])
        ORDER BY device_account_key`,
      [target.id, [target.device_account_key, source.device_account_key]]
    );
    assert.equal(aliases.rows.length, 2, 'As chaves antiga e nova precisam apontar para a principal');

    console.log(JSON.stringify({
      success: true,
      rolledBack: true,
      targetSupportCode: target.support_code,
      sourceSupportCode: source.support_code,
      targetBalanceBefore,
      sourceBalanceBefore,
      consolidatedBalance: Number(merged.target.balance),
      targetAppVersionBefore: target.app_version,
      sourceAppVersionBefore: source.app_version,
      aliasesValidated: aliases.rows.length,
    }, null, 2));
  } finally {
    await client.query('ROLLBACK');
    await client.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
