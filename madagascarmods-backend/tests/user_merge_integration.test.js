const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

const db = require('../src/models/db');
const { mergeUserAccounts } = require('../src/services/userMerge');

const hasDatabase = Boolean(process.env.DATABASE_URL);

test('reconcilia conta duplicada sem perder saldo ou historico', { skip: !hasDatabase }, async (t) => {
  const client = await db.getClient();
  const adminId = randomUUID();
  const targetId = randomUUID();
  const sourceId = randomUUID();
  const missionId = randomUUID();
  const targetKey = 'a'.repeat(64);
  const sourceKey = 'b'.repeat(64);

  t.after(async () => {
    client.release();
    await db.pool.end();
  });

  await client.query('BEGIN');
  try {
    await client.query(
      `INSERT INTO admin_users (id, email, password_hash, name, role)
       VALUES ($1, $2, 'test-hash', 'Merge Test', 'super_admin')`,
      [adminId, `merge-admin-${adminId}@test.local`]
    );

    const target = await client.query(
      `INSERT INTO users (
         id, email, device_id, device_account_key, device_model,
         ip_address, app_version, support_label, last_login_at
       ) VALUES ($1, $2, $3, $3, 'Moto G60', '127.0.0.1', '1.6.0+8', 'Conta principal', NOW() - INTERVAL '1 day')
       RETURNING support_code`,
      [targetId, `target-${targetId}@test.local`, targetKey]
    );

    await client.query(
      `INSERT INTO users (
         id, email, device_id, device_account_key, device_model,
         ip_address, app_version, last_login_at
       ) VALUES ($1, $2, $3, $3, 'Moto G60', '127.0.0.1', '1.7.1+10', NOW())`,
      [sourceId, `source-${sourceId}@test.local`, sourceKey]
    );

    await client.query(
      `INSERT INTO device_account_aliases (device_account_key, user_id, source)
       VALUES ($1, $2, 'test_target'), ($3, $4, 'test_source')`,
      [targetKey, targetId, sourceKey, sourceId]
    );

    await client.query(
      `INSERT INTO points_ledger (user_id, amount, transaction_type, description)
       VALUES ($1, 100, 'REWARD', 'target points'),
              ($2, 25, 'REWARD', 'source points')`,
      [targetId, sourceId]
    );

    await client.query(
      `INSERT INTO daily_checkins (user_id, checkin_date, streak_day, points_awarded)
       VALUES ($1, CURRENT_DATE, 2, 10), ($2, CURRENT_DATE, 4, 5)`,
      [targetId, sourceId]
    );

    await client.query(
      `INSERT INTO push_tokens (user_id, token, platform)
       VALUES ($1, 'same-push-token', 'android'), ($2, 'same-push-token', 'android')`,
      [targetId, sourceId]
    );

    await client.query(
      `INSERT INTO request_nonces (nonce, user_id, path)
       VALUES ($1, $2, '/points/reward')`,
      [`nonce-${sourceId}`, sourceId]
    );

    await client.query(
      `INSERT INTO missions (id, title, type, target_value, reward_points)
       VALUES ($1, 'Merge mission', 'watch_ads', 10, 20)`,
      [missionId]
    );
    await client.query(
      `INSERT INTO mission_progress (
         user_id, mission_id, current_value, is_completed, is_claimed, reset_date
       ) VALUES
         ($1, $3, 3, false, false, CURRENT_DATE),
         ($2, $3, 10, true, true, CURRENT_DATE)`,
      [targetId, sourceId, missionId]
    );

    const result = await mergeUserAccounts({
      client,
      sourceUserId: sourceId,
      targetUserId: targetId,
      adminId,
      reason: 'Rotacao comprovada da chave de assinatura Android',
      requestIp: '127.0.0.1',
      confirmSupportCode: target.rows[0].support_code,
    });

    assert.equal(result.target.id, targetId);
    assert.equal(result.target.support_code, target.rows[0].support_code);
    assert.equal(Number(result.target.balance), 125);

    const users = await client.query(
      `SELECT id, is_active, merged_into_user_id, device_id, device_account_key,
              device_model, app_version
         FROM users WHERE id = ANY($1::uuid[]) ORDER BY id`,
      [[targetId, sourceId]]
    );
    const source = users.rows.find((row) => row.id === sourceId);
    const canonical = users.rows.find((row) => row.id === targetId);
    assert.equal(source.is_active, false);
    assert.equal(source.merged_into_user_id, targetId);
    assert.equal(source.device_id, null);
    assert.equal(source.device_account_key, null);
    assert.equal(canonical.device_account_key, sourceKey);
    assert.equal(canonical.device_model, 'Moto G60');
    assert.equal(canonical.app_version, '1.7.1+10');

    const balances = await client.query(
      `SELECT user_id, COALESCE(SUM(amount), 0)::int AS balance
         FROM points_ledger
        WHERE user_id = ANY($1::uuid[])
        GROUP BY user_id`,
      [[targetId, sourceId]]
    );
    assert.deepEqual(balances.rows, [{ user_id: targetId, balance: 125 }]);

    const aliases = await client.query(
      `SELECT device_account_key, user_id FROM device_account_aliases
        WHERE device_account_key = ANY($1::varchar[]) ORDER BY device_account_key`,
      [[targetKey, sourceKey]]
    );
    assert.equal(aliases.rows.length, 2);
    assert.ok(aliases.rows.every((row) => row.user_id === targetId));

    const checkins = await client.query(
      `SELECT user_id, streak_day, points_awarded
         FROM daily_checkins WHERE checkin_date = CURRENT_DATE`,
    );
    assert.deepEqual(checkins.rows, [{ user_id: targetId, streak_day: 4, points_awarded: 15 }]);

    const progress = await client.query(
      `SELECT user_id, current_value, is_completed, is_claimed
         FROM mission_progress WHERE mission_id = $1`,
      [missionId]
    );
    assert.deepEqual(progress.rows, [{
      user_id: targetId,
      current_value: 10,
      is_completed: true,
      is_claimed: true,
    }]);

    const push = await client.query(
      `SELECT user_id, token FROM push_tokens WHERE token = 'same-push-token'`,
    );
    assert.deepEqual(push.rows, [{ user_id: targetId, token: 'same-push-token' }]);

    const nonce = await client.query(
      `SELECT user_id FROM request_nonces WHERE nonce = $1`,
      [`nonce-${sourceId}`]
    );
    assert.deepEqual(nonce.rows, [{ user_id: targetId }]);

    const audit = await client.query(
      `SELECT action, target_id FROM audit_log
        WHERE actor_id = $1 AND action = 'USER_ACCOUNTS_MERGED'`,
      [adminId]
    );
    assert.deepEqual(audit.rows, [{ action: 'USER_ACCOUNTS_MERGED', target_id: targetId }]);
  } finally {
    await client.query('ROLLBACK');
  }
});
