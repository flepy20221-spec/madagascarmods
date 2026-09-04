const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

test('a exclusao segura desvincula referrals antes de remover o usuario', () => {
  const migration = read('migrations/019_null_referred_by_before_delete.sql');

  assert.match(migration, /UPDATE users[\s\S]*SET referred_by = NULL/);
  assert.match(migration, /WHERE referred_by = target_user_id/);
  assert.match(migration, /v_previous_balance > 1000/);
  assert.match(migration, /merged_into_user_id = target_user_id/);

  const unlinkPosition = migration.indexOf('UPDATE users');
  const deletePosition = migration.indexOf('DELETE FROM users WHERE id = target_user_id');
  assert.ok(unlinkPosition >= 0 && unlinkPosition < deletePosition);
});
