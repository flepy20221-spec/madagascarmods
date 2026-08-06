const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const db = require('../src/models/db');
const { authenticateToken, JWT_SECRET } = require('../src/middleware/auth');

function invokeMiddleware(token) {
  return new Promise((resolve, reject) => {
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {
      statusCode: 200,
      payload: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.payload = payload;
        resolve({ req, res: this, nextCalled: false });
        return this;
      },
    };

    authenticateToken(req, res, () => resolve({ req, res, nextCalled: true }));
    setTimeout(() => reject(new Error('middleware timeout')), 1000).unref();
  });
}

test('token antigo da conta mesclada opera na conta principal', async (t) => {
  const originalQuery = db.query;
  const sourceId = '11111111-1111-4111-8111-111111111111';
  const targetId = '22222222-2222-4222-8222-222222222222';

  db.query = async () => ({
    rows: [{
      is_banned: false,
      is_active: false,
      merged_into_user_id: targetId,
      merged_email: 'target@cashpix.local',
      merged_is_banned: false,
      merged_is_active: true,
    }],
  });
  t.after(() => { db.query = originalQuery; });

  const token = jwt.sign({ userId: sourceId, email: 'source@cashpix.local' }, JWT_SECRET);
  const result = await invokeMiddleware(token);

  assert.equal(result.nextCalled, true);
  assert.equal(result.req.user.userId, targetId);
  assert.equal(result.req.user.mergedFromUserId, sourceId);
  assert.equal(result.req.user.email, 'target@cashpix.local');
});

test('token antigo nao contorna banimento da conta principal', async (t) => {
  const originalQuery = db.query;
  const sourceId = '33333333-3333-4333-8333-333333333333';
  const targetId = '44444444-4444-4444-8444-444444444444';

  db.query = async () => ({
    rows: [{
      is_banned: false,
      is_active: false,
      merged_into_user_id: targetId,
      merged_email: 'target@cashpix.local',
      merged_is_banned: true,
      merged_is_active: true,
    }],
  });
  t.after(() => { db.query = originalQuery; });

  const token = jwt.sign({ userId: sourceId, email: 'source@cashpix.local' }, JWT_SECRET);
  const result = await invokeMiddleware(token);

  assert.equal(result.nextCalled, false);
  assert.equal(result.res.statusCode, 403);
  assert.equal(result.res.payload.code, 'BANNED');
});
