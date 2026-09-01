const test = require('node:test');
const assert = require('node:assert/strict');

const {
  TOKEN_TTL_SECONDS,
  appendProofToken,
  createMissionProofToken,
  verifyMissionProofToken,
} = require('../src/utils/missionProofToken');

const NOW = Date.parse('2026-09-01T15:00:00.000Z');

test('token identifica usuario e missao sem expor os dados na URL', () => {
  const token = createMissionProofToken({
    userId: 'user-123',
    missionId: 'mission-456',
    now: NOW,
  });
  const payload = verifyMissionProofToken(token, { now: NOW });
  const url = new URL(appendProofToken('https://portal.example/path', token));

  assert.equal(payload.userId, 'user-123');
  assert.equal(payload.missionId, 'mission-456');
  assert.equal(payload.exp - payload.iat, TOKEN_TTL_SECONDS);
  assert.equal(url.searchParams.get('access'), token);
  assert.equal(url.href.includes('user-123'), false);
  assert.equal(url.href.includes('CP-'), false);
});

test('token adulterado e token expirado sao recusados', () => {
  const token = createMissionProofToken({
    userId: 'user-123',
    missionId: 'mission-456',
    now: NOW,
  });
  const tampered = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`;

  assert.throws(
    () => verifyMissionProofToken(tampered, { now: NOW }),
    (error) => error.code === 'INVALID_PROOF_TOKEN'
  );
  assert.throws(
    () => verifyMissionProofToken(token, { now: NOW + (TOKEN_TTL_SECONDS + 1) * 1000 }),
    (error) => error.code === 'EXPIRED_PROOF_TOKEN'
  );
});
