const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../src/models/db');
const evidenceRouter = require('../src/routes/missionEvidence');
const { createMissionProofToken } = require('../src/utils/missionProofToken');

function finalHandler(path, method) {
  const layer = evidenceRouter.stack.find(
    (item) => item.route?.path === path && item.route.methods[method]
  );
  assert.ok(layer, `${method.toUpperCase()} ${path} deve existir`);
  return layer.route.stack.at(-1).handle;
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    set(headers) {
      this.headers = headers;
      return this;
    },
    send(body) {
      this.body = body;
      return this;
    },
  };
}

const submitEvidence = finalHandler('/submit', 'post');
const confirmSession = finalHandler('/session', 'post');
const approveEvidence = finalHandler('/admin/:id/approve', 'post');
const rejectEvidence = finalHandler('/admin/:id/reject', 'post');

test('rejeita conteudo que declara PNG mas nao possui assinatura de imagem', async () => {
  const req = {
    body: {
      email: 'usuario@cashpix.test',
      support_code: 'CP-ABCD-1234-EF56',
      mission_slug: 'manus-account-proof',
      attestation: 'true',
    },
    file: {
      mimetype: 'image/png',
      buffer: Buffer.from('nao e uma imagem'),
      size: 16,
      originalname: 'captura.png',
    },
  };
  const res = responseRecorder();

  await submitEvidence(req, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'INVALID_EVIDENCE_CONTENT');
});

test('sessao por token confirma somente o codigo de suporte e o estado da missao', async (t) => {
  const originalQuery = db.query;
  const mission = {
    id: 'mission-1',
    reward_points: 500,
    minimum_external_credits: 1800,
    target_value: 1,
  };
  db.query = async (sql, params) => {
    if (sql.includes('FROM missions')) return { rows: [mission] };
    if (sql.includes('FROM users')) {
      assert.equal(params[0], 'user-1');
      return { rows: [{ id: 'user-1', email: null, support_code: 'CP-ABCD-1234-EF56' }] };
    }
    if (sql.includes('FROM mission_evidence_submissions')) return { rows: [] };
    throw new Error(`Consulta inesperada: ${sql}`);
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const token = createMissionProofToken({ userId: 'user-1', missionId: mission.id });
  const res = responseRecorder();
  await confirmSession(
    { body: { mission_slug: 'manus-account-proof', access_token: token } },
    res
  );

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.account.supportCode, 'CP-ABCD-1234-EF56');
  assert.equal(Object.hasOwn(res.body.account, 'email'), false);
  assert.equal(res.body.mission.rewardPoints, 500);
  assert.equal(res.body.submission, null);
});

test('sessao recusa token adulterado e expirado', async (t) => {
  const originalQuery = db.query;
  db.query = async (sql) => {
    if (sql.includes('FROM missions')) {
      return {
        rows: [{
          id: 'mission-1',
          reward_points: 500,
          minimum_external_credits: 1800,
          target_value: 1,
        }],
      };
    }
    throw new Error('Token invalido nao deve consultar usuario.');
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const valid = createMissionProofToken({ userId: 'user-1', missionId: 'mission-1' });
  const tampered = `${valid.slice(0, -1)}${valid.endsWith('a') ? 'b' : 'a'}`;
  const tamperedResponse = responseRecorder();
  await confirmSession(
    { body: { mission_slug: 'manus-account-proof', access_token: tampered } },
    tamperedResponse
  );
  assert.equal(tamperedResponse.statusCode, 401);
  assert.equal(tamperedResponse.body.code, 'INVALID_PROOF_TOKEN');

  const expired = createMissionProofToken({
    userId: 'user-1',
    missionId: 'mission-1',
    now: Date.now() - 7 * 60 * 60 * 1000,
  });
  const expiredResponse = responseRecorder();
  await confirmSession(
    { body: { mission_slug: 'manus-account-proof', access_token: expired } },
    expiredResponse
  );
  assert.equal(expiredResponse.statusCode, 410);
  assert.equal(expiredResponse.body.code, 'EXPIRED_PROOF_TOKEN');
});

test('aprovar evidencia completa a missao sem creditar pontos diretamente', async (t) => {
  const originalGetClient = db.getClient;
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      if (sql.includes('SELECT s.*, m.target_value')) {
        return {
          rows: [{
            id: 'evidence-1',
            status: 'pending',
            user_id: 'user-1',
            mission_id: 'mission-1',
            target_value: 1,
          }],
        };
      }
      return { rows: [] };
    },
    release() {},
  };
  db.getClient = async () => client;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const req = {
    params: { id: 'evidence-1' },
    admin: { id: 'admin-1', role: 'super_admin' },
    ip: '127.0.0.1',
    body: {},
  };
  const res = responseRecorder();

  await approveEvidence(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.ok(queries.some((sql) => sql.includes('mission_progress')));
  assert.ok(!queries.some((sql) => sql.includes('points_ledger')));
});

test('rejeicao exige motivo antes de abrir transacao', async (t) => {
  const originalGetClient = db.getClient;
  let openedClient = false;
  db.getClient = async () => {
    openedClient = true;
    throw new Error('nao deveria abrir conexao');
  };
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const req = { params: { id: 'evidence-1' }, body: { reason: 'nao' } };
  const res = responseRecorder();

  await rejectEvidence(req, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'REJECTION_REASON_REQUIRED');
  assert.equal(openedClient, false);
});
