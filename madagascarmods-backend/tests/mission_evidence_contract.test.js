const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../src/models/db');
const evidenceRouter = require('../src/routes/missionEvidence');

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
