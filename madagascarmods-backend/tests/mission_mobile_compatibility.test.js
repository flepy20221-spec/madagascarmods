const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../src/models/db');
const missionsRouter = require('../src/routes/missions');

function routeHandler(path, method) {
  const layer = missionsRouter.stack.find(
    (item) => item.route?.path === path && item.route.methods[method]
  );
  assert.ok(layer, `${method.toUpperCase()} ${path} deve existir`);
  return layer.route.stack.at(-1).handle;
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

const listMissions = routeHandler('/', 'get');
const startMission = routeHandler('/:id/start', 'post');

const manualMission = {
  id: 'manus-mission',
  title: 'Cadastre-se no Manus',
  description: 'Envie a captura para analise.',
  type: 'manus_proof',
  target_value: 1,
  reward_points: 500,
  icon: 'task_alt',
  is_daily: false,
  current_value: 0,
  is_completed: false,
  is_claimed: false,
  started_at: null,
  verification_mode: 'manual_evidence',
  action_url: 'https://cashpix-manus-proof-production.up.railway.app',
  requires_ad: false,
  cooldown_days: null,
  min_seconds_before_claim: 0,
  slug: 'manus-account-proof',
  evidence_required: true,
  minimum_external_credits: 1800,
  instructions: {},
};

test('expõe alias legado somente quando a APK deve mostrar abrir ou resgatar', async (t) => {
  const originalQuery = db.query;
  let evidence = null;

  db.query = async (sql) => {
    if (sql.includes('FROM missions m')) return { rows: [manualMission] };
    if (sql.includes('FROM mission_evidence_submissions')) {
      return { rows: evidence ? [evidence] : [] };
    }
    throw new Error(`Consulta inesperada: ${sql}`);
  };

  t.after(() => {
    db.query = originalQuery;
  });

  const notSubmitted = responseRecorder();
  await listMissions({ user: { userId: 'user-1' } }, notSubmitted);
  assert.equal(notSubmitted.body.missions[0].type, 'app_review');
  assert.equal(notSubmitted.body.missions[0].verificationMode, 'self_declared');
  assert.equal(notSubmitted.body.missions[0].actionUrl, manualMission.action_url);
  assert.equal(notSubmitted.body.missions[0].requiresAd, false);
  assert.equal(notSubmitted.body.missions[0].isCompleted, false);
  assert.equal(notSubmitted.body.missions[0].startedAt, null);

  evidence = {
    status: 'pending',
    public_protocol: 'CPM-PENDING',
    rejection_reason: null,
    submitted_at: new Date('2026-09-01T12:00:00.000Z'),
    reviewed_at: null,
  };
  const pending = responseRecorder();
  await listMissions({ user: { userId: 'user-1' } }, pending);
  assert.equal(pending.body.missions[0].type, 'manus_proof');
  assert.equal(pending.body.missions[0].verificationMode, 'manual_evidence');
  assert.equal(pending.body.missions[0].isCompleted, false);

  evidence = {
    status: 'approved',
    public_protocol: 'CPM-APPROVED',
    rejection_reason: null,
    submitted_at: new Date('2026-09-01T12:00:00.000Z'),
    reviewed_at: new Date('2026-09-01T13:00:00.000Z'),
  };
  const approved = responseRecorder();
  await listMissions({ user: { userId: 'user-1' } }, approved);
  assert.equal(approved.body.missions[0].type, 'app_review');
  assert.equal(approved.body.missions[0].verificationMode, 'self_declared');
  assert.equal(approved.body.missions[0].isCompleted, true);
  assert.equal(approved.body.missions[0].currentValue, 1);
  assert.equal(approved.body.missions[0].startedAt, '2026-09-01T13:00:00.000Z');
});

test('start da missão manual devolve o portal sem criar progresso', async (t) => {
  const originalGetClient = db.getClient;
  const calls = [];
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql.includes('SELECT * FROM missions')) return { rows: [manualMission] };
      return { rows: [] };
    },
    release() {},
  };
  db.getClient = async () => client;
  t.after(() => {
    db.getClient = originalGetClient;
  });

  const res = responseRecorder();
  await startMission(
    { user: { userId: 'user-1' }, params: { id: manualMission.id } },
    res
  );

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.actionUrl, manualMission.action_url);
  assert.equal(res.body.requiresAd, false);
  assert.equal(res.body.verificationMode, 'manual_evidence');
  assert.equal(calls.some((sql) => sql.includes('INSERT INTO mission_progress')), false);
  assert.equal(calls.at(-1), 'COMMIT');
});
