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

const createMission = routeHandler('/admin/create', 'post');
const updateMission = routeHandler('/admin/:id', 'put');

test('cria missão aceitando o formato snake_case usado pelo painel antigo', async (t) => {
  const originalQuery = db.query;
  let capturedParams;
  db.query = async (_sql, params) => {
    capturedParams = params;
    return { rows: [{ id: 'mission-1', reward_points: params[4] }] };
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const req = {
    body: {
      title: 'Assistir 5 anúncios',
      description: 'Teste',
      type: 'watch_ads',
      target_value: 5,
      reward_points: 30,
      icon: 'play_circle',
      is_active: true,
      is_daily: true,
      sort_order: 1,
    },
  };
  const res = responseRecorder();

  await createMission(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);

  // A migracao 010 acrescentou cinco parametros ao INSERT. Os valores esperados
  // abaixo das posicoes 9 a 13 sao os defaults, e a asercao existe justamente
  // para travar esses defaults: uma missao comum criada pelo painel antigo
  // precisa continuar com verificacao automatica, anuncio obrigatorio, sem
  // cooldown e sem espera. Qualquer mudanca acidental nesses padroes alteraria o
  // comportamento das missoes ja em producao, e este teste falha antes disso
  // chegar ao deploy.
  assert.deepEqual(capturedParams, [
    'Assistir 5 anúncios',
    'Teste',
    'watch_ads',
    5,
    30,
    'play_circle',
    true,
    true,
    1,
    'auto',  // verification_mode
    null,    // action_url
    true,    // requires_ad
    null,    // cooldown_days
    0,       // min_seconds_before_claim
    null,    // slug
    false,   // evidence_required
    0,       // minimum_external_credits
    '{}',    // instructions
  ]);
});

test('cria missão Manus com comprovacao manual e defaults seguros', async (t) => {
  const originalQuery = db.query;
  let capturedParams;
  db.query = async (_sql, params) => {
    capturedParams = params;
    return { rows: [{ id: 'manus-mission', reward_points: params[4] }] };
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const res = responseRecorder();
  await createMission(
    {
      body: {
        title: 'Cadastre-se no Manus',
        type: 'manus_proof',
        targetValue: 1,
        rewardPoints: 500,
        isDaily: false,
      },
    },
    res
  );

  assert.equal(res.statusCode, 200);
  assert.equal(capturedParams[4], 500);
  assert.equal(capturedParams[7], false);
  assert.equal(capturedParams[9], 'manual_evidence');
  assert.match(capturedParams[10], /^https:\/\/cashpix-manus-proof-production\.up\.railway\.app\/?$/);
  assert.equal(capturedParams[11], false);
  assert.equal(capturedParams[14], 'manus-account-proof');
  assert.equal(capturedParams[15], true);
  assert.equal(capturedParams[16], 1800);
});

test('cria missão aceitando o formato camelCase enviado pelo painel corrigido', async (t) => {
  const originalQuery = db.query;
  let capturedParams;
  db.query = async (_sql, params) => {
    capturedParams = params;
    return { rows: [{ id: 'mission-2', reward_points: params[4] }] };
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const req = {
    body: {
      title: 'Convidar 1 amigo',
      type: 'referral',
      targetValue: 1,
      rewardPoints: 300,
      isActive: true,
      isDaily: false,
      sortOrder: 5,
    },
  };
  const res = responseRecorder();

  await createMission(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(capturedParams[3], 1);
  assert.equal(capturedParams[4], 300);
  assert.equal(capturedParams[6], true);
  assert.equal(capturedParams[7], false);
  assert.equal(capturedParams[8], 5);
});

test('edita meta e recompensa e alterna status nos dois formatos', async (t) => {
  const originalQuery = db.query;
  const calls = [];
  db.query = async (_sql, params) => {
    calls.push(params);
    return { rows: [{ id: params[9] }] };
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const fullUpdate = responseRecorder();
  await updateMission(
    {
      params: { id: 'mission-3' },
      body: {
        targetValue: 15,
        rewardPoints: 90,
        isDaily: true,
      },
    },
    fullUpdate
  );

  const statusUpdate = responseRecorder();
  await updateMission(
    {
      params: { id: 'mission-3' },
      body: { is_active: false },
    },
    statusUpdate
  );

  assert.equal(fullUpdate.statusCode, 200);
  assert.equal(calls[0][3], 15);
  assert.equal(calls[0][4], 90);
  assert.equal(calls[0][7], true);
  assert.equal(calls[0][9], 'mission-3');

  assert.equal(statusUpdate.statusCode, 200);
  assert.equal(calls[1][6], false);
  assert.equal(calls[1][9], 'mission-3');
});

test('rejeita meta ou recompensa inválida antes de consultar o banco', async (t) => {
  const originalQuery = db.query;
  let queryCount = 0;
  db.query = async () => {
    queryCount += 1;
    return { rows: [] };
  };
  t.after(() => {
    db.query = originalQuery;
  });

  const res = responseRecorder();
  await updateMission(
    {
      params: { id: 'mission-4' },
      body: { target_value: 0, reward_points: -10 },
    },
    res
  );

  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /maiores que zero/);
  assert.equal(queryCount, 0);
});
