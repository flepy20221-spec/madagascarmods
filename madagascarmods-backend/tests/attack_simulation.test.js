/**
 * Simulacao END-TO-END dos ataques reais, via HTTP, contra o servidor rodando.
 *
 * Reproduz exatamente o que um atacante faz com HTTPCanary / Frida:
 * interceptar o trafego do app e reenviar requisicoes modificadas.
 *
 * Uso (com o servidor no ar em BASE_URL):
 *   BASE_URL=http://127.0.0.1:3999 \
 *   DATABASE_URL=postgresql://... \
 *   APP_HMAC_SECRET=... JWT_SECRET=... \
 *   node tests/attack_simulation.test.js
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const BASE = process.env.BASE_URL || 'http://127.0.0.1:3999';
const HMAC_SECRET = process.env.APP_HMAC_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });

let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    console.log(`  PASS  ${name}`);
    passed++;
  } else {
    console.log(`  FAIL  ${name}${detail ? ' -> ' + detail : ''}`);
    failed++;
  }
}

/**
 * Reproduz FIELMENTE o algoritmo de assinatura do app.
 * Referencia: madagascarmods-app/lib/services/api_service.dart, _generateSignature (linha 79):
 *   final payload = '$path|$timestamp|$nonce|$body';
 *
 * Dois detalhes que precisam bater exatamente, ou nenhuma assinatura valida e aceita:
 *   - ORDEM: path|timestamp|nonce|body (o metodo HTTP nao entra no payload)
 *   - timestamp em MILISSEGUNDOS (app usa DateTime.now().millisecondsSinceEpoch)
 * O path assinado NAO inclui o prefixo '/api'.
 */
function sign({ path, body, timestamp, nonce, secret = HMAC_SECRET }) {
  const payload = `${path}|${timestamp}|${nonce}|${body}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/** Timestamp no mesmo formato do app: milissegundos. */
function nowMs() {
  return Date.now().toString();
}

async function call({ method, apiPath, signPath, body, token, tamperBody, secret, omitHeaders }) {
  const timestamp = nowMs();
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyStr = body === undefined ? '' : JSON.stringify(body);

  // A assinatura e calculada sobre o corpo ORIGINAL; tamperBody simula o atacante
  // alterando o corpo DEPOIS de assinar (exatamente o que o HTTPCanary permite).
  const signature = sign({
    path: signPath,
    body: bodyStr,
    timestamp,
    nonce,
    secret: secret || HMAC_SECRET,
  });

  const sentBody = tamperBody !== undefined ? JSON.stringify(tamperBody) : bodyStr;

  const headers = { 'Content-Type': 'application/json' };
  if (!omitHeaders) {
    headers['X-Signature'] = signature;
    headers['X-Timestamp'] = timestamp;
    headers['X-Nonce'] = nonce;
    headers['X-Fingerprint'] = 'test_device_fingerprint_0001';
    headers['X-App-Version'] = '1.5.0+6';
    headers['X-Platform'] = 'android';
  }
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${apiPath}`, {
    method,
    headers,
    body: method === 'GET' ? undefined : sentBody,
  });

  let json = null;
  try {
    json = await res.json();
  } catch (_) {
    json = null;
  }
  return { status: res.status, body: json };
}

async function balanceOf(userId) {
  const r = await pool.query(
    'SELECT COALESCE(SUM(amount),0) AS b FROM points_ledger WHERE user_id = $1',
    [userId]
  );
  return parseInt(r.rows[0].b, 10);
}

/** Cria um usuario ativo direto no banco e devolve um JWT valido. */
async function seedUser({ points = 0 } = {}) {
  const userId = crypto.randomUUID();
  const email = `atk_${userId.slice(0, 8)}@test.local`;
  const deviceId = `dev_${userId.slice(0, 8)}`;

  await pool.query(
    `INSERT INTO users (id, email, device_id, is_active, is_banned)
     VALUES ($1, $2, $3, true, false)`,
    [userId, email, deviceId]
  );

  if (points > 0) {
    await pool.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'REWARD', 'seed')`,
      [crypto.randomUUID(), userId, points]
    );
  }

  const token = jwt.sign({ userId, email, deviceId }, JWT_SECRET, { expiresIn: '1h' });
  return { userId, email, deviceId, token };
}

// ===========================================================================
// ATAQUE 1: forjar pontos chamando /api/points/reward direto (o ataque original)
// ===========================================================================
async function attackForgePoints() {
  console.log('\n[ATAQUE 1] Forjar pontos via POST /api/points/reward (HTTPCanary)');

  const user = await seedUser();
  const before = await balanceOf(user.userId);

  // Tentativa classica: dizer que assistiu um anuncio premiado.
  const r1 = await call({
    method: 'POST',
    apiPath: '/api/points/reward',
    signPath: '/points/reward',
    body: { ad_type: 'rewarded' },
    token: user.token,
  });

  // Tentativa mais agressiva: injetar a quantidade de pontos desejada.
  const r2 = await call({
    method: 'POST',
    apiPath: '/api/points/reward',
    signPath: '/points/reward',
    body: { ad_type: 'rewarded', points: 999999, points_awarded: 999999 },
    token: user.token,
  });

  // Rajada: 20 chamadas seguidas, como um script de farm faria.
  for (let i = 0; i < 20; i++) {
    await call({
      method: 'POST',
      apiPath: '/api/points/reward',
      signPath: '/points/reward',
      body: { ad_type: 'rewarded' },
      token: user.token,
    });
  }

  const after = await balanceOf(user.userId);

  check(
    'rajada de 22 chamadas forjadas NAO credita nenhum ponto',
    after === before,
    `antes=${before} depois=${after}`
  );
  check(
    'a rota nao devolve pontos creditados',
    !r1.body || !r1.body.pointsAwarded,
    `resposta=${JSON.stringify(r1.body)}`
  );
  check(
    'injetar points=999999 no corpo nao tem efeito',
    after === before,
    `saldo=${after}`
  );
}

// ===========================================================================
// ATAQUE 2: adulterar o corpo depois de assinar (man-in-the-middle no proprio app)
// ===========================================================================
async function attackTamperBody() {
  console.log('\n[ATAQUE 2] Adulterar o corpo apos a assinatura');

  const user = await seedUser({ points: 5000 });

  const r = await call({
    method: 'POST',
    apiPath: '/api/withdrawals/request',
    signPath: '/withdrawals/request',
    body: { points_amount: 2000 },
    tamperBody: { points_amount: 5000000 }, // alterado no interceptador
    token: user.token,
  });

  check(
    'corpo adulterado e rejeitado com 401/403',
    r.status === 401 || r.status === 403,
    `status=${r.status} body=${JSON.stringify(r.body)}`
  );
}

// ===========================================================================
// ATAQUE 3: requisicao sem os headers de seguranca
// ===========================================================================
async function attackNoHeaders() {
  console.log('\n[ATAQUE 3] Requisicao sem headers de assinatura (curl cru)');

  const user = await seedUser({ points: 5000 });

  const r = await call({
    method: 'POST',
    apiPath: '/api/withdrawals/request',
    signPath: '/withdrawals/request',
    body: { points_amount: 2000 },
    token: user.token,
    omitHeaders: true,
  });

  // O middleware responde 400/INVALID_REQUEST quando faltam os headers de seguranca.
  // O que importa e que a requisicao NAO foi executada; o codigo exato e secundario.
  check(
    'saque sem assinatura e bloqueado',
    [400, 401, 403].includes(r.status),
    `status=${r.status} body=${JSON.stringify(r.body)}`
  );
}

// ===========================================================================
// ATAQUE 4: assinar com segredo proprio (atacante que nao conhece o APP_HMAC_SECRET)
// ===========================================================================
async function attackWrongSecret() {
  console.log('\n[ATAQUE 4] Assinatura com segredo proprio do atacante');

  const user = await seedUser({ points: 5000 });

  const r = await call({
    method: 'POST',
    apiPath: '/api/withdrawals/request',
    signPath: '/withdrawals/request',
    body: { points_amount: 2000 },
    token: user.token,
    secret: 'segredo_inventado_pelo_atacante',
  });

  check(
    'assinatura com segredo errado e rejeitada',
    r.status === 401 || r.status === 403,
    `status=${r.status}`
  );
}

// ===========================================================================
// ATAQUE 5: replay — capturar uma requisicao valida e reenviar
// ===========================================================================
async function attackReplay() {
  console.log('\n[ATAQUE 5] Replay de requisicao capturada');

  const user = await seedUser();

  // Monta manualmente para reenviar EXATAMENTE os mesmos headers.
  const timestamp = nowMs();
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyStr = JSON.stringify({ ad_type: 'rewarded' });
  const signature = sign({
    path: '/points/reward',
    body: bodyStr,
    timestamp,
    nonce,
  });

  const headers = {
    'Content-Type': 'application/json',
    'X-Signature': signature,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Fingerprint': 'test_device_fingerprint_0001',
    'X-App-Version': '1.5.0+6',
    'X-Platform': 'android',
    Authorization: `Bearer ${user.token}`,
  };

  const first = await fetch(`${BASE}/api/points/reward`, {
    method: 'POST',
    headers,
    body: bodyStr,
  });
  const second = await fetch(`${BASE}/api/points/reward`, {
    method: 'POST',
    headers,
    body: bodyStr,
  });

  // 409/DUPLICATE_REQUEST e a resposta correta do anti-replay por nonce.
  // A 1a chamada retorna 202 (aceita, aguardando confirmacao do Google via SSV) —
  // e importante notar que 202 NAO significa pontos creditados.
  check(
    'o reenvio identico e bloqueado por nonce ja usado (409)',
    second.status === 409,
    `1a=${first.status} 2a=${second.status}`
  );
}

// ===========================================================================
// ATAQUE 6: JWT forjado com isAdmin para assumir o painel
// ===========================================================================
async function attackForgedAdmin() {
  console.log('\n[ATAQUE 6] JWT forjado com isAdmin=true');

  // (a) Assinado com o segredo publico que estava no repositorio.
  const publicSecretToken = jwt.sign(
    { userId: crypto.randomUUID(), email: 'atk@test.local', isAdmin: true, role: 'SUPER_ADMIN' },
    'madagascarmods-secret-key-change-in-production',
    { expiresIn: '1h' }
  );

  const r1 = await fetch(`${BASE}/api/admin/withdrawals`, {
    headers: { Authorization: `Bearer ${publicSecretToken}` },
  });
  check(
    'JWT assinado com o segredo publico do repo e rejeitado',
    r1.status === 401 || r1.status === 403,
    `status=${r1.status}`
  );

  // (b) Usuario comum que injeta isAdmin no proprio token valido.
  const user = await seedUser();
  const escalated = jwt.sign(
    { userId: user.userId, email: user.email, deviceId: user.deviceId, isAdmin: true, role: 'SUPER_ADMIN' },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const r2 = await fetch(`${BASE}/api/admin/withdrawals`, {
    headers: { Authorization: `Bearer ${escalated}` },
  });
  check(
    'usuario comum com isAdmin injetado no token e barrado',
    r2.status === 401 || r2.status === 403,
    `status=${r2.status}`
  );

  // (c) Tentativa de definir saldo arbitrario com o token escalado.
  const r3 = await fetch(`${BASE}/api/admin/users/${user.userId}/points`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${escalated}` },
    body: JSON.stringify({ points: 10000000, reason: 'atk' }),
  });
  const bal = await balanceOf(user.userId);
  check(
    'ajuste manual de pontos via token escalado e barrado e o saldo nao muda',
    (r3.status === 401 || r3.status === 403) && bal === 0,
    `status=${r3.status} saldo=${bal}`
  );
}

// ===========================================================================
// ATAQUE 7: callback SSV falsificado (fingir ser o Google)
// ===========================================================================
async function attackFakeSsv() {
  console.log('\n[ATAQUE 7] Callback SSV falsificado');

  const user = await seedUser();
  const before = await balanceOf(user.userId);

  const qs = new URLSearchParams({
    ad_network: 'admob',
    ad_unit: '1234567890',
    reward_amount: '999999',
    reward_item: 'points',
    timestamp: Date.now().toString(),
    transaction_id: crypto.randomBytes(8).toString('hex'),
    user_id: user.userId,
    custom_data: user.userId,
    signature: 'ZmFrZV9zaWduYXR1cmU',
    key_id: '3335741209',
  });

  const r = await fetch(`${BASE}/api/ssv/callback?${qs.toString()}`);
  const after = await balanceOf(user.userId);

  check(
    'callback SSV com assinatura falsa nao credita pontos',
    after === before,
    `status=${r.status} antes=${before} depois=${after}`
  );
}

// ===========================================================================
// ATAQUE 8: login com e-mail de outra pessoa a partir de outro aparelho
// ===========================================================================
async function attackAccountTakeover() {
  console.log('\n[ATAQUE 8] Login na conta de outro usuario (device binding)');

  // Vitima com saldo, vinculada ao aparelho dela.
  const victim = await seedUser({ points: 8000 });

  const r = await call({
    method: 'POST',
    apiPath: '/api/auth/login',
    signPath: '/auth/login',
    body: {
      email: victim.email,
      device_id: 'aparelho_do_atacante_9999',
      device_model: 'AttackerPhone',
      app_version: '1.5.0',
    },
  });

  check(
    'login da conta com saldo a partir de outro aparelho e recusado',
    r.status === 403 || r.status === 401 || r.status === 409,
    `status=${r.status} body=${JSON.stringify(r.body)}`
  );
}

async function main() {
  if (!HMAC_SECRET || !JWT_SECRET || !process.env.DATABASE_URL) {
    console.error('Defina APP_HMAC_SECRET, JWT_SECRET e DATABASE_URL.');
    process.exit(1);
  }

  console.log('=== Simulacao de ataques end-to-end contra ' + BASE + ' ===');

  try {
    await attackForgePoints();
    await attackTamperBody();
    await attackNoHeaders();
    await attackWrongSecret();
    await attackReplay();
    await attackForgedAdmin();
    await attackFakeSsv();
    await attackAccountTakeover();
  } catch (err) {
    console.error('\nERRO inesperado:', err);
    failed++;
  }

  console.log(`\n${passed} passaram, ${failed} falharam`);
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main();
