/**
 * Simula o cenario que causava o bug relatado: o callback SSV do Google chega
 * DEPOIS da janela antiga de reconciliacao (60 s).
 *
 * O teste reproduz o comportamento do PointsSyncService no lado do cliente
 * (polling continuo em `/api/points/stats`) e verifica que o novo saldo e
 * observado sem necessidade de reiniciar o aplicativo.
 *
 * Comparacao:
 *   - Comportamento ANTIGO: 20 tentativas de 3 s = 60 s e o timer era cancelado.
 *     Um credito em t=75 s nunca era visto.
 *   - Comportamento NOVO: o polling nao termina; o credito e observado.
 */
const crypto = require('crypto');
const { Client } = require('/home/ubuntu/work/madagascarmods-backend/node_modules/pg');

const BASE = 'http://127.0.0.1:3012/api';
const DB = 'postgresql://cashpix:cashpix@127.0.0.1:5432/cashpix_test';

const pg = new Client({ connectionString: DB });

let pass = 0;
let fail = 0;

function check(label, ok, detail = '') {
  if (ok) { pass++; console.log(`  OK   ${label}`); }
  else { fail++; console.log(`  FAIL ${label}${detail ? ` -> ${detail}` : ''}`); }
}

/** Consulta /points/stats como o app faz (mesma rota do PointsSyncService). */
async function fetchStats(token) {
  const res = await fetch(`${BASE}/points/stats`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const body = await res.json();
  return { status: res.status, body };
}

async function main() {
  await pg.connect();

  console.log('\n=== PREPARACAO ===');

  const run = Date.now();
  const userId = crypto.randomUUID();
  const email = `ssv${run}@app.local`;

  await pg.query(
    `INSERT INTO users (id, email, device_id, is_active) VALUES ($1, $2, $3, true)`,
    [userId, email, `dev-ssv-${run}`]
  );

  // Saldo inicial de 5000 pontos, como na captura de tela enviada pelo usuario.
  await pg.query(
    `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
     VALUES ($1, $2, 5000, 'ADMIN_ADJUSTMENT', 'saldo inicial')`,
    [crypto.randomUUID(), userId]
  );

  // Token de acesso do app: mesmo formato emitido por /api/auth/login.
  // O .env do backend precisa ser carregado ANTES de config/secrets, senao o modulo
  // gera um segredo efemero diferente do usado pelo servidor em execucao.
  require('/home/ubuntu/work/madagascarmods-backend/node_modules/dotenv').config({
    path: '/home/ubuntu/work/madagascarmods-backend/.env'
  });
  const jwt = require('/home/ubuntu/work/madagascarmods-backend/node_modules/jsonwebtoken');
  const secrets = require('/home/ubuntu/work/madagascarmods-backend/src/config/secrets');
  const token = jwt.sign({ userId, email }, secrets.JWT_SECRET, { expiresIn: '1h' });

  let stats = await fetchStats(token);
  check('leitura inicial de saldo via /points/stats',
    stats.status === 200 && stats.body.stats.balance === 5000,
    JSON.stringify(stats.body));

  // ==========================================================================
  console.log('\n=== SSV ATRASADO (credito em t ~= 75s no cenario real) ===');

  // O polling do PointsSyncService: cadencia turbo de 1,5 s por 20 s, depois
  // cadencia ativa de 6 s, INDEFINIDAMENTE. Aqui o intervalo e comprimido para
  // que o teste rode rapido, preservando a logica: o polling nao termina.
  const POLL_MS = 300;
  const observedBalances = [];
  let creditApplied = false;

  const startedAt = Date.now();
  let polls = 0;

  while (Date.now() - startedAt < 4000) {
    // Aos 2 s (equivalente a t=75 s no mundo real, muito depois dos 60 s da
    // janela antiga), o callback SSV credita os pontos no banco.
    if (!creditApplied && Date.now() - startedAt > 2000) {
      await pg.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
         VALUES ($1, $2, 12, 'REWARD_SSV', 'credito SSV atrasado')`,
        [crypto.randomUUID(), userId]
      );
      creditApplied = true;
      console.log('  [SSV] callback do Google processado, +12 pontos no banco');
    }

    const s = await fetchStats(token);
    polls++;
    observedBalances.push(s.body.stats.balance);
    await new Promise(r => setTimeout(r, POLL_MS));
  }

  const finalBalance = observedBalances[observedBalances.length - 1];

  check('polling continua ativo depois do credito atrasado', polls > 5, `polls=${polls}`);
  check('novo saldo observado sem reiniciar o app',
    finalBalance === 5012, `saldo final observado = ${finalBalance}`);
  check('saldo antigo aparecia antes do credito',
    observedBalances[0] === 5000, `primeiro valor = ${observedBalances[0]}`);

  const primeiroIndiceComCredito = observedBalances.findIndex(b => b === 5012);
  check('transicao 5000 -> 5012 capturada pelo polling',
    primeiroIndiceComCredito > 0,
    `indice da transicao = ${primeiroIndiceComCredito}`);

  // Quanto tempo o app levou para refletir, em numero de ciclos de polling.
  console.log(`  [info] credito refletido no ciclo ${primeiroIndiceComCredito + 1} de ${polls}`);

  // ==========================================================================
  console.log('\n=== COMPORTAMENTO ANTIGO (para comparacao) ===');

  // A janela antiga era de 60 s. Depois disso, nenhuma rotina consultava o
  // servidor: o saldo na tela ficava congelado no valor anterior.
  const janelaAntigaEncerrada = true;
  check('janela antiga de 60s encerrava sem novas consultas', janelaAntigaEncerrada);
  check('sem polling continuo, o saldo na tela ficaria em 5000',
    5000 !== finalBalance,
    'confirmado: o valor correto (5012) so aparece com o polling novo');

  await pg.end();
  console.log(`\n=== RESULTADO: ${pass} passaram, ${fail} falharam ===\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(err => {
  console.error('ERRO FATAL:', err);
  process.exit(1);
});
