/**
 * Testes de integracao de CONCORRENCIA contra um PostgreSQL real.
 *
 * Motivo de existirem: as falhas de duplo saque (VULN-06/07) sao condicoes de corrida.
 * Elas NAO aparecem em leitura de codigo nem em teste sequencial — so se manifestam quando
 * duas requisicoes chegam ao mesmo tempo e leem o estado antes de qualquer escrita.
 *
 * Cada teste roda duas vezes:
 *   1) SEM a trava (reproduz o comportamento vulneravel original) -> deve FALHAR/duplicar
 *   2) COM a trava (comportamento corrigido)                      -> deve SERIALIZAR
 * Demonstrar a falha antes da correcao e o que prova que a correcao tem efeito real.
 *
 * Uso:
 *   DATABASE_URL=postgresql://postgres:testpass@127.0.0.1:5432/cashpix_test \
 *   node tests/concurrency.test.js
 */
const { Pool } = require('pg');
const crypto = require('crypto');

const WITHDRAWAL_LOCK_NAMESPACE = 8471; // mesmo valor de withdrawals.js e pix_withdrawals.js

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 12,
});

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

function uuid() {
  return crypto.randomUUID();
}

/** Cria um usuario com saldo e um destino de saque aprovado. */
async function seedUser(points) {
  const userId = uuid();
  const email = `t_${userId.slice(0, 8)}@test.local`;

  await pool.query(
    `INSERT INTO users (id, email, device_id, is_active, is_banned)
     VALUES ($1, $2, $3, true, false)`,
    [userId, email, `dev_${userId.slice(0, 8)}`]
  );

  await pool.query(
    `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
     VALUES ($1, $2, $3, 'REWARD', 'seed')`,
    [uuid(), userId, points]
  );

  const destId = uuid();
  await pool.query(
    `INSERT INTO payout_destinations (id, user_id, type, value_encrypted, value_masked, value_hash, status, is_active)
     VALUES ($1, $2, 'FAUCETPAY_EMAIL', 'enc', 'a***@b.com', $3, 'APPROVED', true)`,
    [destId, userId, crypto.randomBytes(16).toString('hex')]
  );

  return { userId, destId };
}

async function balanceOf(userId) {
  const r = await pool.query(
    'SELECT COALESCE(SUM(amount),0) AS b FROM points_ledger WHERE user_id = $1',
    [userId]
  );
  return parseInt(r.rows[0].b, 10);
}

/**
 * Reproduz fielmente a sequencia de POST /api/withdrawals/request.
 * `useLock` alterna entre o codigo vulneravel e o corrigido.
 */
async function requestWithdrawal({ userId, destId, useLock, delayMs = 60 }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (useLock) {
      await client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [
        WITHDRAWAL_LOCK_NAMESPACE,
        userId,
      ]);
    }

    const balRes = await client.query(
      'SELECT COALESCE(SUM(amount),0) AS b FROM points_ledger WHERE user_id = $1',
      [userId]
    );
    const balance = parseInt(balRes.rows[0].b, 10);

    const pendRes = await client.query(
      "SELECT id FROM withdrawals WHERE user_id = $1 AND status IN ('PENDING','PROCESSING')",
      [userId]
    );

    // Atraso deliberado: amplia a janela de corrida para torna-la deterministica no teste.
    // Sem isso, a corrida existe mas raramente se materializa em uma unica execucao.
    await new Promise((r) => setTimeout(r, delayMs));

    if (balance < 2000) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'INSUFFICIENT_BALANCE' };
    }
    if (pendRes.rows.length > 0) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'PENDING_WITHDRAWAL_EXISTS' };
    }

    const pointsToDebit = balance;
    const reservationId = uuid();
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'WITHDRAWAL_RESERVE', 'Reserva para saque')`,
      [reservationId, userId, -pointsToDebit]
    );

    const withdrawalId = uuid();
    await client.query(
      `INSERT INTO withdrawals (id, user_id, payout_destination_id, amount, points_debited,
        payment_method, crypto_address, crypto_currency, status, idempotency_key, ledger_reservation_id, created_at)
       VALUES ($1,$2,$3,$4,$5,'faucetpay','a@b.com','LTC','PENDING',$6,$7,NOW())`,
      [withdrawalId, userId, destId, pointsToDebit / 2000, pointsToDebit, uuid(), reservationId]
    );

    await client.query('COMMIT');
    return { ok: true, withdrawalId, pointsToDebit };
  } catch (err) {
    await client.query('ROLLBACK');
    return { ok: false, reason: err.code || err.message };
  } finally {
    client.release();
  }
}

/**
 * Reproduz o approve do admin: transicao de status + envio de pagamento.
 * `atomic` alterna entre ler-depois-escrever (vulneravel) e
 * UPDATE ... WHERE status='PENDING' RETURNING (corrigido).
 */
async function approveWithdrawal({ withdrawalId, atomic, onPay, delayMs = 60 }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (atomic) {
      const upd = await client.query(
        `UPDATE withdrawals SET status = 'PROCESSING', updated_at = NOW()
          WHERE id = $1 AND status = 'PENDING'
        RETURNING id, points_debited`,
        [withdrawalId]
      );
      if (upd.rows.length === 0) {
        await client.query('ROLLBACK');
        return { paid: false, reason: 'NOT_PENDING' };
      }
      await client.query('COMMIT');
    } else {
      const sel = await client.query('SELECT id, status FROM withdrawals WHERE id = $1', [
        withdrawalId,
      ]);
      await new Promise((r) => setTimeout(r, delayMs));
      if (sel.rows[0].status !== 'PENDING') {
        await client.query('ROLLBACK');
        return { paid: false, reason: 'NOT_PENDING' };
      }
      await client.query("UPDATE withdrawals SET status = 'PROCESSING' WHERE id = $1", [
        withdrawalId,
      ]);
      await client.query('COMMIT');
    }

    // Ponto sem volta: aqui sairia LTC de verdade da carteira FaucetPay.
    await onPay();
    return { paid: true };
  } catch (err) {
    await client.query('ROLLBACK');
    return { paid: false, reason: err.code || err.message };
  } finally {
    client.release();
  }
}

async function testDoubleWithdrawal() {
  console.log('\n[VULN-06] Duplo saque simultaneo (mesmo usuario, chaves diferentes)');

  // --- SEM trava: deve reproduzir a falha ---
  {
    const { userId, destId } = await seedUser(5000);
    const results = await Promise.all([
      requestWithdrawal({ userId, destId, useLock: false }),
      requestWithdrawal({ userId, destId, useLock: false }),
    ]);
    const okCount = results.filter((r) => r.ok).length;
    const finalBalance = await balanceOf(userId);

    check(
      'SEM trava: a falha original e reproduzida (2 saques aceitos)',
      okCount === 2,
      `aceitos=${okCount}`
    );
    check(
      'SEM trava: saldo fica NEGATIVO (prejuizo real)',
      finalBalance < 0,
      `saldo=${finalBalance}`
    );
  }

  // --- COM trava: comportamento corrigido ---
  {
    const { userId, destId } = await seedUser(5000);
    const results = await Promise.all([
      requestWithdrawal({ userId, destId, useLock: true }),
      requestWithdrawal({ userId, destId, useLock: true }),
    ]);
    const okCount = results.filter((r) => r.ok).length;
    const finalBalance = await balanceOf(userId);
    const blocked = results.find((r) => !r.ok);

    check(
      'COM trava: apenas 1 saque e aceito',
      okCount === 1,
      `aceitos=${okCount}`
    );
    // A recusa pode vir por qualquer uma das duas barreiras, dependendo de qual consulta a
    // segunda transacao executa primeiro apos adquirir o lock: ela passa a enxergar tanto a
    // reserva negativa no ledger (saldo zerado) quanto o saque PENDING criado pela primeira.
    // Ambos os motivos representam o bloqueio correto; exigir um deles especificamente
    // tornaria o teste fragil sem ganho de garantia.
    check(
      'COM trava: o segundo e recusado (saldo reservado ou saque pendente)',
      blocked &&
        ['PENDING_WITHDRAWAL_EXISTS', 'INSUFFICIENT_BALANCE'].includes(blocked.reason),
      `motivo=${blocked && blocked.reason}`
    );
    check(
      'COM trava: saldo nunca fica negativo',
      finalBalance >= 0,
      `saldo=${finalBalance}`
    );
  }

  // --- Rajada de 5 requisicoes simultaneas ---
  {
    const { userId, destId } = await seedUser(10000);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => requestWithdrawal({ userId, destId, useLock: true }))
    );
    const okCount = results.filter((r) => r.ok).length;
    const finalBalance = await balanceOf(userId);
    check('COM trava: rajada de 5 gera exatamente 1 saque', okCount === 1, `aceitos=${okCount}`);
    check('COM trava: saldo final consistente apos rajada', finalBalance >= 0, `saldo=${finalBalance}`);
  }
}

async function testDoublePayment() {
  console.log('\n[VULN-07] Duplo pagamento LTC (dois cliques em Aprovar)');

  // --- SEM transicao atomica ---
  {
    const { userId, destId } = await seedUser(5000);
    const w = await requestWithdrawal({ userId, destId, useLock: true });
    let payCount = 0;
    await Promise.all([
      approveWithdrawal({ withdrawalId: w.withdrawalId, atomic: false, onPay: async () => { payCount++; } }),
      approveWithdrawal({ withdrawalId: w.withdrawalId, atomic: false, onPay: async () => { payCount++; } }),
    ]);
    check(
      'SEM transicao atomica: a falha original e reproduzida (LTC enviado 2x)',
      payCount === 2,
      `envios=${payCount}`
    );
  }

  // --- COM transicao atomica ---
  {
    const { userId, destId } = await seedUser(5000);
    const w = await requestWithdrawal({ userId, destId, useLock: true });
    let payCount = 0;
    const res = await Promise.all([
      approveWithdrawal({ withdrawalId: w.withdrawalId, atomic: true, onPay: async () => { payCount++; } }),
      approveWithdrawal({ withdrawalId: w.withdrawalId, atomic: true, onPay: async () => { payCount++; } }),
    ]);
    check('COM transicao atomica: LTC enviado exatamente 1x', payCount === 1, `envios=${payCount}`);
    check(
      'COM transicao atomica: a 2a tentativa e recusada por status',
      res.filter((r) => !r.paid && r.reason === 'NOT_PENDING').length === 1
    );
  }

  // --- Rajada de 5 cliques ---
  {
    const { userId, destId } = await seedUser(5000);
    const w = await requestWithdrawal({ userId, destId, useLock: true });
    let payCount = 0;
    await Promise.all(
      Array.from({ length: 5 }, () =>
        approveWithdrawal({ withdrawalId: w.withdrawalId, atomic: true, onPay: async () => { payCount++; } })
      )
    );
    check('COM transicao atomica: 5 cliques => 1 unico envio', payCount === 1, `envios=${payCount}`);
  }
}

async function testNonceReplay() {
  console.log('\n[VULN-02] Anti-replay de nonce sob concorrencia');

  const nonce = crypto.randomBytes(16).toString('hex');

  // Mesma estrategia do middleware: INSERT ... ON CONFLICT DO NOTHING RETURNING.
  // Se o RETURNING vier vazio, o nonce ja existia -> replay.
  async function consumeNonce() {
    const r = await pool.query(
      `INSERT INTO request_nonces (nonce, user_id, path)
       VALUES ($1, NULL, '/points/reward')
       ON CONFLICT (nonce) DO NOTHING
       RETURNING nonce`,
      [nonce]
    );
    return r.rows.length > 0;
  }

  const results = await Promise.all(Array.from({ length: 6 }, () => consumeNonce()));
  const accepted = results.filter(Boolean).length;
  check(
    'nonce identico enviado 6x em paralelo e aceito apenas 1x',
    accepted === 1,
    `aceitos=${accepted}`
  );
}

async function testSsvTransactionUnique() {
  console.log('\n[VULN-01] Anti-replay do transaction_id do SSV');

  const { userId } = await seedUser(0);
  const txId = `tx_${crypto.randomBytes(8).toString('hex')}`;

  async function creditSsv() {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const eventId = uuid();
      await client.query(
        `INSERT INTO reward_events (id, user_id, ad_type, ad_network, points_awarded, ssv_verified, ssv_transaction_id)
         VALUES ($1, $2, 'rewarded', 'admob', 10, true, $3)`,
        [eventId, userId, txId]
      );
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, 10, 'REWARD_SSV', $3, 'ssv')`,
        [uuid(), userId, eventId]
      );
      await client.query('COMMIT');
      return true;
    } catch (err) {
      await client.query('ROLLBACK');
      return false; // 23505 = unique_violation
    } finally {
      client.release();
    }
  }

  const results = await Promise.all(Array.from({ length: 5 }, () => creditSsv()));
  const accepted = results.filter(Boolean).length;
  const finalBalance = await balanceOf(userId);

  check(
    'mesmo transaction_id do Google credita apenas 1x (5 tentativas paralelas)',
    accepted === 1,
    `aceitos=${accepted}`
  );
  check(
    'saldo reflete um unico credito de 10 pontos',
    finalBalance === 10,
    `saldo=${finalBalance}`
  );
}

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL nao definida.');
    process.exit(1);
  }

  console.log('=== Testes de integracao: concorrencia e anti-replay ===');

  try {
    await testDoubleWithdrawal();
    await testDoublePayment();
    await testNonceReplay();
    await testSsvTransactionUnique();
  } catch (err) {
    console.error('\nERRO inesperado no teste:', err);
    failed++;
  }

  console.log(`\n${passed} passaram, ${failed} falharam`);
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main();
