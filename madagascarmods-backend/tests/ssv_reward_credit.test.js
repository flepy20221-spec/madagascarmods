/**
 * Teste de integracao do credito de recompensa via SSV.
 *
 * Este teste existe por causa de uma falha real em producao: as migracoes 003 e
 * 004 nunca eram aplicadas, porque src/migrate.js ignorava a pasta migrations/.
 * As colunas reward_events.ssv_transaction_id e reward_events.reward_session_id
 * nao existiam no banco, o INSERT da rota SSV falhava com 42703
 * undefined_column, a transacao sofria ROLLBACK e o usuario nunca recebia os
 * pontos do anuncio assistido. Como a rota responde sempre HTTP 200 para o
 * Google nao retentar, a falha era invisivel do lado do cliente.
 *
 * Aqui o INSERT real e exercido contra um PostgreSQL de verdade, sem mock, para
 * que qualquer regressao de schema seja detectada antes do deploy.
 *
 * Execucao:
 *   DATABASE_URL=postgresql://user:pass@localhost:5432/db \
 *     node --test tests/ssv_reward_credit.test.js
 */
const test = require('node:test');
const assert = require('node:assert');
const { randomUUID } = require('node:crypto');
const { Client } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

// Sem banco configurado o teste nao tem como validar schema. Falhar aqui e
// melhor do que passar vazio e dar falsa confianca no pipeline.
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is required to run the SSV integration test');
}

async function withClient(fn) {
  const client = new Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

// Cria um usuario descartavel para o teste, ja que reward_events e points_ledger
// possuem FOREIGN KEY para users(id).
async function createTestUser(client) {
  const userId = randomUUID();
  await client.query(
    `INSERT INTO users (id, email, is_active, is_banned)
     VALUES ($1, $2, true, false)`,
    [userId, `ssv-test-${userId}@example.invalid`]
  );
  return userId;
}

async function cleanupTestUser(client, userId) {
  await client.query('DELETE FROM points_ledger WHERE user_id = $1', [userId]);
  await client.query('DELETE FROM reward_events WHERE user_id = $1', [userId]);
  await client.query('DELETE FROM users WHERE id = $1', [userId]);
}

// Reproduz exatamente o INSERT executado por src/routes/ssv.js. Se o schema
// estiver incompleto, este INSERT falha com 42703 e o teste acusa.
async function insertRewardEvent(client, params) {
  const {
    eventId, userId, transactionId, rewardSessionId, points
  } = params;

  await client.query(
    `INSERT INTO reward_events
       (id, user_id, ad_type, ad_network, ad_unit_id, points_awarded,
        ssv_token, ssv_verified, ssv_transaction_id, reward_session_id, ip_address)
     VALUES ($1, $2, 'rewarded', 'admob', 'test-ad-unit', $3,
             '{}', true, $4, $5, '127.0.0.1')`,
    [eventId, userId, points, transactionId, rewardSessionId]
  );

  await client.query(
    `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
     VALUES ($1, $2, $3, 'REWARD_SSV', $4, 'Rewarded ad (SSV verified)')`,
    [randomUUID(), userId, points, eventId]
  );
}

test('reward_events possui as colunas exigidas pela rota SSV', async () => {
  await withClient(async (client) => {
    const result = await client.query(
      `SELECT column_name, data_type
         FROM information_schema.columns
        WHERE table_name = 'reward_events'
          AND column_name IN ('ssv_transaction_id', 'reward_session_id')`
    );

    const columns = new Map(result.rows.map((r) => [r.column_name, r.data_type]));

    assert.ok(
      columns.has('ssv_transaction_id'),
      'reward_events.ssv_transaction_id ausente: migracao 003 nao foi aplicada'
    );
    assert.ok(
      columns.has('reward_session_id'),
      'reward_events.reward_session_id ausente: migracao 004 nao foi aplicada'
    );
    assert.strictEqual(columns.get('reward_session_id'), 'uuid');
  });
});

test('as migracoes versionadas ficam registradas em schema_migrations', async () => {
  await withClient(async (client) => {
    const result = await client.query('SELECT filename FROM schema_migrations');
    const applied = new Set(result.rows.map((r) => r.filename));

    assert.ok(
      applied.has('003_security_hardening.sql'),
      'migracao 003 nao registrada em schema_migrations'
    );
    assert.ok(
      applied.has('004_reward_session_and_withdrawal_hardening.sql'),
      'migracao 004 nao registrada em schema_migrations'
    );
  });
});

test('callback SSV valido credita pontos no ledger', async () => {
  await withClient(async (client) => {
    const userId = await createTestUser(client);

    try {
      const eventId = randomUUID();
      const rewardSessionId = randomUUID();
      const transactionId = `TXN-${randomUUID()}`;

      await insertRewardEvent(client, {
        eventId,
        userId,
        transactionId,
        rewardSessionId,
        points: 42
      });

      const ledger = await client.query(
        `SELECT amount, transaction_type FROM points_ledger
          WHERE reference_id = $1`,
        [eventId]
      );

      assert.strictEqual(ledger.rows.length, 1, 'credito nao chegou ao ledger');
      assert.strictEqual(Number(ledger.rows[0].amount), 42);
      assert.strictEqual(ledger.rows[0].transaction_type, 'REWARD_SSV');

      const event = await client.query(
        `SELECT reward_session_id, ssv_transaction_id, ssv_verified
           FROM reward_events WHERE id = $1`,
        [eventId]
      );

      assert.strictEqual(event.rows[0].reward_session_id, rewardSessionId);
      assert.strictEqual(event.rows[0].ssv_transaction_id, transactionId);
      assert.strictEqual(event.rows[0].ssv_verified, true);
    } finally {
      await cleanupTestUser(client, userId);
    }
  });
});

test('transaction_id repetido e rejeitado com SQLSTATE 23505', async () => {
  await withClient(async (client) => {
    const userId = await createTestUser(client);

    try {
      const transactionId = `TXN-${randomUUID()}`;

      await insertRewardEvent(client, {
        eventId: randomUUID(),
        userId,
        transactionId,
        rewardSessionId: randomUUID(),
        points: 10
      });

      // O mesmo comprovante do Google reenviado nao pode gerar segundo credito.
      await assert.rejects(
        () => insertRewardEvent(client, {
          eventId: randomUUID(),
          userId,
          transactionId,
          rewardSessionId: randomUUID(),
          points: 10
        }),
        (err) => {
          assert.strictEqual(
            err.code,
            '23505',
            `esperado 23505 unique_violation, recebido ${err.code}`
          );
          return true;
        }
      );
    } finally {
      await cleanupTestUser(client, userId);
    }
  });
});

test('reward_session_id repetido e rejeitado com SQLSTATE 23505', async () => {
  await withClient(async (client) => {
    const userId = await createTestUser(client);

    try {
      const rewardSessionId = randomUUID();

      await insertRewardEvent(client, {
        eventId: randomUUID(),
        userId,
        transactionId: `TXN-${randomUUID()}`,
        rewardSessionId,
        points: 8
      });

      // Duas entregas do mesmo callback para a mesma sessao de anuncio devem
      // creditar uma unica vez.
      await assert.rejects(
        () => insertRewardEvent(client, {
          eventId: randomUUID(),
          userId,
          transactionId: `TXN-${randomUUID()}`,
          rewardSessionId,
          points: 8
        }),
        (err) => {
          assert.strictEqual(err.code, '23505');
          return true;
        }
      );
    } finally {
      await cleanupTestUser(client, userId);
    }
  });
});

test('callbacks v1 sem reward_session_id continuam sendo aceitos', async () => {
  await withClient(async (client) => {
    const userId = await createTestUser(client);

    try {
      // O indice UNIQUE de reward_session_id e parcial (WHERE NOT NULL), logo
      // APKs antigos que nao enviam sessao nao colidem entre si.
      for (let i = 0; i < 3; i += 1) {
        await insertRewardEvent(client, {
          eventId: randomUUID(),
          userId,
          transactionId: `TXN-${randomUUID()}`,
          rewardSessionId: null,
          points: 4
        });
      }

      const result = await client.query(
        'SELECT COUNT(*)::int AS total FROM reward_events WHERE user_id = $1',
        [userId]
      );

      assert.strictEqual(result.rows[0].total, 3);
    } finally {
      await cleanupTestUser(client, userId);
    }
  });
});
