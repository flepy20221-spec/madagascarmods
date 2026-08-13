'use strict';
/**
 * Limpeza automatica de tokens push mortos (push token hygiene).
 *
 * PROBLEMA: o token FCM de um usuario morre quando ele desinstala/reinstala o app,
 * limpa os dados ou troca de aparelho. Tokens mortos inflavam o contador de
 * "dispositivos ativos" do painel e geravam falhas em todos os envios em massa,
 * derrubando a taxa de entrega relatada.
 *
 * SOLUCAO (sem mexer no app):
 * 1. Job diario (03:30 de Brasilia, horario de menor uso) envia uma mensagem
 *    silenciosa de probe a cada token ativo. Respostas com codigo
 *    'messaging/registration-token-not-registered' ou
 *    'messaging/invalid-registration-token' marcam o token como inativo.
 * 2. Tokens que falham por 'unavailable' (offline temporario) NAO sao tocados:
 *    o Google entrega quando o aparelho volta.
 * 3. Limite de seguranca: no maximo 200 tokens desativados por execucao, para
 *    evitar limpeza acidental em massa por erro de configuracao do Firebase.
 *
 * Endpoint GET /api/admin/push/coverage devolve a cobertura real: quantos
 * usuarios sao alcancaveis hoje, separando ativos, inativos e nunca registrados.
 */

const db = require('../models/db');

// Firebase Admin SDK: reutiliza a inicializacao feita por routes/push.js.
// Nao pode chamar initializeApp() de novo (erro 'default app already exists').
let firebaseAdmin = null;
function getFirebase() {
  if (firebaseAdmin) return firebaseAdmin;
  try {
    const admin = require('firebase-admin');
    // Usa o app ja inicializado pelo push.js (ou o app default do sistema)
    const apps = admin.apps || [];
    if (apps.length > 0 && apps[0].name === '[DEFAULT]') {
      firebaseAdmin = admin;
      return firebaseAdmin;
    }
    // Fallback: inicializa somente se nenhum app default existir
    const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (sa) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
      firebaseAdmin = admin;
    }
  } catch (e) {
    console.error('[PushCleanup] Erro ao obter Firebase:', e.message);
  }
  return firebaseAdmin;
}

const INVALID_CODES = new Set([
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
]);

const MAX_DEACTIVATE_PER_RUN = 200;

/**
 * Varre tokens ativos e desativa os mortos segundo o FCM.
 * @returns {Promise<{scanned: number, deactivated: number, stillValid: number, error?: string}>}
 */
async function cleanupDeadTokens() {
  const admin = getFirebase();
  if (!admin) {
    return { scanned: 0, deactivated: 0, stillValid: 0, error: 'Firebase nao configurado' };
  }

  const res = await db.query(
    `SELECT token FROM push_tokens WHERE is_active = true ORDER BY updated_at ASC`
  );
  const tokens = res.rows.map(r => r.token);
  if (tokens.length === 0) return { scanned: 0, deactivated: 0, stillValid: 0 };

  let deactivated = 0;
  let scanned = 0;
  let stillValid = 0;
  const deactivationPromises = [];

  const batchSize = 500;
  for (let i = 0; i < tokens.length && deactivated < MAX_DEACTIVATE_PER_RUN; i += batchSize) {
    const batch = tokens.slice(i, i + batchSize);
    try {
      // Mensagem de probe: dados vazios, sem notificacao visivel ao usuario.
      const response = await admin.messaging().sendEachForMulticast({
        data: { type: 'token_probe' },
        tokens: batch,
      });
      response.responses.forEach((resp, idx) => {
        scanned++;
        if (!resp.success && INVALID_CODES.has(resp.error?.code)) {
          if (deactivated < MAX_DEACTIVATE_PER_RUN) {
            deactivated++;
            deactivationPromises.push(
              db.query(`UPDATE push_tokens SET is_active = false WHERE token = $1`, [batch[idx]])
            );
          }
        } else {
          stillValid++;
        }
      });
    } catch (fcmError) {
      console.error('[PushCleanup] Erro no lote de probe:', fcmError?.message || fcmError);
      // Lote com erro de rede: nao desativar nada, tentar na proxima execucao
      scanned += batch.length;
      stillValid += batch.length;
    }
  }

  if (deactivationPromises.length > 0) {
    await Promise.allSettled(deactivationPromises);
  }
  return { scanned, deactivated, stillValid };
}

/**
 * Estatisticas de cobertura de push.
 */
async function getCoverageStats() {
  const [totalUsers, everRegistered, activeUsers, inactiveDistinct] = await Promise.all([
    db.query(`SELECT COUNT(*)::int AS n FROM users`),
    db.query(`SELECT COUNT(DISTINCT user_id)::int AS n FROM push_tokens`),
    db.query(`SELECT COUNT(DISTINCT user_id)::int AS n FROM push_tokens WHERE is_active = true`),
    db.query(`SELECT COUNT(DISTINCT user_id)::int AS n FROM push_tokens WHERE is_active = false`),
  ]);
  const totalUsersN = totalUsers.rows[0].n;
  const neverRegistered = totalUsersN - everRegistered.rows[0].n;
  return {
    totalUsers: totalUsersN,
    reachable: activeUsers.rows[0].n,
    unreachableInactive: inactiveDistinct.rows[0].n,
    neverRegistered,
    coveragePercent: totalUsersN > 0
      ? Math.round((activeUsers.rows[0].n / totalUsersN) * 10000) / 100
      : 0,
  };
}

/**
 * Grava o resultado de uma limpeza em push_token_cleanup_log.
 */
async function logCleanupResult(result) {
  try {
    await db.query(
      `INSERT INTO push_token_cleanup_log (scanned, deactivated, still_valid)
       VALUES ($1, $2, $3)`,
      [result.scanned, result.deactivated, result.stillValid]
    ).catch(async () => {
      await db.query(`
        CREATE TABLE IF NOT EXISTS push_token_cleanup_log (
          id SERIAL PRIMARY KEY,
          scanned INT NOT NULL DEFAULT 0,
          deactivated INT NOT NULL DEFAULT 0,
          still_valid INT NOT NULL DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await db.query(
        `INSERT INTO push_token_cleanup_log (scanned, deactivated, still_valid)
         VALUES ($1, $2, $3)`,
        [result.scanned, result.deactivated, result.stillValid]
      );
    });
  } catch (e) {
    console.error('[PushCleanup] Falha ao gravar log da limpeza:', e.message);
  }
}

/**
 * Job diario: executa a limpeza e grava o resultado em push_token_cleanup_log.
 */
async function runDailyCleanupJob() {
  try {
    const result = await cleanupDeadTokens();
    await logCleanupResult(result);
    console.log(
      `[PushCleanup] Job diario: ${result.scanned} verificados, ${result.deactivated} mortos desativados, ${result.stillValid} validos`
    );
    return result;
  } catch (error) {
    console.error('[PushCleanup] Job diario falhou:', error.message);
    return { scanned: 0, deactivated: 0, stillValid: 0, error: error.message };
  }
}

/**
 * Inicia o job diario as 03:30 de Brasilia (UTC-3).
 * Aligna ao primeiro :00 do minuto e roda a cada 60s, executando apenas
 * quando o relogio de Brasilia marca 03:30.
 */
function startDailyJob() {
  function check() {
    const now = new Date();
    const brasilia = new Date(now.getTime() + (now.getTimezoneOffset() - 180) * 60000);
    if (brasilia.getHours() === 3 && brasilia.getMinutes() === 30) {
      runDailyCleanupJob();
    }
  }
  const now = new Date();
  const msToNextSecond = 1000 - now.getMilliseconds();
  setTimeout(() => {
    check();
    setInterval(check, 60 * 1000);
  }, msToNextSecond);
  console.log('[PushCleanup] Job diario de limpeza de tokens agendado (03:30 Brasilia).');
}

module.exports = { cleanupDeadTokens, getCoverageStats, logCleanupResult, runDailyCleanupJob, startDailyJob };
