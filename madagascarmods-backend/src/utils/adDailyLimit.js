'use strict';

/**
 * Utilitario do limite diario de ads rewarded (reset a meia-noite, horario de Brasilia).
 *
 * O reset passa a ser por dia de calendario no fuso America/Sao_Paulo (UTC-3),
 * alinhado com o reset das missoes diarias (que usam DATE(created_at) = hoje).
 *
 * A coluna created_at e timestamptz (UTC no banco). A contagem compara o dia do
 * horario local de Brasilia do evento com o dia atual de Brasilia.
 */

const db = require('../models/db');

/**
 * Data 'hoje' em Brasilia no formato 'YYYY-MM-DD' (ex.: 2026-08-17).
 * Calculada no servidor para garantir o mesmo ponto de corte (00:00 BR)
 * para todos os usuarios.
 */
function todayBr() {
  // NOW() do Postgres em UTC convertido para Brasilia.
  const d = new Date();
  // Brasilia = UTC-3 (sem horario de verao desde 2019)
  const br = new Date(d.getTime() - 3 * 3600 * 1000);
  return br.toISOString().split('T')[0];
}

/**
 * Query SQL que conta os ads rewarded verificados do dia (Brasilia).
 *
 * O dia e delimitado por 00:00 BR do dia `$2` (inclusive) ate 00:00 BR do dia
 * seguinte (exclusive). Brasilia e UTC-3 fixo (sem horario de verao).
 */
const DAILY_COUNT_SQL = `
  SELECT COUNT(*) AS count
    FROM reward_events
   WHERE user_id = $1
     AND ad_type = 'rewarded'
     AND ssv_verified = true
     AND created_at >= ($2 || ' 00:00:00-03')::timestamptz
     AND created_at <  (($2 || ' 00:00:00-03')::timestamptz + INTERVAL '1 day')
`;

/**
 * Conta os ads rewarded verificados do usuario no dia atual (Brasilia).
 */
async function countDailyAds(userId, queryable = db) {
  const result = await queryable.query(DAILY_COUNT_SQL, [userId, todayBr()]);
  return parseInt(result.rows[0].count, 10);
}

/**
 * Consulta o limite diário configurado em system_config.
 *
 * Durante versões anteriores foram usadas duas chaves diferentes. A leitura
 * aceita ambas para que o limite aplicado pelo SSV seja sempre o mesmo limite
 * exibido pela API pública. O valor de produção aprovado é 200.
 */
async function getDailyLimit() {
  const DAILY_LIMIT_DEFAULT = 200;
  try {
    const limitConfig = await db.query(
      `SELECT key, value
         FROM system_config
        WHERE key IN ('dailyAdLimitRewarded', 'daily_ad_limit_rewarded')
        ORDER BY CASE WHEN key = 'daily_ad_limit_rewarded' THEN 0 ELSE 1 END`
    );
    for (const row of limitConfig.rows) {
      const parsed = Number(JSON.parse(row.value));
      if (Number.isFinite(parsed) && parsed > 0) return parsed;
    }
  } catch (_) { /* usa o default */ }
  return DAILY_LIMIT_DEFAULT;
}

module.exports = { todayBr, countDailyAds, getDailyLimit, DAILY_COUNT_SQL };
