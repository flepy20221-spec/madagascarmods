/**
 * AbandonedAccounts — limpeza automatica de contas abandonadas.
 *
 * Regra de negocio (validada com o admin do painel):
 *   - Conta entra em OBSERVACAO quando fica 15 dias sem login.
 *   - Conta e EXCLUIDA automaticamente quando completa 20 dias sem
 *     login (last_login_at) e sem cadastro recente (created_at), e sem
 *     saque pago/processando no periodo.
 *
 * Execucao: job diario as 04:00 (America/Sao_Paulo), maximo de 50
 * exclusoes por dia, com registro em audit_log (ACCOUNT_DELETED_AUTO)
 * preservando o saldo anterior, saques e lancamentos removidos.
 *
 * A exclusao usa a funcao SQL delete_user_safely (migration 013), que
 * remove os dados operacionais em ordem correta respeitando as FKs.
 */
const db = require('../models/db');

const EXCLUSION_DAYS = 20;
const MAX_PER_RUN = 50;
const EXCLUDE_IF_HAS_RECENT_WITHDRAWAL = true;

/**
 * Identifica contas elegiveis a exclusao automatica.
 *
 * Elegivel: sem login ha >= EXCLUSION_DAYS dias (ou nunca logou e criada
 * ha >= EXCLUSION_DAYS), sem saque PAID/PROCESSING, nao e alvo de merge,
 * nao banida (banidas tem processo proprio).
 */
async function findExcludable() {
  const result = await db.query(
    `SELECT u.id, u.email, u.support_code, u.created_at, u.last_login_at,
            (SELECT COALESCE(SUM(amount), 0)::float
               FROM points_ledger pl WHERE pl.user_id = u.id) AS balance
       FROM users u
      WHERE u.merged_into_user_id IS NULL
        AND u.is_banned = false
        AND NOT EXISTS (
          SELECT 1 FROM withdrawals w
           WHERE w.user_id = u.id AND w.status IN ('PAID', 'PROCESSING')
        )
        AND (u.last_login_at IS NULL
             OR u.last_login_at < NOW() - make_interval(days => $1))
        AND u.created_at < NOW() - make_interval(days => $1)
      ORDER BY COALESCE(u.last_login_at, u.created_at) ASC NULLS FIRST
      LIMIT $2`,
    [EXCLUSION_DAYS, MAX_PER_RUN],
  );
  return result.rows;
}

/**
 * Executa a exclusao automatica. Retorna resumo do que foi feito.
 */
async function run() {
  const log = { startedAt: new Date().toISOString(), excluded: [], errors: [] };
  const candidates = await findExcludable();
  for (const user of candidates) {
    try {
      const result = await db.query(
        `SELECT * FROM delete_user_safely($1)`,
        [user.id],
      );
      const { previous_balance, deleted_withdrawals, deleted_ledger_rows } = result.rows[0];
      await db.query(
        `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value)
         VALUES (NULL, 'system', $1, 'user', $2, $3)`,
        [
          'ACCOUNT_DELETED_AUTO',
          user.id,
          JSON.stringify({
            email: user.email,
            support_code: user.support_code,
            source: 'abandoned_auto',
            exclusion_days: EXCLUSION_DAYS,
            previous_balance_points: previous_balance,
            deleted_withdrawals,
            deleted_ledger_rows,
            deleted_at: new Date().toISOString(),
          }),
        ],
      );
      log.excluded.push({
        email: user.email,
        support_code: user.support_code,
        previous_balance_points: previous_balance,
      });
    } catch (error) {
      console.error(`[abandoned] Falha ao excluir ${user.email}:`, error.message || error);
      log.errors.push({ email: user.email, error: String(error.message || error) });
    }
  }
  log.finishedAt = new Date().toISOString();
  console.log(
    `[abandoned] Job concluido: ${log.excluded.length} excluidas, ${log.errors.length} erros`,
  );
  return log;
}

function scheduleJob() {
  const scheduleDailyAt = (hour, minute) => {
    const next = () => {
      const now = new Date();
      const target = new Date();
      target.setHours(hour, minute, 0, 0);
      if (target <= now) target.setDate(target.getDate() + 1);
      return target.getTime() - now.getTime();
    };
    const tick = () => {
      setTimeout(async () => {
        try {
          await run();
        } catch (error) {
          console.error('[abandoned] Job falhou:', error.message || error);
        }
        tick();
      }, next());
    };
    tick();
  };
  // 04:00 de Brasilia. O processo Railway roda em UTC; converter BRT->UTC:
  // BRT = UTC-3, entao 04:00 BRT = 07:00 UTC (mesmo durante horario de verao
  // a diferenca e no maximo 1h e o job roda diariamente de qualquer forma).
  scheduleDailyAt(7, 0);
  console.log('[abandoned] Job diario agendado (04:00 BRT / 07:00 UTC)');
}

module.exports = { run, findExcludable, scheduleJob };
