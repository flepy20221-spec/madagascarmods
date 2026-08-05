const MERGEABLE_USER_TABLES = [
  'points_ledger',
  'reward_events',
  'withdrawals',
  'payout_destinations',
  'pix_accounts',
  'request_nonces',
];

class UserMergeError extends Error {
  constructor(message, code, statusCode = 400) {
    super(message);
    this.name = 'UserMergeError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

function normalizeReason(value) {
  return typeof value === 'string' ? value.trim().slice(0, 500) : '';
}

async function mergeUserAccounts({
  client,
  sourceUserId,
  targetUserId,
  adminId,
  reason,
  requestIp,
  confirmSupportCode,
}) {
  const safeReason = normalizeReason(reason);
  if (sourceUserId === targetUserId) {
    throw new UserMergeError(
      'A conta de origem e a conta principal precisam ser diferentes.',
      'MERGE_SAME_USER'
    );
  }
  if (safeReason.length < 8) {
    throw new UserMergeError(
      'Informe um motivo com no minimo 8 caracteres para reconciliar as contas.',
      'MERGE_REASON_REQUIRED'
    );
  }

  const locked = await client.query(
    `SELECT id, email, support_code, support_label, device_id,
            device_account_key, device_model, ip_address, app_version,
            is_active, is_banned, referred_by, merged_into_user_id,
            created_at, last_login_at
       FROM users
      WHERE id = ANY($1::uuid[])
      ORDER BY id
      FOR UPDATE`,
    [[sourceUserId, targetUserId]]
  );

  if (locked.rows.length !== 2) {
    throw new UserMergeError(
      'Conta de origem ou conta principal nao encontrada.',
      'MERGE_USER_NOT_FOUND',
      404
    );
  }

  const source = locked.rows.find((row) => row.id === sourceUserId);
  const target = locked.rows.find((row) => row.id === targetUserId);
  if (!source || !target) {
    throw new UserMergeError(
      'Nao foi possivel identificar as contas para reconciliacao.',
      'MERGE_USER_NOT_FOUND',
      404
    );
  }

  if (source.merged_into_user_id) {
    throw new UserMergeError(
      'A conta de origem ja foi reconciliada anteriormente.',
      'SOURCE_ALREADY_MERGED',
      409
    );
  }
  if (target.merged_into_user_id) {
    throw new UserMergeError(
      'A conta escolhida como principal ja esta arquivada em outra conta.',
      'TARGET_ALREADY_MERGED',
      409
    );
  }

  const expectedCode = String(target.support_code || '').toUpperCase();
  if (!confirmSupportCode || String(confirmSupportCode).trim().toUpperCase() !== expectedCode) {
    throw new UserMergeError(
      'Confirme o codigo de suporte exato da conta principal.',
      'MERGE_CONFIRMATION_MISMATCH',
      409
    );
  }

  // Garante que as chaves atuais estejam representadas antes de mover os aliases.
  await client.query(
    `INSERT INTO device_account_aliases (
       device_account_key, user_id, source, first_seen_at, last_seen_at
     )
     SELECT device_account_key, id, 'merge_backfill', NOW(), NOW()
       FROM users
      WHERE id = ANY($1::uuid[]) AND device_account_key IS NOT NULL
     ON CONFLICT (device_account_key) DO NOTHING`,
    [[sourceUserId, targetUserId]]
  );

  await client.query(
    `UPDATE device_account_aliases
        SET user_id = $1,
            source = 'admin_merge',
            created_by_admin = $2,
            last_seen_at = NOW(),
            metadata = metadata || $3::jsonb
      WHERE user_id = $4`,
    [
      targetUserId,
      adminId,
      JSON.stringify({ sourceUserId, targetUserId, reason: safeReason }),
      sourceUserId,
    ]
  );

  // Tabelas sem unicidade composta por usuario podem ser movidas diretamente.
  for (const table of MERGEABLE_USER_TABLES) {
    await client.query(
      `UPDATE ${table} SET user_id = $1 WHERE user_id = $2`,
      [targetUserId, sourceUserId]
    );
  }

  // Check-ins do mesmo dia sao consolidados; o ledger continua preservando todos
  // os lancamentos financeiros das duas contas.
  await client.query(
    `UPDATE daily_checkins target
        SET streak_day = GREATEST(target.streak_day, source.streak_day),
            points_awarded = target.points_awarded + source.points_awarded,
            created_at = LEAST(target.created_at, source.created_at)
       FROM daily_checkins source
      WHERE target.user_id = $1
        AND source.user_id = $2
        AND target.checkin_date = source.checkin_date`,
    [targetUserId, sourceUserId]
  );
  await client.query(
    `DELETE FROM daily_checkins source
      USING daily_checkins target
      WHERE source.user_id = $2
        AND target.user_id = $1
        AND source.checkin_date = target.checkin_date`,
    [targetUserId, sourceUserId]
  );
  await client.query(
    'UPDATE daily_checkins SET user_id = $1 WHERE user_id = $2',
    [targetUserId, sourceUserId]
  );

  // Progresso equivalente da mesma missao/ciclo e unido pelo estado mais avancado.
  await client.query(
    `UPDATE mission_progress target
        SET current_value = GREATEST(target.current_value, source.current_value),
            is_completed = target.is_completed OR source.is_completed,
            is_claimed = target.is_claimed OR source.is_claimed,
            completed_at = COALESCE(
              LEAST(target.completed_at, source.completed_at),
              target.completed_at,
              source.completed_at
            ),
            claimed_at = COALESCE(
              LEAST(target.claimed_at, source.claimed_at),
              target.claimed_at,
              source.claimed_at
            )
       FROM mission_progress source
      WHERE target.user_id = $1
        AND source.user_id = $2
        AND target.mission_id = source.mission_id
        AND target.reset_date = source.reset_date`,
    [targetUserId, sourceUserId]
  );
  await client.query(
    `DELETE FROM mission_progress source
      USING mission_progress target
      WHERE source.user_id = $2
        AND target.user_id = $1
        AND source.mission_id = target.mission_id
        AND source.reset_date = target.reset_date`,
    [targetUserId, sourceUserId]
  );
  await client.query(
    'UPDATE mission_progress SET user_id = $1 WHERE user_id = $2',
    [targetUserId, sourceUserId]
  );

  // O mesmo token push pode ter sido registrado nas duas contas.
  await client.query(
    `DELETE FROM push_tokens source
      USING push_tokens target
      WHERE source.user_id = $2
        AND target.user_id = $1
        AND source.token = target.token`,
    [targetUserId, sourceUserId]
  );
  await client.query(
    'UPDATE push_tokens SET user_id = $1 WHERE user_id = $2',
    [targetUserId, sourceUserId]
  );

  // Remove relacoes que virariam autoindicacao e normaliza as demais recompensas.
  await client.query(
    `DELETE FROM referral_rewards
      WHERE (referrer_id = $1 AND referred_id = $2)
         OR (referrer_id = $2 AND referred_id = $1)`,
    [sourceUserId, targetUserId]
  );
  // `status` e `credited_at` foram introduzidas depois da criacao da tabela em algumas
  // instalacoes. O merge inspeciona o schema real para nao falhar onde as colunas ainda
  // nao existem, mantendo a consolidacao de status quando elas estao presentes.
  const referralColumns = await client.query(
    `SELECT column_name
       FROM information_schema.columns
      WHERE table_name = 'referral_rewards'
        AND column_name IN ('status', 'credited_at')`
  );
  const referralColumnSet = new Set(referralColumns.rows.map((row) => row.column_name));
  const hasStatus = referralColumnSet.has('status');
  const hasCreditedAt = referralColumnSet.has('credited_at');

  const optionalColumns = [
    hasStatus ? 'status' : null,
    hasCreditedAt ? 'credited_at' : null,
  ].filter(Boolean);
  const optionalSelect = optionalColumns.length > 0 ? `, ${optionalColumns.join(', ')}` : '';

  const conflictUpdates = [
    'points_awarded = GREATEST(referral_rewards.points_awarded, EXCLUDED.points_awarded)',
  ];
  if (hasStatus) {
    conflictUpdates.push(`status = CASE
         WHEN referral_rewards.status = 'credited' OR EXCLUDED.status = 'credited'
           THEN 'credited'
         ELSE COALESCE(referral_rewards.status, EXCLUDED.status)
       END`);
  }
  if (hasCreditedAt) {
    conflictUpdates.push('credited_at = COALESCE(referral_rewards.credited_at, EXCLUDED.credited_at)');
  }

  await client.query(
    `WITH moved AS (
       DELETE FROM referral_rewards
        WHERE referrer_id = $1 OR referred_id = $1
        RETURNING *
     ), normalized AS (
       SELECT id,
              CASE WHEN referrer_id = $1 THEN $2::uuid ELSE referrer_id END AS referrer_id,
              CASE WHEN referred_id = $1 THEN $2::uuid ELSE referred_id END AS referred_id,
              reward_type, points_awarded, milestone_name, created_at${optionalSelect}
         FROM moved
     )
     INSERT INTO referral_rewards (
       id, referrer_id, referred_id, reward_type, points_awarded,
       milestone_name, created_at${optionalSelect}
     )
     SELECT id, referrer_id, referred_id, reward_type, points_awarded,
            milestone_name, created_at${optionalSelect}
       FROM normalized
      WHERE referrer_id <> referred_id
     ON CONFLICT (referrer_id, referred_id, reward_type, milestone_name)
     DO UPDATE SET ${conflictUpdates.join(',\n       ')}`,
    [sourceUserId, targetUserId]
  );

  const sourceReferrer = source.referred_by === targetUserId ? null : source.referred_by;
  if (target.referred_by === sourceUserId || !target.referred_by) {
    await client.query(
      'UPDATE users SET referred_by = $1 WHERE id = $2',
      [sourceReferrer, targetUserId]
    );
  }
  await client.query(
    `UPDATE users SET referred_by = $1
      WHERE referred_by = $2 AND id <> ALL($3::uuid[])`,
    [targetUserId, sourceUserId, [sourceUserId, targetUserId]]
  );

  const newPrimaryKey = source.device_account_key || target.device_account_key;
  const newDeviceId = source.device_id || newPrimaryKey || target.device_id;

  // Libera os indices unicos antes de promover a chave atual para a conta principal.
  await client.query(
    `UPDATE users
        SET device_id = NULL,
            device_account_key = NULL,
            is_active = false,
            merged_into_user_id = $1,
            merged_at = NOW(),
            updated_at = NOW()
      WHERE id = $2`,
    [targetUserId, sourceUserId]
  );

  await client.query(
    `UPDATE users
        SET device_id = COALESCE($1, device_id),
            device_account_key = COALESCE($2, device_account_key),
            device_model = COALESCE($3, device_model),
            ip_address = COALESCE($4, ip_address),
            app_version = COALESCE($5, app_version),
            support_label = COALESCE(support_label, $6),
            last_login_at = GREATEST(last_login_at, $7),
            referral_count = (
              SELECT COUNT(*) FROM users referred WHERE referred.referred_by = $8
            ),
            updated_at = NOW()
      WHERE id = $8`,
    [
      newDeviceId,
      newPrimaryKey,
      source.device_model,
      source.ip_address,
      source.app_version,
      source.support_label,
      source.last_login_at,
      targetUserId,
    ]
  );

  await client.query(
    `INSERT INTO audit_log (
       actor_id, actor_type, action, target_type, target_id,
       old_value, new_value, ip_address
     )
     VALUES ($1, 'admin', 'USER_ACCOUNTS_MERGED', 'user', $2, $3, $4, $5)`,
    [
      adminId,
      targetUserId,
      JSON.stringify({
        sourceUserId,
        sourceSupportCode: source.support_code,
        sourceEmail: source.email,
        sourceDeviceKey: source.device_account_key,
        reason: safeReason,
      }),
      JSON.stringify({
        targetUserId,
        targetSupportCode: target.support_code,
        targetEmail: target.email,
        promotedDeviceKey: newPrimaryKey,
      }),
      requestIp || null,
    ]
  );

  const result = await client.query(
    `SELECT u.id, u.support_code, u.support_label, u.email, u.device_id,
            u.device_account_key, u.app_version,
            COALESCE(SUM(pl.amount), 0) AS balance
       FROM users u
       LEFT JOIN points_ledger pl ON pl.user_id = u.id
      WHERE u.id = $1
      GROUP BY u.id`,
    [targetUserId]
  );

  return {
    sourceUserId,
    target: result.rows[0],
  };
}

module.exports = {
  UserMergeError,
  mergeUserAccounts,
};
