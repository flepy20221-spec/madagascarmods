'use strict';

const { v4: uuidv4, validate: uuidValidate } = require('uuid');

async function shouldRequireVerifiedReward(client) {
  const result = await client.query(
    `SELECT value FROM system_config WHERE key = 'reward_ssv_required_for_bonus' LIMIT 1`,
  );
  if (result.rows.length === 0) return false;
  const value = result.rows[0].value;
  if (typeof value === 'boolean') return value;
  try {
    return JSON.parse(String(value).toLowerCase()) === true;
  } catch (_) {
    return String(value).toLowerCase() === 'true';
  }
}

class RewardConsumptionError extends Error {
  constructor(message, code = 'REWARDED_SESSION_INVALID') {
    super(message);
    this.name = 'RewardConsumptionError';
    this.code = code;
  }
}

/**
 * Consome exatamente um evento rewarded confirmado pelo Google para um bônus.
 * Deve ser chamado dentro da transação que também grava o bônus.
 */
async function consumeVerifiedReward(client, {
  userId,
  rewardSessionId,
  purpose,
}) {
  if (!rewardSessionId || !uuidValidate(rewardSessionId)) {
    throw new RewardConsumptionError(
      'A confirmação do anúncio não foi identificada.',
      'REWARDED_SESSION_REQUIRED',
    );
  }

  const event = await client.query(
    `SELECT id
       FROM reward_events
      WHERE user_id = $1
        AND reward_session_id = $2
        AND ad_type = 'rewarded'
        AND ssv_verified = true
        AND created_at >= NOW() - INTERVAL '15 minutes'
      ORDER BY created_at DESC
      LIMIT 1
      FOR UPDATE`,
    [userId, rewardSessionId],
  );

  if (event.rows.length === 0) {
    throw new RewardConsumptionError(
      'A confirmação do anúncio ainda não chegou. Aguarde alguns segundos e tente novamente.',
      'REWARDED_SSV_PENDING',
    );
  }

  const rewardEventId = event.rows[0].id;
  try {
    await client.query(
      `INSERT INTO reward_consumptions
         (id, reward_event_id, user_id, purpose)
       VALUES ($1, $2, $3, $4)`,
      [uuidv4(), rewardEventId, userId, purpose],
    );
  } catch (error) {
    if (error.code === '23505') {
      throw new RewardConsumptionError(
        'Este anúncio já foi usado para liberar esta recompensa.',
        'REWARDED_SESSION_ALREADY_USED',
      );
    }
    throw error;
  }

  return rewardEventId;
}

module.exports = {
  consumeVerifiedReward,
  shouldRequireVerifiedReward,
  RewardConsumptionError,
};
