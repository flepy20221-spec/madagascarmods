const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken, authenticateAdmin } = require('../middleware/auth');

function compatibleField(body, camelCase, snakeCase) {
  if (Object.prototype.hasOwnProperty.call(body, camelCase)) {
    return body[camelCase];
  }
  if (Object.prototype.hasOwnProperty.call(body, snakeCase)) {
    return body[snakeCase];
  }
  return undefined;
}

function parseOptionalPositiveInteger(value) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseOptionalNonNegativeInteger(value) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

// ============================================================================
// MISSAO DE AVALIACAO NA PLAY STORE
//
// O que a plataforma permite e o que nao permite
// ---------------------------------------------
// O Google nao expoe nenhuma forma de saber se um usuario especifico avaliou o
// aplicativo. A In-App Review API mostra o formulario dentro do app, mas por
// decisao de privacidade nao informa se a avaliacao foi enviada nem qual nota
// recebeu. Nao existe endpoint, webhook ou consulta que resolva isso.
//
// Portanto: esta missao e AUTODECLARADA, e nao ha implementacao possivel que a
// torne verificavel. Registrar isso de forma explicita no codigo evita que
// alguem venha a "consertar" a ausencia de verificacao mais tarde procurando uma
// API que nao existe.
//
// O que o servidor consegue garantir
// ----------------------------------
// Tres coisas, todas implementadas abaixo:
//   1. que o usuario passou pelo fluxo (POST /:id/start grava started_at);
//   2. que houve um intervalo minimo plausivel entre abrir a loja e resgatar
//      (min_seconds_before_claim), o que quebra o claim automatizado imediato;
//   3. que a recompensa e concedida no maximo uma vez por ciclo (uma vez por
//      conta, ou uma vez por cooldown_days quando configurado).
//
// Isso nao transforma a missao em verificavel. Torna o atalho detectavel e
// limita o prejuizo a uma concessao por conta — que e a mesma exposicao de
// qualquer bonus de cadastro.
// ============================================================================
const SELF_DECLARED_TYPES = new Set(['app_review']);
const MANUAL_EVIDENCE_TYPES = new Set(['manus_proof']);
const MANUS_PROOF_SLUG = 'manus-account-proof';
const MANUS_PROOF_PORTAL_URL = process.env.MANUS_PROOF_PORTAL_URL
  || 'https://cashpix-manus-proof-production.up.railway.app/';

// Aceita apenas a ficha de um aplicativo na Play Store. A validacao existe para
// que um erro de digitacao no painel administrativo nao consiga apontar a base
// instalada inteira para um dominio arbitrario: a URL chega ao aplicativo pela
// API e e aberta no navegador do aparelho.
function normalizeActionUrl(value) {
  if (value === undefined) return undefined;
  if (value === null || (typeof value === 'string' && value.trim() === '')) return null;
  if (typeof value !== 'string') return false;

  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch (_) {
    return false;
  }

  if (parsed.protocol !== 'https:') return false;

  const host = parsed.hostname.toLowerCase();
  const isPlayStorePage = host === 'play.google.com'
    && parsed.pathname === '/store/apps/details'
    && Boolean(parsed.searchParams.get('id'));
  let isManusProofPortal = false;
  try {
    isManusProofPortal = parsed.origin === new URL(MANUS_PROOF_PORTAL_URL).origin;
  } catch (_) {
    // Uma variavel de ambiente invalida nao deve ampliar a lista de destinos.
  }
  // market:// nao passa por new URL() com protocolo https, e a ficha web abre a
  // Play Store nativa por intent de qualquer forma. Um unico formato aceito
  // mantem a validacao simples e o comportamento previsivel.
  return isPlayStorePage || isManusProofPortal ? parsed.toString() : false;
}

/**
 * Decide se uma missao autodeclarada pode ser resgatada agora.
 *
 * Recebe a linha de progresso vigente (ou undefined) e devolve `null` quando
 * esta liberada, ou um objeto de erro pronto para a resposta HTTP. Extraida em
 * funcao propria porque a mesma regra e consultada na listagem (para decidir se
 * o botao aparece) e no resgate (para decidir se o credito acontece); duplicar
 * a condicao nos dois lugares abriria espaco para eles divergirem.
 */
function evaluateSelfDeclaredClaim(mission, progressRow) {
  const startedAt = progressRow?.started_at ? new Date(progressRow.started_at) : null;

  if (!startedAt) {
    return {
      status: 400,
      body: {
        error: 'Abra a Play Store pela missao antes de resgatar a recompensa.',
        code: 'MISSION_NOT_STARTED',
      },
    };
  }

  const minSeconds = Number(mission.min_seconds_before_claim) || 0;
  if (minSeconds > 0) {
    const elapsedSeconds = (Date.now() - startedAt.getTime()) / 1000;
    if (elapsedSeconds < minSeconds) {
      const remaining = Math.ceil(minSeconds - elapsedSeconds);
      return {
        status: 400,
        body: {
          error: `Aguarde ${remaining} segundo(s) e toque novamente para resgatar.`,
          code: 'MISSION_TOO_FAST',
          retryAfterSeconds: remaining,
        },
      };
    }
  }

  return null;
}

/**
 * Ultima concessao da missao para o usuario, considerando o cooldown.
 *
 * Missoes com `cooldown_days` nao usam `reset_date` como as diarias: a janela e
 * contada a partir do instante do resgate anterior, nao do calendario. Uma
 * missao com cooldown de 30 dias resgatada dia 20 volta no dia 19 do mes
 * seguinte, e nao no dia 1.
 */
async function findActiveClaim(queryable, userId, mission, today) {
  if (mission.cooldown_days) {
    const result = await queryable.query(
      `SELECT id, is_claimed, claimed_at, started_at
         FROM mission_progress
        WHERE user_id = $1
          AND mission_id = $2
          AND is_claimed = true
          AND claimed_at > NOW() - ($3 || ' days')::interval
        ORDER BY claimed_at DESC
        LIMIT 1`,
      [userId, mission.id, String(mission.cooldown_days)]
    );
    return result.rows[0] || null;
  }

  const result = await queryable.query(
    `SELECT id, is_claimed, claimed_at, started_at
       FROM mission_progress
      WHERE user_id = $1
        AND mission_id = $2
        AND (reset_date = $3 OR $4 = false)
      ORDER BY created_at DESC
      LIMIT 1`,
    [userId, mission.id, today, mission.is_daily]
  );
  return result.rows[0] || null;
}

/**
 * GET /api/missions
 * Lista missões ativas com progresso do usuário
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const today = new Date().toISOString().split('T')[0];

    // Buscar missões ativas
    const missions = await db.query(
      `SELECT m.id, m.title, m.description, m.type, m.target_value, m.reward_points, m.icon, m.is_daily,
              m.verification_mode, m.action_url, m.requires_ad, m.cooldown_days,
              m.min_seconds_before_claim, m.slug, m.evidence_required,
              m.minimum_external_credits, m.instructions,
              COALESCE(mp.current_value, 0) as current_value,
              COALESCE(mp.is_completed, false) as is_completed,
              COALESCE(mp.is_claimed, false) as is_claimed,
              mp.started_at
       FROM missions m
       LEFT JOIN mission_progress mp ON mp.mission_id = m.id AND mp.user_id = $1 
         AND (m.is_daily = false OR mp.reset_date = $2)
       WHERE m.is_active = true
       ORDER BY m.sort_order ASC`,
      [userId, today]
    );

    // Calcular progresso automático para missões baseadas em dados existentes
    const enrichedMissions = [];
    for (const mission of missions.rows) {
      let currentValue = mission.current_value;

      // Auto-calcular progresso para missões do tipo watch_ads (baseado no dia)
      if (mission.type === 'watch_ads' && mission.is_daily) {
        const adsToday = await db.query(
          `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1 AND DATE(created_at) = $2`,
          [userId, today]
        );
        currentValue = parseInt(adsToday.rows[0].total);
      }

      // Auto-calcular para reach_level
      if (mission.type === 'reach_level') {
        const totalAds = await db.query(
          `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1`,
          [userId]
        );
        currentValue = Math.floor(parseInt(totalAds.rows[0].total) / 50);
      }

      // Auto-calcular para referral
      if (mission.type === 'referral') {
        const referrals = await db.query(
          `SELECT referral_count FROM users WHERE id = $1`,
          [userId]
        );
        currentValue = referrals.rows[0]?.referral_count || 0;
      }

      // Auto-calcular para checkin
      if (mission.type === 'checkin' && mission.is_daily) {
        const checkinToday = await db.query(
          `SELECT id FROM daily_checkins WHERE user_id = $1 AND checkin_date = $2`,
          [userId, today]
        );
        currentValue = checkinToday.rows.length > 0 ? 1 : 0;
      }

      // ======================================================================
      // MISSOES AUTODECLARADAS
      //
      // Nao ha o que auto-calcular: o servidor nao tem fonte de dados propria
      // sobre o ato externo. O progresso vem exclusivamente da linha gravada por
      // POST /:id/start, e por isso `current_value` e usado como esta.
      //
      // Duas informacoes precisam ser refeitas aqui em vez de vir do LEFT JOIN:
      //
      //   * `isClaimed` — o JOIN casa por `reset_date` para missoes diarias, o
      //     que nao cobre cooldown em dias. findActiveClaim aplica a regra certa.
      //   * `startedAt` — quando ha cooldown, a linha relevante pode ser de
      //     outro dia e nao ser a que o JOIN trouxe.
      // ======================================================================
      let startedAt = mission.started_at;
      let isClaimed = mission.is_claimed;
      let evidenceStatus = null;
      let evidenceProtocol = null;
      let evidenceRejectionReason = null;

      if (SELF_DECLARED_TYPES.has(mission.type) || mission.verification_mode === 'self_declared') {
        const activeClaim = await findActiveClaim(db, userId, mission, today);
        isClaimed = Boolean(activeClaim?.is_claimed);
        startedAt = activeClaim?.started_at ?? mission.started_at;

        if (!isClaimed && mission.cooldown_days) {
          // Fora do cooldown a missao recomeca do zero: a linha antiga nao pode
          // deixar a barra de progresso cheia sem que o usuario tenha aberto a
          // loja de novo nesta rodada.
          const currentCycle = await db.query(
            `SELECT current_value, started_at
               FROM mission_progress
              WHERE user_id = $1 AND mission_id = $2 AND is_claimed = false
              ORDER BY created_at DESC LIMIT 1`,
            [userId, mission.id]
          );
          currentValue = currentCycle.rows[0]?.current_value ?? 0;
          startedAt = currentCycle.rows[0]?.started_at ?? null;
        }
      }

      if (MANUAL_EVIDENCE_TYPES.has(mission.type) || mission.verification_mode === 'manual_evidence') {
        const evidence = await db.query(
          `SELECT status, public_protocol, rejection_reason
             FROM mission_evidence_submissions
            WHERE user_id = $1 AND mission_id = $2
            ORDER BY submitted_at DESC
            LIMIT 1`,
          [userId, mission.id]
        );
        const latestEvidence = evidence.rows[0] || null;
        evidenceStatus = latestEvidence?.status || 'not_submitted';
        evidenceProtocol = latestEvidence?.public_protocol || null;
        evidenceRejectionReason = latestEvidence?.rejection_reason || null;
        currentValue = evidenceStatus === 'approved' ? mission.target_value : 0;
      }

      const isCompleted = currentValue >= mission.target_value;

      enrichedMissions.push({
        id: mission.id,
        title: mission.title,
        description: mission.description,
        type: mission.type,
        targetValue: mission.target_value,
        rewardPoints: mission.reward_points,
        icon: mission.icon,
        isDaily: mission.is_daily,
        currentValue: Math.min(currentValue, mission.target_value),
        isCompleted,
        isClaimed,
        // Campos novos. Clientes antigos ignoram propriedades desconhecidas no
        // JSON, portanto acrescenta-los nao afeta nenhuma versao ja publicada.
        verificationMode: mission.verification_mode || 'auto',
        actionUrl: mission.action_url || null,
        requiresAd: mission.requires_ad !== false,
        cooldownDays: mission.cooldown_days || null,
        minSecondsBeforeClaim: mission.min_seconds_before_claim || 0,
        startedAt: startedAt ? new Date(startedAt).toISOString() : null,
        slug: mission.slug || null,
        evidenceRequired: mission.evidence_required === true,
        minimumExternalCredits: Number(mission.minimum_external_credits) || 0,
        instructions: mission.instructions || {},
        evidenceStatus,
        evidenceProtocol,
        evidenceRejectionReason,
      });
    }

    res.json({
      success: true,
      missions: enrichedMissions
    });
  } catch (error) {
    console.error('Missions list error:', error);
    res.status(500).json({ error: 'Erro ao buscar missões' });
  }
});

/**
 * POST /api/missions/:id/start
 *
 * Registra que o usuario iniciou a acao externa da missao (abriu a Play Store).
 * E o passo que produz `started_at`, sem o qual o resgate de uma missao
 * autodeclarada e recusado.
 *
 * Idempotente por escolha: chamar duas vezes nao reinicia o cronometro. Se
 * reiniciasse, o aplicativo bastaria chamar /start de novo para zerar a espera
 * minima, e a unica barreira antifraude da missao deixaria de existir.
 */
router.post('/:id/start', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const missionId = req.params.id;
    const today = new Date().toISOString().split('T')[0];

    await client.query('BEGIN');

    const missionResult = await client.query(
      'SELECT * FROM missions WHERE id = $1 AND is_active = true',
      [missionId]
    );

    if (missionResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Missao nao encontrada' });
    }

    const mission = missionResult.rows[0];
    const isSelfDeclared = SELF_DECLARED_TYPES.has(mission.type)
      || mission.verification_mode === 'self_declared';

    if (!isSelfDeclared) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Esta missao nao possui acao externa.',
        code: 'MISSION_NOT_STARTABLE',
      });
    }

    const activeClaim = await findActiveClaim(client, userId, mission, today);
    if (activeClaim?.is_claimed) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: mission.cooldown_days
          ? `Recompensa ja resgatada. Disponivel novamente em ${mission.cooldown_days} dia(s).`
          : 'Recompensa ja resgatada',
        code: 'MISSION_ALREADY_CLAIMED',
      });
    }

    // O progresso vai direto ao alvo: em uma missao autodeclarada, iniciar a acao
    // e todo o progresso que o servidor consegue observar. A checagem de tempo no
    // resgate e o que impede que isso vire credito instantaneo.
    //
    // COALESCE em started_at preserva o instante da primeira chamada — e o que
    // torna a rota idempotente.
    const progress = await client.query(
      `INSERT INTO mission_progress (
         user_id, mission_id, current_value, is_completed, is_claimed,
         completed_at, started_at, reset_date
       )
       VALUES ($1, $2, $3, true, false, NOW(), NOW(), $4)
       ON CONFLICT (user_id, mission_id, reset_date) DO UPDATE
          SET current_value = GREATEST(mission_progress.current_value, EXCLUDED.current_value),
              is_completed  = true,
              completed_at  = COALESCE(mission_progress.completed_at, NOW()),
              started_at    = COALESCE(mission_progress.started_at, NOW())
       RETURNING started_at`,
      [userId, missionId, mission.target_value, today]
    );

    await client.query('COMMIT');

    const startedAt = progress.rows[0].started_at;
    res.json({
      success: true,
      startedAt: new Date(startedAt).toISOString(),
      minSecondsBeforeClaim: mission.min_seconds_before_claim || 0,
      actionUrl: mission.action_url || null,
      requiresAd: mission.requires_ad !== false,
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Mission start error:', error);
    res.status(500).json({ error: 'Erro ao iniciar missao' });
  } finally {
    client.release();
  }
});

/**
 * POST /api/missions/:id/claim
 * Resgata a recompensa de uma missão completa
 */
router.post('/:id/claim', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  try {
    const userId = req.user.userId;
    const missionId = req.params.id;
    const { ad_watched } = req.body;
    const today = new Date().toISOString().split('T')[0];

    await client.query('BEGIN');

    // Buscar missão
    const mission = await client.query(
      `SELECT * FROM missions WHERE id = $1 AND is_active = true`,
      [missionId]
    );

    if (mission.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Missão não encontrada' });
    }

    const m = mission.rows[0];

    // ========================================================================
    // EXIGENCIA DE ANUNCIO
    //
    // A regra era fixa no codigo e aplicada antes de saber qual missao era. Agora
    // e por missao, com `requires_ad` cujo default no banco e `true` — as sete
    // missoes existentes em producao seguem exigindo anuncio exatamente como
    // antes desta alteracao.
    //
    // A checagem desceu para depois da leitura da missao porque agora depende
    // dela. Nenhum credito acontece entre os dois pontos, portanto a mudanca de
    // ordem nao abre janela: a transacao apenas leu a definicao da missao.
    // ========================================================================
    const requiresAd = m.requires_ad !== false;
    if (requiresAd && !ad_watched) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'É necessário assistir um anúncio para coletar a recompensa',
        require_ad: true,
      });
    }

    const isSelfDeclared = SELF_DECLARED_TYPES.has(m.type)
      || m.verification_mode === 'self_declared';
    const isManualEvidence = MANUAL_EVIDENCE_TYPES.has(m.type)
      || m.verification_mode === 'manual_evidence';

    // Verificar se já foi resgatada. findActiveClaim aplica cooldown_days quando
    // configurado e cai na regra historica (reset_date) quando nao ha cooldown.
    const existing = await findActiveClaim(client, userId, m, today);

    if (existing?.is_claimed) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: m.cooldown_days
          ? `Recompensa já resgatada. Disponível novamente em ${m.cooldown_days} dia(s).`
          : 'Recompensa já resgatada',
      });
    }

    // Verificar se a missão está completa (recalcular progresso)
    let currentValue = 0;

    if (m.type === 'watch_ads' && m.is_daily) {
      const adsToday = await client.query(
        `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1 AND DATE(created_at) = $2`,
        [userId, today]
      );
      currentValue = parseInt(adsToday.rows[0].total);
    } else if (m.type === 'reach_level') {
      const totalAds = await client.query(
        `SELECT COUNT(*) as total FROM reward_events WHERE user_id = $1`,
        [userId]
      );
      currentValue = Math.floor(parseInt(totalAds.rows[0].total) / 50);
    } else if (m.type === 'referral') {
      const referrals = await client.query(
        `SELECT referral_count FROM users WHERE id = $1`,
        [userId]
      );
      currentValue = referrals.rows[0]?.referral_count || 0;
    } else if (m.type === 'checkin' && m.is_daily) {
      const checkinToday = await client.query(
        `SELECT id FROM daily_checkins WHERE user_id = $1 AND checkin_date = $2`,
        [userId, today]
      );
      currentValue = checkinToday.rows.length > 0 ? 1 : 0;
    } else if (isSelfDeclared) {
      // ======================================================================
      // MISSAO AUTODECLARADA
      //
      // Nao existe fonte de dados propria para recalcular: o progresso e a
      // propria linha gravada por /start. Reler do banco DENTRO da transacao,
      // com FOR UPDATE, e o que impede que duas requisicoes simultaneas do mesmo
      // usuario passem as duas pela checagem e creditem a recompensa em dobro.
      // ======================================================================
      const lockedProgress = await client.query(
        `SELECT current_value, started_at, is_claimed
           FROM mission_progress
          WHERE user_id = $1 AND mission_id = $2 AND is_claimed = false
          ORDER BY created_at DESC
          LIMIT 1
          FOR UPDATE`,
        [userId, missionId]
      );

      const progressRow = lockedProgress.rows[0] || null;
      currentValue = progressRow?.current_value ?? 0;

      const rejection = evaluateSelfDeclaredClaim(m, progressRow);
      if (rejection) {
        await client.query('ROLLBACK');
        return res.status(rejection.status).json(rejection.body);
      }
    } else if (isManualEvidence) {
      const lockedEvidence = await client.query(
        `SELECT id, status
           FROM mission_evidence_submissions
          WHERE user_id = $1 AND mission_id = $2 AND status = 'approved'
          ORDER BY reviewed_at DESC
          LIMIT 1
          FOR UPDATE`,
        [userId, missionId]
      );
      if (!lockedEvidence.rows[0]) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: 'Sua comprovacao ainda nao foi aprovada.',
          code: 'MISSION_EVIDENCE_NOT_APPROVED',
        });
      }

      const lockedProgress = await client.query(
        `SELECT current_value, is_claimed
           FROM mission_progress
          WHERE user_id = $1 AND mission_id = $2
          ORDER BY created_at DESC
          LIMIT 1
          FOR UPDATE`,
        [userId, missionId]
      );
      if (lockedProgress.rows[0]?.is_claimed) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Recompensa ja resgatada' });
      }
      currentValue = m.target_value;
    }

    if (currentValue < m.target_value) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Missão ainda não foi completada' });
    }

    // Upsert progress e marcar como claimed.
    //
    // `started_at` e preservado com COALESCE: ele e o registro historico de
    // quando a acao externa comecou e nao deve ser sobrescrito pelo resgate.
    await client.query(
      `INSERT INTO mission_progress (user_id, mission_id, current_value, is_completed, is_claimed, completed_at, claimed_at, reset_date)
       VALUES ($1, $2, $3, true, true, NOW(), NOW(), $4)
       ON CONFLICT (user_id, mission_id, reset_date) 
       DO UPDATE SET is_completed = true, is_claimed = true, current_value = $3, completed_at = NOW(), claimed_at = NOW(),
                     started_at = COALESCE(mission_progress.started_at, EXCLUDED.started_at)`,
      [userId, missionId, currentValue, today]
    );

    // Registrar no ledger (saldo é calculado pela soma do points_ledger)
    await client.query(
      `INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ($1, $2, $3, 'MISSION', $4)`,
      [uuidv4(), userId, m.reward_points, `Missão: ${m.title}`]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      pointsAwarded: m.reward_points,
      message: `Parabéns! Você ganhou ${m.reward_points} pontos!`
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Mission claim error:', error);
    res.status(500).json({ error: 'Erro ao resgatar recompensa' });
  } finally {
    client.release();
  }
});

// ============ ADMIN ROUTES ============

/**
 * GET /api/admin/missions
 * Lista todas as missões (admin)
 */
router.get('/admin/list', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT m.*,
              (SELECT COUNT(*)::integer
                 FROM mission_evidence_submissions s
                WHERE s.mission_id = m.id AND s.status = 'pending') AS pending_evidence_count
         FROM missions m
        ORDER BY m.sort_order ASC, m.created_at DESC`
    );
    res.json({ success: true, missions: result.rows });
  } catch (error) {
    console.error('Admin missions list error:', error);
    res.status(500).json({ error: 'Erro ao buscar missões' });
  }
});

/**
 * POST /api/admin/missions
 * Criar nova missão (admin)
 */
router.post('/admin/create', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, type, icon } = req.body;
    const targetValue = parseOptionalPositiveInteger(
      compatibleField(req.body, 'targetValue', 'target_value')
    );
    const rewardPoints = parseOptionalPositiveInteger(
      compatibleField(req.body, 'rewardPoints', 'reward_points')
    );
    const sortOrder = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'sortOrder', 'sort_order')
    );
    const isActive = compatibleField(req.body, 'isActive', 'is_active');
    const isDaily = compatibleField(req.body, 'isDaily', 'is_daily');
    const requiresAd = compatibleField(req.body, 'requiresAd', 'requires_ad');
    const cooldownDays = parseOptionalPositiveInteger(
      compatibleField(req.body, 'cooldownDays', 'cooldown_days')
    );
    const minSecondsBeforeClaim = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'minSecondsBeforeClaim', 'min_seconds_before_claim')
    );
    const actionUrl = normalizeActionUrl(
      compatibleField(req.body, 'actionUrl', 'action_url')
    );
    const evidenceRequired = compatibleField(req.body, 'evidenceRequired', 'evidence_required');
    const minimumExternalCredits = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'minimumExternalCredits', 'minimum_external_credits')
    );
    const instructions = compatibleField(req.body, 'instructions', 'instructions');

    if (!title || !type || targetValue === undefined || rewardPoints === undefined) {
      return res.status(400).json({ error: 'Campos obrigatórios: title, type, targetValue, rewardPoints' });
    }
    if (targetValue === null || rewardPoints === null) {
      return res.status(400).json({ error: 'Meta e recompensa devem ser números inteiros maiores que zero' });
    }
    if (sortOrder === null) {
      return res.status(400).json({ error: 'Ordem deve ser um número inteiro maior ou igual a zero' });
    }
    if (isActive !== undefined && typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive deve ser booleano' });
    }
    if (isDaily !== undefined && typeof isDaily !== 'boolean') {
      return res.status(400).json({ error: 'isDaily deve ser booleano' });
    }
    if (requiresAd !== undefined && typeof requiresAd !== 'boolean') {
      return res.status(400).json({ error: 'requiresAd deve ser booleano' });
    }
    if (evidenceRequired !== undefined && typeof evidenceRequired !== 'boolean') {
      return res.status(400).json({ error: 'evidenceRequired deve ser booleano' });
    }
    if (minimumExternalCredits === null) {
      return res.status(400).json({ error: 'Creditos externos devem ser um numero inteiro maior ou igual a zero' });
    }
    if (instructions !== undefined && (typeof instructions !== 'object' || Array.isArray(instructions) || instructions === null)) {
      return res.status(400).json({ error: 'instructions deve ser um objeto JSON' });
    }
    if (cooldownDays === null) {
      return res.status(400).json({ error: 'Cooldown deve ser um número inteiro maior que zero, ou vazio' });
    }
    if (minSecondsBeforeClaim === null) {
      return res.status(400).json({ error: 'Espera mínima deve ser um número inteiro maior ou igual a zero' });
    }
    if (minSecondsBeforeClaim !== undefined && minSecondsBeforeClaim > 3600) {
      return res.status(400).json({ error: 'Espera mínima não pode passar de 3600 segundos' });
    }
    if (actionUrl === false) {
      return res.status(400).json({
        error: 'A URL da ação deve ser um link de ficha de aplicativo na Play Store, '
          + 'no formato https://play.google.com/store/apps/details?id=SEU.PACOTE',
      });
    }

    // `app_review` implica verificacao autodeclarada. Derivar isso do tipo em vez
    // de aceitar do cliente evita a combinacao incoerente de uma missao de
    // avaliacao marcada como verificavel automaticamente — o servidor nao teria
    // como calcular progresso algum e a missao ficaria permanentemente travada.
    const verificationMode = MANUAL_EVIDENCE_TYPES.has(type)
      ? 'manual_evidence'
      : (SELF_DECLARED_TYPES.has(type) ? 'self_declared' : 'auto');

    if (verificationMode === 'self_declared' && actionUrl === undefined) {
      return res.status(400).json({
        error: 'Missões de avaliação exigem a URL da ficha do aplicativo na Play Store.',
      });
    }
    const effectiveActionUrl = verificationMode === 'manual_evidence'
      ? (actionUrl ?? MANUS_PROOF_PORTAL_URL)
      : (actionUrl ?? null);

    const result = await db.query(
      `INSERT INTO missions (
         title, description, type, target_value, reward_points, icon,
         is_active, is_daily, sort_order,
         verification_mode, action_url, requires_ad, cooldown_days,
         min_seconds_before_claim, slug, evidence_required,
         minimum_external_credits, instructions
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
               $15, $16, $17, $18) RETURNING *`,
      [
        title, description || '', type, targetValue, rewardPoints, icon || 'star',
        isActive !== false, isDaily !== false, sortOrder ?? 0,
        verificationMode,
        effectiveActionUrl,
        // Default divergente por tipo, e proposital: uma missao de avaliacao leva
        // o usuario para fora do aplicativo e o traz de volta, e cobrar um anuncio
        // por cima disso e atrito sem contrapartida. As demais mantem `true`.
        requiresAd !== undefined ? requiresAd : verificationMode === 'auto',
        cooldownDays ?? null,
        minSecondsBeforeClaim ?? (verificationMode === 'self_declared' ? 15 : 0),
        verificationMode === 'manual_evidence' ? MANUS_PROOF_SLUG : null,
        verificationMode === 'manual_evidence' ? true : (evidenceRequired ?? false),
        minimumExternalCredits ?? (verificationMode === 'manual_evidence' ? 1800 : 0),
        instructions ? JSON.stringify(instructions) : JSON.stringify({}),
      ]
    );

    res.json({ success: true, mission: result.rows[0] });
  } catch (error) {
    console.error('Admin create mission error:', error);
    res.status(500).json({ error: 'Erro ao criar missão' });
  }
});

/**
 * PUT /api/admin/missions/:id
 * Atualizar missão (admin)
 */
router.put('/admin/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, type, icon } = req.body;
    const targetValue = parseOptionalPositiveInteger(
      compatibleField(req.body, 'targetValue', 'target_value')
    );
    const rewardPoints = parseOptionalPositiveInteger(
      compatibleField(req.body, 'rewardPoints', 'reward_points')
    );
    const sortOrder = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'sortOrder', 'sort_order')
    );
    const isActive = compatibleField(req.body, 'isActive', 'is_active');
    const isDaily = compatibleField(req.body, 'isDaily', 'is_daily');
    const requiresAd = compatibleField(req.body, 'requiresAd', 'requires_ad');
    const cooldownDaysRaw = compatibleField(req.body, 'cooldownDays', 'cooldown_days');
    const minSecondsBeforeClaim = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'minSecondsBeforeClaim', 'min_seconds_before_claim')
    );
    const actionUrl = normalizeActionUrl(
      compatibleField(req.body, 'actionUrl', 'action_url')
    );

    const evidenceRequired = compatibleField(req.body, 'evidenceRequired', 'evidence_required');
    const minimumExternalCredits = parseOptionalNonNegativeInteger(
      compatibleField(req.body, 'minimumExternalCredits', 'minimum_external_credits')
    );
    const instructions = compatibleField(req.body, 'instructions', 'instructions');

    // Cooldown difere dos outros inteiros: `null` explicito e um valor valido,
    // significa "remover o cooldown". Por isso nao passa por
    // parseOptionalPositiveInteger, que trata null como erro de digitacao.
    let cooldownDays;
    if (cooldownDaysRaw === undefined) {
      cooldownDays = undefined;
    } else if (cooldownDaysRaw === null || cooldownDaysRaw === '' || cooldownDaysRaw === 0) {
      cooldownDays = null;
    } else {
      const parsed = Number(cooldownDaysRaw);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        return res.status(400).json({ error: 'Cooldown deve ser um número inteiro maior que zero, ou vazio' });
      }
      cooldownDays = parsed;
    }

    if (targetValue === null || rewardPoints === null) {
      return res.status(400).json({ error: 'Meta e recompensa devem ser números inteiros maiores que zero' });
    }
    if (sortOrder === null) {
      return res.status(400).json({ error: 'Ordem deve ser um número inteiro maior ou igual a zero' });
    }
    if (isActive !== undefined && typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive deve ser booleano' });
    }
    if (isDaily !== undefined && typeof isDaily !== 'boolean') {
      return res.status(400).json({ error: 'isDaily deve ser booleano' });
    }
    if (requiresAd !== undefined && typeof requiresAd !== 'boolean') {
      return res.status(400).json({ error: 'requiresAd deve ser booleano' });
    }
    if (evidenceRequired !== undefined && typeof evidenceRequired !== 'boolean') {
      return res.status(400).json({ error: 'evidenceRequired deve ser booleano' });
    }
    if (minimumExternalCredits === null) {
      return res.status(400).json({ error: 'Creditos externos devem ser um numero inteiro maior ou igual a zero' });
    }
    if (instructions !== undefined && (typeof instructions !== 'object' || Array.isArray(instructions) || instructions === null)) {
      return res.status(400).json({ error: 'instructions deve ser um objeto JSON' });
    }
    if (minSecondsBeforeClaim === null) {
      return res.status(400).json({ error: 'Espera mínima deve ser um número inteiro maior ou igual a zero' });
    }
    if (minSecondsBeforeClaim !== undefined && minSecondsBeforeClaim > 3600) {
      return res.status(400).json({ error: 'Espera mínima não pode passar de 3600 segundos' });
    }
    if (actionUrl === false) {
      return res.status(400).json({
        error: 'A URL da ação deve ser um link de ficha de aplicativo na Play Store, '
          + 'no formato https://play.google.com/store/apps/details?id=SEU.PACOTE',
      });
    }

    // O modo de verificacao acompanha o tipo quando o tipo e informado, pelo mesmo
    // motivo do endpoint de criacao. Quando o tipo nao vem no corpo (edicao
    // parcial, por exemplo so a recompensa), COALESCE preserva o valor atual.
    const verificationMode = type === undefined
      ? null
      : (MANUAL_EVIDENCE_TYPES.has(type)
        ? 'manual_evidence'
        : (SELF_DECLARED_TYPES.has(type) ? 'self_declared' : 'auto'));

    const result = await db.query(
      `UPDATE missions SET 
        title = COALESCE($1, title),
        description = COALESCE($2, description),
        type = COALESCE($3, type),
        target_value = COALESCE($4, target_value),
        reward_points = COALESCE($5, reward_points),
        icon = COALESCE($6, icon),
        is_active = COALESCE($7, is_active),
        is_daily = COALESCE($8, is_daily),
        sort_order = COALESCE($9, sort_order),
        verification_mode = COALESCE($11, verification_mode),
        action_url = CASE WHEN $12::boolean THEN $13::text ELSE action_url END,
        requires_ad = COALESCE($14, requires_ad),
        cooldown_days = CASE WHEN $15::boolean THEN $16::integer ELSE cooldown_days END,
        min_seconds_before_claim = COALESCE($17, min_seconds_before_claim),
        slug = CASE WHEN $18 = 'manual_evidence' THEN $19 ELSE slug END,
        evidence_required = COALESCE($20, evidence_required),
        minimum_external_credits = COALESCE($21, minimum_external_credits),
        instructions = COALESCE($22::jsonb, instructions),
        updated_at = NOW()
       WHERE id = $10 RETURNING *`,
      [
        title, description, type, targetValue, rewardPoints, icon, isActive, isDaily, sortOrder, id,
        verificationMode,
        // O par booleano+valor existe porque COALESCE nao distingue "campo ausente"
        // de "campo enviado como null para limpar". Sem isso, apagar a URL da acao
        // ou remover o cooldown seria impossivel pelo painel.
        actionUrl !== undefined, actionUrl ?? null,
        requiresAd,
        cooldownDays !== undefined, cooldownDays ?? null,
        minSecondsBeforeClaim,
        verificationMode,
        MANUS_PROOF_SLUG,
        verificationMode === 'manual_evidence' ? true : evidenceRequired,
        minimumExternalCredits,
        instructions ? JSON.stringify(instructions) : null,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Missão não encontrada' });
    }

    res.json({ success: true, mission: result.rows[0] });
  } catch (error) {
    console.error('Admin update mission error:', error);
    res.status(500).json({ error: 'Erro ao atualizar missão' });
  }
});

/**
 * DELETE /api/admin/missions/:id
 * Deletar missão (admin)
 */
router.delete('/admin/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query(`DELETE FROM mission_progress WHERE mission_id = $1`, [id]);
    await db.query(`DELETE FROM missions WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Admin delete mission error:', error);
    res.status(500).json({ error: 'Erro ao deletar missão' });
  }
});

module.exports = router;
