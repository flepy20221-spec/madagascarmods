const express = require('express');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware, rewardFraudDetection, clientIp } = require('../middleware/antiFraud');
const { botDetectionMiddleware } = require('../middleware/botDetection');
const { rewardLimiter, rewardStatusLimiter } = require('../middleware/rateLimits');
const {
  getRewardDistribution,
  POINT_VALUES
} = require('../utils/pointsRandom');
// Nota: drawRewardPoints e validateSsvToken NAO sao mais usados aqui.
// O sorteio de pontos de anuncios rewarded e a validacao criptografica do Google passaram a
// viver exclusivamente em src/routes/ssv.js, que e o unico caminho autorizado a creditar
// esse tipo de recompensa (ver auditoria VULN-01).

const router = express.Router();

// ============================================================================================
// GET /api/points/reward-status/:sessionId
//
// Consulta somente leitura de uma exibicao rewarded especifica. O UUID da sessao e criado no
// aparelho antes de `show()` e viaja ao Google dentro do custom_data assinado pelo SSV. A rota
// nunca credita pontos; ela apenas observa o evento que o callback servidor-a-servidor gravou.
// ============================================================================================
router.get(
  '/reward-status/:sessionId',
  rewardStatusLimiter,
  authenticateToken,
  botDetectionMiddleware,
  antifraudMiddleware,
  async (req, res) => {
    try {
      const { sessionId } = req.params;
      if (!uuidValidate(sessionId)) {
        return res.status(400).json({
          error: 'Invalid reward session',
          code: 'INVALID_REWARD_SESSION'
        });
      }

      const userId = req.user.userId;
      const [eventResult, balanceResult, dailyResult] = await Promise.all([
        db.query(
          `SELECT id, points_awarded, created_at
             FROM reward_events
            WHERE user_id = $1
              AND reward_session_id = $2
              AND ad_type = 'rewarded'
              AND ssv_verified = true
            LIMIT 1`,
          [userId, sessionId]
        ),
        db.query(
          `SELECT COALESCE(SUM(amount), 0) AS balance
             FROM points_ledger
            WHERE user_id = $1`,
          [userId]
        ),
        db.query(
          `SELECT COUNT(*) AS count
             FROM reward_events
            WHERE user_id = $1
              AND ad_type = 'rewarded'
              AND ssv_verified = true
              AND created_at >= ($2 || ' 00:00:00-03')::timestamptz
              AND created_at <  ($2::date + INTERVAL '1 day')::timestamptz AT TIME ZONE 'America/Sao_Paulo'`,
          [userId, require('../utils/adDailyLimit').todayBr()]
        )
      ]);

      const balance = parseInt(balanceResult.rows[0].balance, 10);
      const dailyCount = parseInt(dailyResult.rows[0].count, 10);

      if (eventResult.rows.length === 0) {
        return res.status(202).json({
          success: false,
          pending: true,
          code: 'SSV_PENDING',
          message: 'Aguardando confirmacao do anuncio.',
          newBalance: balance,
          pointValues: POINT_VALUES,
          dailyLimit: 100,
          dailyCount
        });
      }

      const event = eventResult.rows[0];
      return res.json({
        success: true,
        pending: false,
        verifiedBy: 'admob_ssv',
        pointsAwarded: event.points_awarded,
        newBalance: balance,
        eventId: event.id,
        rewardSessionId: sessionId,
        pointValues: POINT_VALUES,
        dailyLimit: 100,
        dailyCount
      });
    } catch (error) {
      console.error('Reward status error:', error);
      return res.status(500).json({ error: 'Failed to get reward status' });
    }
  }
);

// ============================================================================================
// POST /api/points/reward
//
// CORRECAO DA VULNERABILIDADE MAIS GRAVE (auditoria VULN-01)
//
// Comportamento anterior: esta rota creditava pontos com base apenas no que o cliente
// afirmava. O campo ssv_token era opcional; quando ausente, a validacao era ignorada e os
// pontos entravam do mesmo jeito. Quando o token vinha invalido, o codigo so registrava um
// aviso — a linha de bloqueio estava comentada com a observacao "Nao bloquear por enquanto".
// Resultado pratico: com um proxy HTTP (HTTPCanary e afins), bastava repetir
// POST /api/points/reward {"ad_type":"rewarded"} para gerar pontos infinitos sem assistir
// anuncio nenhum, e depois converter em saque real.
//
// Por que a "correcao obvia" nao serve:
// Exigir o ssv_token do aplicativo e impossivel. No SSV do AdMob o token NUNCA passa pelo
// dispositivo — o Google chama o servidor diretamente:
//
//     usuario assiste -> Google --(GET assinado)--> /api/ssv/callback   (o token existe aqui)
//                     -> App    --(POST)---------> /api/points/reward   (nunca tem o token)
//
// Essa e precisamente a razao de existir do SSV: o cliente nao participa da prova, logo nao
// ha o que adulterar no aparelho. Exigir do app um dado que so trafega no canal
// servidor-a-servidor faria toda requisicao legitima retornar 403, e o usuario veria
// "nao foi possivel confirmar a exibicao" depois de assistir o anuncio inteiro.
//
// Correcao adotada: retirar desta rota o poder de creditar anuncios rewarded.
//   - 'rewarded'  -> a rota NAO credita. Apenas consulta o que o callback do Google ja
//                    confirmou e devolve o saldo. Chamar isso mil vezes por um proxy nao
//                    gera um unico ponto, porque nao existe caminho de escrita aqui.
//   - 'interstitial' / 'banner' -> nao possuem SSV no AdMob (o formato nao preve
//                    verificacao servidor-a-servidor). Seguem creditando por esta rota,
//                    contidos por HMAC, limite por usuario, intervalo minimo e teto diario.
//                    O valor por exibicao e baixo por definicao de produto, o que torna o
//                    abuso pouco atrativo; ainda assim, o risco residual esta documentado.
//
// O credito legitimo de rewarded acontece integralmente em src/routes/ssv.js, que valida a
// assinatura do Google com as chaves publicas do AdMob, confere replay por transaction_id e
// associa o usuario pelo custom_data.
// ============================================================================================
router.post(
  '/reward',
  rewardLimiter,
  authenticateToken,
  botDetectionMiddleware,
  antifraudMiddleware,
  rewardFraudDetection,
  async (req, res) => {
  try {
    const { ad_type, ad_unit_id, ad_network } = req.body;

    if (!ad_type) {
      return res.status(400).json({ error: 'ad_type is required' });
    }

    const userId = req.user.userId;
    const ip = clientIp(req);

    if (!['rewarded', 'interstitial', 'banner'].includes(ad_type)) {
      return res.status(400).json({ error: 'Invalid ad_type. Must be: rewarded, interstitial, or banner' });
    }

    // Bloquear se fraud score é muito alto (detectado pelo middleware)
    if (req.fraudScore && req.fraudScore >= 3) {
      console.warn(`[Reward] Blocked reward for user ${userId} - fraud score: ${req.fraudScore}`);
      return res.status(403).json({
        error: 'Atividade suspeita detectada. Aguarde alguns minutos.',
        code: 'FRAUD_DETECTED'
      });
    }

    // ==========================================================================================
    // CAMINHO 'rewarded': CONSULTA, NUNCA CREDITO
    //
    // O app chama este endpoint ao terminar de assistir o anuncio. A resposta informa se o
    // Google ja confirmou a exibicao pelo callback SSV. Como o callback e assincrono e chega
    // em poucos segundos, o app deve tolerar o estado "pendente" e consultar novamente.
    // ==========================================================================================
    if (ad_type === 'rewarded') {
      // Janela de correlacao: eventos SSV confirmados para este usuario nos ultimos minutos.
      // Nao ha como amarrar a chamada do app a uma exibicao especifica (o app nao conhece o
      // transaction_id do Google), por isso a correlacao e temporal.
      const recentSsv = await db.query(
        `SELECT id, points_awarded, created_at
           FROM reward_events
          WHERE user_id = $1
            AND ad_type = 'rewarded'
            AND ssv_verified = true
            AND created_at > NOW() - INTERVAL '5 minutes'
          ORDER BY created_at DESC
          LIMIT 1`,
        [userId]
      );

      const balanceResult = await db.query(
        'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
        [userId]
      );
      const balance = parseInt(balanceResult.rows[0].balance, 10);

      const dailyCount = await db.query(
        `SELECT COUNT(*) as count FROM reward_events
          WHERE user_id = $1 AND ad_type = 'rewarded' AND ssv_verified = true
            AND created_at >= ($2 || ' 00:00:00-03')::timestamptz
            AND created_at <  ($2::date + 1)::date::timestamptz AT TIME ZONE 'America/Sao_Paulo'`,
        [userId, require('../utils/adDailyLimit').todayBr()]
      );

      if (recentSsv.rows.length === 0) {
        // Ainda sem confirmacao do Google. Nao e erro: o callback pode estar a caminho.
        // Registrar ajuda a diagnosticar SSV mal configurado no painel do AdMob, situacao em
        // que NENHUM credito acontece e o sintoma aparece exatamente aqui.
        console.log(`[Reward] Aguardando callback SSV do Google para user ${userId} (ip ${ip})`);
        return res.status(202).json({
          success: false,
          pending: true,
          code: 'SSV_PENDING',
          message: 'Aguardando confirmacao do anuncio. O saldo sera atualizado em instantes.',
          newBalance: balance,
          pointValues: POINT_VALUES,
          dailyLimit: 100,
          dailyCount: parseInt(dailyCount.rows[0].count, 10)
        });
      }

      const confirmed = recentSsv.rows[0];
      return res.json({
        success: true,
        verifiedBy: 'admob_ssv',
        pointsAwarded: confirmed.points_awarded,
        newBalance: balance,
        eventId: confirmed.id,
        pointValues: POINT_VALUES,
        dailyLimit: 100,
        dailyCount: parseInt(dailyCount.rows[0].count, 10)
      });
    }

    // ==========================================================================================
    // CAMINHO 'interstitial' / 'banner': SEM CREDITO DE PONTOS
    //
    // Estes formatos NAO possuem SSV no AdMob, portanto nao ha como provar que o anuncio
    // foi realmente assistido. Qualquer credito aqui seria exploravel por automacao.
    //
    // Decisao: interstitial e banner geram receita para o app (AdMob paga por impressao)
    // mas NAO creditam pontos ao usuario. Apenas anuncios rewarded (com SSV do Google)
    // geram pontos. Isso elimina 100% da superficie de ataque por automacao.
    //
    // O app continua chamando esta rota normalmente (para tracking), mas o servidor
    // responde com pointsAwarded: 0 sem tocar no ledger.
    // ==========================================================================================
    const balanceResult = await db.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [userId]
    );
    const currentBalance = parseInt(balanceResult.rows[0].balance, 10);

      const dailyCount = await db.query(
      `SELECT COUNT(*) as count FROM reward_events
        WHERE user_id = $1 AND ad_type = 'rewarded' AND ssv_verified = true
          AND created_at >= ($2 || ' 00:00:00-03')::timestamptz
          AND created_at <  ($2::date + INTERVAL '1 day')::timestamptz AT TIME ZONE 'America/Sao_Paulo'`,
      [userId, require('../utils/adDailyLimit').todayBr()]
    );
    // Responde sucesso (o app nao precisa saber que nao creditou)
    // Isso evita que o app mostre erro ao usuario apos assistir interstitial
    res.json({
      success: true,
      verifiedBy: 'no_credit',
      pointsAwarded: 0,
      newBalance: currentBalance,
      pointValues: POINT_VALUES,
      dailyLimit: 100,
      dailyCount: parseInt(dailyCount.rows[0].count, 10)
    });
  } catch (error) {
    console.error('Reward error:', error);
    res.status(500).json({ error: 'Failed to process reward' });
  }
});

// GET /api/points/table - Grade de valores e distribuicao de probabilidade
router.get('/table', async (req, res) => {
  try {
    res.json({
      success: true,
      pointValues: POINT_VALUES,
      distribution: getRewardDistribution()
    });
  } catch (error) {
    console.error('Points table error:', error);
    res.status(500).json({ error: 'Failed to get points table' });
  }
});

// GET /api/points/history - Get points history
router.get('/history', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = (page - 1) * limit;

    const result = await db.query(
      `SELECT id, amount, transaction_type, description, created_at 
       FROM points_ledger 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
      [req.user.userId, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) as total FROM points_ledger WHERE user_id = $1',
      [req.user.userId]
    );

    res.json({
      success: true,
      transactions: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        totalPages: Math.ceil(parseInt(countResult.rows[0].total) / limit)
      }
    });
  } catch (error) {
    console.error('History error:', error);
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// GET /api/points/stats - Get user reward stats
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await db.query(
      `SELECT 
        COALESCE(SUM(amount), 0) as total_balance,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_earned,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_spent,
        COUNT(CASE WHEN amount > 0 THEN 1 END) as total_rewards
       FROM points_ledger WHERE user_id = $1`,
      [req.user.userId]
    );

    const todayStats = await db.query(
      `SELECT 
        COALESCE(SUM(points_awarded), 0) as today_earned,
        COUNT(*) as today_views
       FROM reward_events 
       WHERE user_id = $1
         AND created_at >= ($2 || ' 00:00:00-03')::timestamptz
         AND created_at <  ($2::date + INTERVAL '1 day')::timestamptz AT TIME ZONE 'America/Sao_Paulo'`,
      [req.user.userId, require('../utils/adDailyLimit').todayBr()]
    );

    // Sistema de níveis visual (puramente cosmético)
    // Nível 1 = 50 anúncios, Nível 2 = 100, Nível 3 = 150, etc.
    const totalAdsWatched = parseInt(stats.rows[0].total_rewards) || 0;
    const adsPerLevel = 50;
    const currentLevel = Math.floor(totalAdsWatched / adsPerLevel);
    const adsInCurrentLevel = totalAdsWatched % adsPerLevel;
    const adsForNextLevel = adsPerLevel;

    res.json({
      success: true,
      stats: {
        balance: parseInt(stats.rows[0].total_balance),
        totalEarned: parseInt(stats.rows[0].total_earned),
        totalSpent: parseInt(stats.rows[0].total_spent),
        totalRewards: totalAdsWatched,
        todayEarned: parseInt(todayStats.rows[0].today_earned),
        todayViews: parseInt(todayStats.rows[0].today_views),
        level: currentLevel,
        levelProgress: adsInCurrentLevel,
        levelTarget: adsForNextLevel,
        totalAdsWatched: totalAdsWatched
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

module.exports = router;
