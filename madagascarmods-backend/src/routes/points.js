const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');
const { antifraudMiddleware, rewardFraudDetection, clientIp } = require('../middleware/antiFraud');
const { rewardLimiter } = require('../middleware/rateLimits');
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
            AND created_at > NOW() - INTERVAL '24 hours'`,
        [userId]
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
    // CAMINHO 'interstitial' / 'banner': credito pelo servidor, sem prova criptografica
    //
    // Estes formatos nao possuem SSV no AdMob. O credito depende da palavra do cliente, o que
    // nao pode ser eliminado — apenas contido. As barreiras aplicadas sao: assinatura HMAC do
    // corpo, limite por usuario, intervalo minimo entre eventos, teto diario e valor baixo por
    // exibicao. Se estes formatos passarem a valer mais pontos, o abuso volta a compensar; a
    // recomendacao registrada no relatorio e mante-los com valor simbolico.
    // ==========================================================================================
    const configResult = await db.query(
      "SELECT key, value FROM system_config WHERE key IN ('reward_points_interstitial', 'reward_points_banner')"
    );

    const config = {};
    configResult.rows.forEach(row => {
      try {
        config[row.key] = JSON.parse(row.value);
      } catch (err) {
        config[row.key] = row.value;
      }
    });

    const pointsToAward = ad_type === 'interstitial'
      ? Number(config.reward_points_interstitial) || 0
      : Number(config.reward_points_banner) || 0;

    if (pointsToAward <= 0) {
      return res.status(400).json({ error: 'This ad type does not award points' });
    }

    // Intervalo minimo entre exibicoes do mesmo tipo.
    const lastReward = await db.query(
      `SELECT created_at FROM reward_events
        WHERE user_id = $1 AND ad_type = $2
        ORDER BY created_at DESC LIMIT 1`,
      [userId, ad_type]
    );

    if (lastReward.rows.length > 0) {
      const diffSeconds = (Date.now() - new Date(lastReward.rows[0].created_at).getTime()) / 1000;
      const minInterval = 30;
      if (diffSeconds < minInterval) {
        return res.status(429).json({
          error: 'Too soon since last reward',
          retryAfter: Math.ceil(minInterval - diffSeconds)
        });
      }
    }

    // Teto diario.
    const dailyCount = await db.query(
      `SELECT COUNT(*) as count FROM reward_events
        WHERE user_id = $1 AND ad_type = $2 AND created_at > NOW() - INTERVAL '24 hours'`,
      [userId, ad_type]
    );

    const dailyLimit = 50;
    const currentDailyCount = parseInt(dailyCount.rows[0].count, 10);
    if (currentDailyCount >= dailyLimit) {
      return res.status(429).json({
        error: 'Limite diário atingido. Volte amanhã!',
        code: 'DAILY_LIMIT',
        dailyLimit,
        dailyCount: currentDailyCount
      });
    }

    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      // Serializa os creditos deste usuario. Sem o lock, varias requisicoes simultaneas
      // passariam juntas pelas checagens de intervalo e de teto diario acima (todas leem o
      // estado antes de qualquer escrita) e o limite seria ultrapassado.
      await client.query('SELECT pg_advisory_xact_lock(9412, hashtext($1))', [userId]);

      // Revalidacao do teto diario DENTRO do lock.
      const recheck = await client.query(
        `SELECT COUNT(*) as count FROM reward_events
          WHERE user_id = $1 AND ad_type = $2 AND created_at > NOW() - INTERVAL '24 hours'`,
        [userId, ad_type]
      );
      if (parseInt(recheck.rows[0].count, 10) >= dailyLimit) {
        await client.query('ROLLBACK');
        return res.status(429).json({
          error: 'Limite diário atingido. Volte amanhã!',
          code: 'DAILY_LIMIT',
          dailyLimit,
          dailyCount: parseInt(recheck.rows[0].count, 10)
        });
      }

      const eventId = uuidv4();
      await client.query(
        `INSERT INTO reward_events (id, user_id, ad_type, ad_network, ad_unit_id, points_awarded, ssv_verified, device_id, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8)`,
        [eventId, userId, ad_type, ad_network || 'admob', ad_unit_id || null, pointsToAward, req.body.device_id || null, ip]
      );

      const ledgerId = uuidv4();
      await client.query(
        `INSERT INTO points_ledger (id, user_id, amount, transaction_type, reference_id, description)
         VALUES ($1, $2, $3, 'REWARD', $4, $5)`,
        [ledgerId, userId, pointsToAward, eventId, `${ad_type} ad reward`]
      );

      await client.query('COMMIT');

      const balanceResult = await db.query(
        'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
        [userId]
      );

      res.json({
        success: true,
        verifiedBy: 'server_limits',
        pointsAwarded: pointsToAward,
        newBalance: parseInt(balanceResult.rows[0].balance, 10),
        eventId,
        pointValues: POINT_VALUES,
        dailyLimit,
        dailyCount: currentDailyCount + 1
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
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
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
      [req.user.userId]
    );

    res.json({
      success: true,
      stats: {
        balance: parseInt(stats.rows[0].total_balance),
        totalEarned: parseInt(stats.rows[0].total_earned),
        totalSpent: parseInt(stats.rows[0].total_spent),
        totalRewards: parseInt(stats.rows[0].total_rewards),
        todayEarned: parseInt(todayStats.rows[0].today_earned),
        todayViews: parseInt(todayStats.rows[0].today_views)
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

module.exports = router;
