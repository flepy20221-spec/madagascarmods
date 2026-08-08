/**
 * CashPix — Limites de requisicao por usuario
 *
 * Motivacao (auditoria de seguranca, VULN-10):
 * O unico controle existente era global e por IP: 100 requests / 15 min em /api/ e
 * 10 / 15 min em /api/auth/. Isso e insuficiente por dois motivos:
 *
 *   1. Chave por IP e facil de contornar. Num celular, basta alternar entre dados moveis
 *      e Wi-Fi, ou usar VPN, para reiniciar a contagem. E o inverso tambem e um problema:
 *      atras do proxy do Railway, sem 'trust proxy', varios usuarios legitimos podem
 *      compartilhar o mesmo IP aparente e se bloquearem mutuamente.
 *   2. Nao havia nenhum limite especifico nas rotas que movimentam valor
 *      (/points/reward, /withdrawals/request), justamente as que precisam.
 *
 * Aqui os limites sao aplicados por ID de usuario autenticado (com o IP como fallback
 * quando nao ha token), sobre a janela real de negocio de cada rota.
 */
const rateLimit = require('express-rate-limit');

/**
 * Chave de contagem: prioriza o usuario autenticado; cai para o IP quando anonimo.
 *
 * Observacao: authenticateToken roda DEPOIS do limiter na cadeia de /points/reward
 * (para nao gastar consulta ao banco em request abusiva), entao aqui o req.user pode
 * ainda nao existir. Nesse caso o proprio token e usado como chave, o que ja e
 * suficiente para individualizar a conta sem precisar validar a assinatura.
 */
function userOrTokenKey(req) {
  if (req.user?.userId) return `u:${req.user.userId}`;

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    // O payload do JWT identifica a conta sem necessidade de verificar a assinatura.
    // Um token forjado nao passaria pelo authenticateToken logo em seguida.
    try {
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64').toString('utf8')
      );
      if (payload?.userId) return `u:${payload.userId}`;
    } catch (_) { /* token malformado: usa IP */ }
  }

  return `ip:${req.ip}`;
}

/**
 * Limite da rota de pontuacao.
 *
 * O limite diario de negocio e de 100 anuncios rewarded, com intervalo minimo de 10s
 * entre eles. Em 10 minutos, um usuario legitimo nao consegue completar mais que ~60
 * exibicoes. O teto de 40 por 10 min acomoda uso intenso e retries de rede, mas corta
 * qualquer script em laco.
 */
const rewardLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 40,
  keyGenerator: userOrTokenKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas solicitacoes de recompensa. Aguarde alguns minutos.',
    code: 'REWARD_RATE_LIMIT'
  }
});

/**
 * Polling leve do status SSV por sessao.
 *
 * O app usa backoff curto durante poucos segundos depois de fechar o anuncio.
 * Trinta consultas por minuto acomodam variacao de rede sem permitir loops
 * indefinidos que pressionem PostgreSQL ou enumerem sessoes em volume.
 */
const rewardStatusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: userOrTokenKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas consultas de confirmacao. Aguarde alguns segundos.',
    code: 'REWARD_STATUS_RATE_LIMIT'
  }
});

/**
 * Limite das rotas de saque (FaucetPay e PIX).
 * Um usuario legitimo faz poucos saques por hora; 5 e folgado.
 */
const withdrawalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: userOrTokenKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas solicitacoes de saque. Aguarde antes de tentar novamente.',
    code: 'WITHDRAWAL_RATE_LIMIT'
  }
});

/**
 * Limite do login administrativo, por IP.
 * O login admin usa senha, portanto e alvo de forca bruta.
 */
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    error: 'Muitas tentativas de login. Aguarde 15 minutos.',
    code: 'ADMIN_LOGIN_RATE_LIMIT'
  }
});

/**
 * Limite do cadastro de dados de pagamento (PIX/FaucetPay).
 * Evita uso do endpoint para enumerar ou testar CPFs em massa.
 */
const payoutSetupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: userOrTokenKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas tentativas de cadastro de pagamento. Aguarde um pouco.',
    code: 'PAYOUT_RATE_LIMIT'
  }
});

/**
 * Limite das rotas de autenticacao do app (/auth/login e /auth/register), por IP.
 *
 * O login do app nao usa senha (ver VULN-05 em routes/auth.js), portanto o abuso possivel
 * aqui nao e forca bruta de credencial, e sim criacao de contas em massa e sondagem de
 * e-mails. O valor precisa ser tolerante: por causa do CGNAT das operadoras moveis, muitos
 * usuarios legitimos compartilham o mesmo IP aparente.
 *
 * CORRECAO: o valor 20 ainda era baixo demais para CGNAT. Um unico IP de operadora atende
 * milhares de aparelhos; vinte requisicoes de login/cadastro em quinze minutos e trafego
 * normal, e o estouro bloqueava usuario legitimo. Elevado e tornado configuravel, alinhado
 * ao AUTH_RATE_LIMIT_MAX de src/index.js. A contencao de farm de contas continua sendo
 * feita por aparelho (indices unicos de device_account_key e device_id).
 */
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX) > 0
  ? Number(process.env.AUTH_RATE_LIMIT_MAX)
  : 120;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas tentativas de acesso. Aguarde alguns minutos.',
    code: 'AUTH_RATE_LIMIT'
  }
});

/**
 * Limite da rota de configuração do app.
 * O app busca config na abertura e a cada reload. 10 por minuto é generoso.
 */
const configLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: userOrTokenKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas consultas de configuração. Aguarde.',
    code: 'CONFIG_RATE_LIMIT'
  }
});

module.exports = {
  rewardLimiter,
  rewardStatusLimiter,
  withdrawalLimiter,
  adminLoginLimiter,
  payoutSetupLimiter,
  authLimiter,
  configLimiter,
  userOrTokenKey,
};
