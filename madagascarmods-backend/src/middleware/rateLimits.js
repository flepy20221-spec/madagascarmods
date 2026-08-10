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
const {
  normalizeDeviceAccountKey,
  normalizeAndroidIdKey,
} = require('../utils/deviceIdentity');

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

// ============================================================================================
// LIMITE DAS ROTAS DE AUTENTICACAO DO APP — CONTAGEM POR APARELHO, NAO POR IP
//
// O QUE ESTAVA ERRADO, E POR QUE TROCAR O NUMERO NAO RESOLVIA
//
// Este limiter contava por IP. Sob CGNAT das operadoras moveis, centenas de aparelhos
// compartilham um mesmo IPv4 publico: medido em producao, 273 das 604 contas ativas estavam
// em apenas dois IPs (136 e 137 aparelhos cada). O teto por IP e fixo, mas a demanda por IP
// cresce junto com a base instalada — cada usuario novo consumia a cota dos vizinhos. Projetado
// sobre a taxa de crescimento observada, qualquer valor escolhido estoura em semanas:
//
//     hoje       604 contas | 137 aparelhos no IP mais cheio |   411 req/15min
//     1 semana  1.437       | 326                            |   978
//     2 semanas 2.270       | 515                            | 1.545
//     4 semanas 3.936       | 893                            | 2.678
//
// Elevar o teto e uma corrida que o aplicativo sempre perde. O defeito estava na CHAVE de
// contagem, nao no limite.
//
// O QUE PASSA A VALER
//
// A chave e o aparelho, extraida do corpo da requisicao (device_account_key, ou o alias
// android_id_key, ou o device_id legado). O app envia esses valores no bootstrap, ANTES de
// qualquer autenticacao, o que torna a chave disponivel exatamente onde antes so havia o IP.
// O limite passa a significar "quantas vezes ESTE aparelho pode tentar entrar", uma grandeza
// que nao muda quando a base vai a dez mil usuarios.
//
// O ganho e duplo, e o de seguranca e o mais relevante: por nao ser compartilhado, o teto pode
// ser MUITO mais apertado. Antes um atacante dispunha de 120 tentativas por IP e as reiniciava
// alternando modo aviao; agora tem 30 por aparelho, e trocar de aparelho fisico custa caro.
//
// O QUE NAO MUDA (e por que a rota continua protegida sem o IP aqui)
//
//   - MAX_ACCOUNTS_PER_DEVICE = 1 com pg_advisory_xact_lock: uma conta por aparelho, atomico
//   - indices unicos de device_account_key e device_id: o banco recusa duplicata
//   - IP_BURST_LIMIT (40 aparelhos novos / 10 min) e MAX_ACCOUNTS_PER_IP_24H (500) em
//     routes/auth.js: continuam por IP de proposito, porque medem CRIACAO de conta e nao
//     acesso — nao punem quem ja tem conta
//   - loginBotDetection (observacao em 40, bloqueio em 200 aparelhos distintos por IP)
//   - antifraudMiddleware: assinatura HMAC e impressao da requisicao
//
// Alem disso, o login do aplicativo nao usa senha (VULN-05 em routes/auth.js). Nao existe
// forca bruta de credencial a conter nesta rota, que e a razao classica para limitar login
// por IP. O limite por IP era o unico dos controles acima que punia usuario legitimo por causa
// do vizinho de CGNAT.
// ============================================================================================

// Teto por APARELHO. Estreito de proposito: a cota nao e compartilhada com ninguem.
// Uso legitimo consome poucas unidades — o app faz um bootstrap por abertura, com retry
// eventual de rede. Trinta acomoda reinstalacao, troca de rede e reabertura repetida.
const DEFAULT_DEVICE_AUTH_LIMIT = 30;
const MIN_DEVICE_AUTH_LIMIT = 10;

// Teto do FALLBACK por IP, usado somente quando a requisicao nao traz identificacao de
// aparelho (builds antigos, requisicao malformada, sondagem direta da API). Precisa continuar
// tolerante ao CGNAT: aqui o bucket volta a ser compartilhado por muitos aparelhos, e um valor
// baixo reproduziria o bloqueio em massa que esta correcao existe para eliminar.
const DEFAULT_AUTH_IP_FALLBACK_LIMIT = 600;
const MIN_AUTH_IP_FALLBACK_LIMIT = 300;

/**
 * Resolve um limite vindo do ambiente respeitando um piso de seguranca.
 *
 * Mesma disciplina ja adotada em routes/auth.js e middleware/botDetection.js: uma variavel
 * de ambiente herdada de uma configuracao antiga tem precedencia sobre o padrao do codigo e
 * pode reintroduzir um defeito corrigido sem aparecer em nenhum diff. Abaixo do piso o valor
 * e recusado, com aviso no log de boot.
 */
function resolveLimit(envName, defaultValue, minimumValue) {
  const raw = process.env[envName];
  const parsed = Number(raw);

  if (!raw || !Number.isFinite(parsed) || parsed <= 0) return defaultValue;

  if (parsed < minimumValue) {
    console.warn(
      `[RateLimits] ${envName}=${raw} esta abaixo do piso de seguranca (${minimumValue}) `
      + `e foi ignorado. Valor em uso: ${minimumValue}.`
    );
    return minimumValue;
  }

  return parsed;
}

const DEVICE_AUTH_RATE_LIMIT_MAX = resolveLimit(
  'DEVICE_AUTH_RATE_LIMIT_MAX',
  DEFAULT_DEVICE_AUTH_LIMIT,
  MIN_DEVICE_AUTH_LIMIT
);

// AUTH_RATE_LIMIT_MAX permanece com o nome antigo por compatibilidade com a variavel ja
// configurada no Railway, mas passou a governar APENAS o fallback por IP. O piso subiu
// junto: o valor que fazia sentido para um bucket por aparelho seria destrutivo num bucket
// compartilhado por CGNAT.
const AUTH_IP_FALLBACK_LIMIT = resolveLimit(
  'AUTH_RATE_LIMIT_MAX',
  DEFAULT_AUTH_IP_FALLBACK_LIMIT,
  MIN_AUTH_IP_FALLBACK_LIMIT
);

/**
 * Extrai a identificacao do aparelho do corpo da requisicao de autenticacao.
 *
 * Ordem de preferencia, da ancora mais estavel para a menos estavel:
 *   1. device_account_key — hash com escopo do app, presente em todo build 1.6.0+
 *   2. android_id_key     — alias sem numero de versao no escopo (build 1.7.4+)
 *   3. legacy_device_id    — identificador aleatorio das versoes anteriores a 1.6.0
 *
 * Retorna null quando nenhuma delas esta presente ou valida. Nesse caso o chamador aplica
 * o fallback por IP: nenhum build antigo para de funcionar por causa desta mudanca.
 *
 * NOTA DE SEGURANCA: um cliente adulterado pode enviar uma chave inventada a cada requisicao
 * e assim obter uma cota nova por tentativa. Isso NAO e uma regressao em relacao ao desenho
 * anterior — trocar de IP pelo modo aviao produzia o mesmo efeito, com menos esforco. E, ao
 * contrario do IP, a chave inventada nao ajuda o atacante a chegar a uma conta: a criacao
 * exige passar por MAX_ACCOUNTS_PER_DEVICE, pelos indices unicos e pela trava de rajada por
 * IP, todos preservados. O limitador aqui protege a rota contra flood, e essa funcao ele
 * cumpre para o cliente honesto — que e quem sofria o bloqueio indevido.
 */
function deviceIdentifierFromBody(req) {
  const body = req.body;
  if (!body || typeof body !== 'object') return null;

  const accountKey = normalizeDeviceAccountKey(body.device_account_key);
  if (accountKey) return `dev:${accountKey}`;

  const androidIdKey = normalizeAndroidIdKey(body.android_id_key);
  if (androidIdKey) return `aid:${androidIdKey}`;

  // O device_id legado nao tem formato fixo (era um UUID gerado no cliente). Exige tamanho
  // minimo para nao transformar valores triviais como "1" em chave de bucket.
  if (typeof body.legacy_device_id === 'string') {
    const legacy = body.legacy_device_id.trim();
    if (legacy.length >= 8) return `leg:${legacy.slice(0, 128)}`;
  }

  if (typeof body.device_id === 'string') {
    const deviceId = body.device_id.trim();
    if (deviceId.length >= 8) return `leg:${deviceId.slice(0, 128)}`;
  }

  return null;
}

/**
 * Chave de contagem das rotas de autenticacao do app.
 *
 * Prefixos distintos ('dev:', 'aid:', 'leg:', 'ip:') garantem que os espacos de nome nunca
 * colidam: um device_id legado nunca cai no mesmo bucket de um IP, mesmo que os textos
 * coincidissem.
 */
function deviceOrIpKey(req) {
  return deviceIdentifierFromBody(req) || `ip:${req.ip}`;
}

/**
 * Limiter das rotas de autenticacao do aplicativo (/auth/device, /auth/login, /auth/register).
 *
 * Um unico limiter atende os dois casos, com tetos diferentes conforme a chave resolvida:
 * requisicao identificada por aparelho recebe o teto estreito; requisicao sem identificacao
 * recebe o teto tolerante do fallback por IP.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: (req) => (
    deviceIdentifierFromBody(req) === null
      ? AUTH_IP_FALLBACK_LIMIT
      : DEVICE_AUTH_RATE_LIMIT_MAX
  ),
  keyGenerator: deviceOrIpKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas tentativas de acesso deste aparelho. Aguarde alguns minutos.',
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
  // Exportadas para teste e para reuso por outros limiters que rodem antes da autenticacao.
  deviceOrIpKey,
  deviceIdentifierFromBody,
  // Reportado pelo /health: valores efetivos apos a aplicacao dos pisos de seguranca.
  //
  // `keyedBy` existe para que o diagnostico em producao mostre a informacao que faltava no
  // incidente anterior: nao apenas QUANTO e o limite, mas SOBRE O QUE ele conta. Um limite de
  // 30 por aparelho e um de 30 por IP sao politicas radicalmente diferentes com o mesmo numero.
  authRateLimit: {
    keyedBy: 'device_account_key',
    max: DEVICE_AUTH_RATE_LIMIT_MAX,
    floor: MIN_DEVICE_AUTH_LIMIT,
    windowMinutes: 15,
    configuredValue: process.env.DEVICE_AUTH_RATE_LIMIT_MAX || null,
    ipFallback: {
      max: AUTH_IP_FALLBACK_LIMIT,
      floor: MIN_AUTH_IP_FALLBACK_LIMIT,
      configuredValue: process.env.AUTH_RATE_LIMIT_MAX || null,
    },
  },
};
