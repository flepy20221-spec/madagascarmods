require('dotenv').config();

// A validacao de segredos precisa acontecer antes de qualquer rota ser carregada.
// Em producao, este modulo aborta o processo se JWT_SECRET, JWT_REFRESH_SECRET ou
// APP_HMAC_SECRET estiverem ausentes, curtos ou iguais aos valores publicados no
// repositorio. (auditoria VULN-03 e VULN-04)
require('./config/secrets');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const usersRoutes = require('./routes/users');
const pointsRoutes = require('./routes/points');
const payoutRoutes = require('./routes/payout');
const withdrawalRoutes = require('./routes/withdrawals');
const adminRoutes = require('./routes/admin');
const configRoutes = require('./routes/config');
const pixRoutes = require('./routes/pix');
const pixWithdrawalRoutes = require('./routes/pix_withdrawals');
const ssvRoutes = require('./routes/ssv');
const adminPayoutKeysRoutes = require('./routes/admin_payout_keys');
const checkinRoutes = require('./routes/checkin');
const referralRoutes = require('./routes/referral');
const pushRoutes = require('./routes/push');
const missionsRoutes = require('./routes/missions');
const missionEvidenceRoutes = require('./routes/missionEvidence');
const myIpRoutes = require('./routes/myip');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Confianca no proxy
//
// O Railway coloca um proxy na frente da aplicacao. Sem esta configuracao,
// req.ip retorna o IP interno do proxy: todos os usuarios sao contabilizados como
// um unico cliente pelo rate limiter, e os IPs gravados em audit_log/reward_events
// ficam inuteis para investigacao de fraude. (auditoria VULN-10)
//
// O valor 1 confia em apenas um salto (o proxy do Railway), impedindo que o
// cliente injete IPs falsos empilhando entradas em X-Forwarded-For.
// ---------------------------------------------------------------------------
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());

// ---------------------------------------------------------------------------
// CORS
//
// Antes, sem ALLOWED_ORIGINS definida, a origem liberada era '*'. Como o app mobile
// nao depende de CORS (nao e um navegador), a permissao ampla so servia para permitir
// que qualquer site chamasse a API a partir do navegador da vitima. Agora o padrao e
// restritivo: sem ALLOWED_ORIGINS, apenas requests sem Origin (apps nativos) e o
// painel admin local passam. (auditoria VULN-12)
// ---------------------------------------------------------------------------
const allowedOrigins = [
  process.env.ALLOWED_ORIGINS,
  process.env.PUBLIC_ALLOWED_ORIGINS,
]
  .filter(Boolean)
  .flatMap(value => value.split(','))
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // Requests sem Origin: app nativo, curl, health check do Railway
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origem nao permitida pelo CORS'));
  },
  credentials: true
}));

// ---------------------------------------------------------------------------
// Corpo da requisicao
//
// O `verify` guarda o corpo BRUTO em req.rawBody. Isso e indispensavel para a
// validacao HMAC: o app assina exatamente os bytes que envia, e reserializar o
// objeto com JSON.stringify(req.body) produz uma string diferente (ordem de chaves,
// campos nulos, espacamento), invalidando assinaturas legitimas. (auditoria VULN-02)
//
// O limite de 100kb tambem evita que payloads gigantes consumam CPU no calculo do HMAC.
// ---------------------------------------------------------------------------
app.use(express.json({
  limit: '100kb',
  verify: (req, _res, buf) => {
    req.rawBody = buf && buf.length ? buf.toString('utf8') : '';
  }
}));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ---------------------------------------------------------------------------
// Rate limiting geral
//
// ESTE ERA O LIMITER QUE BLOQUEAVA O USUARIO EM PRODUCAO.
//
// A mensagem "Too many requests, please try again later." relatada pelo usuario vinha daqui,
// e nao do limiter de autenticacao: confirmado por header em producao, /api/config respondia
// com `ratelimit-limit: 300`. Como este middleware roda antes de todas as rotas de /api/ e
// contava por IP, ele era o teto mais baixo de toda a cadeia sob CGNAT.
//
// A aritmetica do bloqueio: cada abertura do aplicativo consome cerca de quatro requisicoes
// (/config/app, /auth/device e as chamadas de sessao). Trezentas por IP significam por volta
// de setenta aberturas por gateway de operadora em quinze minutos — numero alcancado por uso
// normal quando 137 aparelhos compartilham o mesmo IPv4, como foi medido.
//
// CORRECAO: a chave passa a ser o usuario autenticado, ou o aparelho quando a requisicao o
// identifica, com o IP apenas como ultimo recurso. `userOrTokenKey` ja resolvia o usuario a
// partir do JWT sem precisar validar assinatura; `deviceIdentifierFromBody` cobre o bootstrap,
// que acontece antes de existir token. O teto por IP sobe para 1200 porque, no caminho residual
// em que ele ainda se aplica (requisicao anonima e sem identificacao de aparelho), o bucket
// continua compartilhado por todo o CGNAT.
//
// Por que isso nao afrouxa a protecao: o objetivo deste limiter e conter flood de requisicoes,
// e contra flood a chave por usuario/aparelho e mais eficaz — um unico cliente em laco atinge
// o proprio teto sem consumir a cota de terceiros, que era precisamente o efeito colateral
// indesejado da contagem por IP.
// ---------------------------------------------------------------------------
const {
  userOrTokenKey,
  deviceIdentifierFromBody,
  adminApiLimiter,
} = require('./middleware/rateLimits');

const GENERAL_LIMIT_PER_IDENTITY = 300;
const GENERAL_LIMIT_PER_IP = 1200;

/**
 * Chave do limiter geral: usuario > aparelho > IP.
 *
 * `userOrTokenKey` devolve `ip:<endereco>` quando nao consegue identificar o usuario. Esse
 * retorno e o sinal de que ainda ha uma chance de identificar o aparelho pelo corpo da
 * requisicao, caminho usado pelo bootstrap.
 */
function generalLimiterKey(req) {
  const identity = userOrTokenKey(req);
  if (!identity.startsWith('ip:')) return identity;

  const deviceKey = deviceIdentifierFromBody(req);
  return deviceKey || identity;
}

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: (req) => (
    generalLimiterKey(req).startsWith('ip:')
      ? GENERAL_LIMIT_PER_IP
      : GENERAL_LIMIT_PER_IDENTITY
  ),
  keyGenerator: generalLimiterKey,
  standardHeaders: true,
  legacyHeaders: false,
  // Mensagem em portugues e com codigo, como no restante da API. A versao anterior era a
  // string padrao da biblioteca, em ingles e sem codigo: o aplicativo nao tinha como
  // distinguir este bloqueio de qualquer outro 429 e exibia texto cru ao usuario.
  message: {
    error: 'Muitas requisicoes. Aguarde alguns minutos e tente novamente.',
    code: 'GENERAL_RATE_LIMIT'
  }
});

// ---------------------------------------------------------------------------
// Limite das rotas de autenticacao
//
// O limiter mora em src/middleware/rateLimits.js e agora conta POR APARELHO. A justificativa
// completa da troca de chave esta documentada la.
//
// ESTE ARQUIVO NAO O APLICA MAIS.
//
// Havia um `app.use('/api/auth/', authLimiter)` aqui, e as rotas /device, /login e /register
// ja declaram o MESMO limiter na propria cadeia. O efeito era invisivel no codigo e grave na
// pratica: express-rate-limit incrementa o contador uma vez por passagem, de modo que cada
// requisicao consumia DOIS hits do mesmo bucket. O teto efetivo era a metade do configurado
// — 120 por IP viravam 60 reais.
//
// Reproduzido em laboratorio com a mesma versao da biblioteca (7.5.1) e limite 4:
//
//     req 1 -> 200, remaining=2      (dois hits consumidos)
//     req 2 -> 200, remaining=0
//     req 3 -> 429                   (bloqueio na terceira, nao na quinta)
//
// A biblioteca detecta a situacao pela validacao `singleCount` e registra ERR_ERL_DOUBLE_COUNT
// no console, sem interromper a requisicao — por isso o defeito nunca apareceu como erro.
//
// A aplicacao permanece apenas nas rotas (routes/auth.js), que e o lugar correto: /auth/refresh
// e /auth/logout nao precisam do limiter de tentativa de acesso, e aplicar em '/api/auth/'
// inteiro os incluia sem necessidade.
// ---------------------------------------------------------------------------

// O callback SSV vem dos servidores do Google e nao deve ser limitado por IP:
// um unico IP do Google concentra os callbacks de todos os usuarios.
// O webhook de validacao de saques da Asaas tambem vem da infraestrutura do Asaas
// e nao deve ser limitado por IP (uma unica origem concentra todas as validacoes).
app.use('/api/', (req, res, next) => {
  // O painel tem polling próprio e usa autenticação administrativa; isolá-lo
  // impede que a atividade do admin consuma a cota do aplicativo móvel.
  // Login e setup têm limitador de força bruta próprio e não passam duas vezes por aqui.
  if (req.path === '/admin/login' || req.path === '/admin/setup') return next();
  if (req.path.startsWith('/admin/')) return adminApiLimiter(req, res, next);
  if (req.path.startsWith('/ssv/')) return next();
  if (req.path.startsWith('/asaas/')) return next();
  // O portal envia imagens multipart e possui limitadores proprios por token nas
  // rotas /session e /submit. Passar antes pelo bucket geral por IP fazia usuarios
  // sob o mesmo CGNAT de operadora compartilharem a cota; se a cota terminasse
  // enquanto o celular ainda transmitia o arquivo, alguns navegadores Android
  // exibiam apenas "Failed to fetch" em vez do JSON 429. As rotas continuam
  // protegidas pelos limitadores dedicados em missionEvidence.js.
  if (
    req.path === '/mission-evidence/session'
    || req.path === '/mission-evidence/submit'
  ) return next();
  return generalLimiter(req, res, next);
});

/**
 * Limites de rede efetivamente vigentes neste processo.
 *
 * Lidos dos proprios modulos que os aplicam, e nao de process.env, porque a diferenca
 * entre o valor CONFIGURADO e o valor EM USO (quando o piso de seguranca recusa um valor
 * baixo herdado) e justamente a informacao que faltava para diagnosticar o bloqueio de
 * cadastro em producao. Nao expoe segredo algum: sao apenas limiares operacionais.
 */
function effectiveNetworkLimits() {
  try {
    const { loginIpLimits } = require('./middleware/botDetection');
    const { authRateLimit } = require('./middleware/rateLimits');
    return {
      // Trava de primeira linha contra automacao: taxa de cadastros em janela curta.
      // Substituiu o teto acumulado de 24h, que gerava falso positivo em massa sob CGNAT.
      ipBurstLimit: authRoutes.limits?.ipBurstLimit ?? null,
      ipBurstObserveLimit: authRoutes.limits?.ipBurstObserveLimit ?? null,
      ipBurstWindowMinutes: authRoutes.limits?.ipBurstWindowMinutes ?? null,
      ipBurstConfigured: authRoutes.limits?.ipBurstConfigured ?? null,
      // Rede de seguranca contra abuso sustentado.
      accountsPerIp24h: authRoutes.limits?.maxAccountsPerIp24h ?? null,
      accountsPerIp24hConfigured: authRoutes.limits?.configuredValue ?? null,
      accountsPerIp24hFloor: authRoutes.limits?.maxAccountsPerIp24hFloor ?? null,
      loginIpSoftLimit: loginIpLimits?.softLimit ?? null,
      loginIpHardLimit: loginIpLimits?.hardLimit ?? null,
      // Limiter das rotas de autenticacao. `authKeyedBy` e o campo que faltava no diagnostico
      // anterior: sem ele, um limite de 30 exibido aqui era indistinguivel entre "30 por
      // aparelho" (politica atual, apertada e isolada) e "30 por IP" (politica antiga, que
      // derrubaria toda uma operadora). O numero sozinho nao descreve a regra.
      authKeyedBy: authRateLimit?.keyedBy ?? null,
      authRequestsPer15min: authRateLimit?.max ?? null,
      authRequestsPer15minConfigured: authRateLimit?.configuredValue ?? null,
      authIpFallbackPer15min: authRateLimit?.ipFallback?.max ?? null,
      // Limiter geral de /api/, que foi a origem real do "Too many requests" relatado.
      generalPerIdentityPer15min: GENERAL_LIMIT_PER_IDENTITY,
      generalPerIpPer15min: GENERAL_LIMIT_PER_IP,
    };
  } catch (_) {
    // O health check nunca deve falhar por causa de um campo informativo.
    return null;
  }
}

// ============ HEALTH CHECK AVANÇADO ============
// Verifica conexão com o banco de dados e retorna status detalhado.
app.get('/health', async (req, res) => {
  const db = require('./models/db');
  let dbStatus = 'unknown';
  let dbLatency = 0;
  try {
    const start = Date.now();
    await db.query('SELECT 1');
    dbLatency = Date.now() - start;
    dbStatus = 'connected';
  } catch (err) {
    dbStatus = 'disconnected';
  }

  const status = dbStatus === 'connected' ? 'healthy' : 'degraded';
  const httpCode = dbStatus === 'connected' ? 200 : 503;

  res.status(httpCode).json({
    status,
    // A versao vinha de um literal '1.5.2' escrito aqui, que envelheceu no arquivo e passou
    // a mentir sobre o que estava em producao. Agora vem do package.json, atualizado junto
    // com o codigo, e continua sobrescrevivel por APP_VERSION.
    version: process.env.APP_VERSION || require('../package.json').version,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    database: {
      status: dbStatus,
      latencyMs: dbLatency
    },
    // Limites de rede EFETIVAMENTE vigentes no processo. Sem isto, descobrir que uma variavel
    // de ambiente antiga estava sobrescrevendo o padrao do codigo exigia ler o banco: o
    // sintoma aparecia no aplicativo do usuario e nao havia como inspecionar o valor em uso.
    networkLimits: effectiveNetworkLimits(),
    memory: {
      heapUsedMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      rssMB: Math.round(process.memoryUsage().rss / 1024 / 1024)
    }
  });
});

// ============ MIDDLEWARE DE VERSÃO MÍNIMA ============
// Bloqueia versões antigas do app que podem ter bugs ou vulnerabilidades.
// A versão mínima é controlada via system_config (chave: min_app_version).
const versionCheckCache = { minVersion: null, lastCheck: 0 };

app.use('/api/', async (req, res, next) => {
  // Não aplicar a rotas admin, SSV, health, ou config
  if (req.path.startsWith('/admin') || req.path.startsWith('/ssv/') || 
      req.path.startsWith('/config/') || req.path.startsWith('/auth/')) {
    return next();
  }

  const clientVersion = req.headers['x-app-version'];
  if (!clientVersion) return next(); // Apps antigos sem header passam (backward compat)

  // Cache da versão mínima por 5 minutos
  const now = Date.now();
  if (!versionCheckCache.minVersion || now - versionCheckCache.lastCheck > 5 * 60 * 1000) {
    try {
      const db = require('./models/db');
      const result = await db.query("SELECT value FROM system_config WHERE key = 'min_app_version'");
      if (result.rows.length > 0) {
        versionCheckCache.minVersion = JSON.parse(result.rows[0].value);
      } else {
        versionCheckCache.minVersion = '0.0.0';
      }
      versionCheckCache.lastCheck = now;
    } catch {
      return next(); // Fail-open
    }
  }

  const minVersion = versionCheckCache.minVersion;
  if (minVersion && minVersion !== '0.0.0') {
    // Comparação semver simples
    const parseVer = (v) => (v || '0.0.0').split('.').map(Number);
    const client = parseVer(clientVersion);
    const min = parseVer(minVersion);
    
    const isOutdated = client[0] < min[0] || 
      (client[0] === min[0] && client[1] < min[1]) ||
      (client[0] === min[0] && client[1] === min[1] && client[2] < min[2]);

    if (isOutdated) {
      return res.status(426).json({
        error: 'Versão do app desatualizada. Atualize para continuar.',
        code: 'APP_VERSION_OUTDATED',
        minVersion,
        currentVersion: clientVersion
      });
    }
  }

  next();
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/points', pointsRoutes);
app.use('/api/payout-destinations', payoutRoutes);
app.use('/api/withdrawals', withdrawalRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin', adminPayoutKeysRoutes);
app.use('/api/config', configRoutes);
app.use('/api/pix', pixRoutes);
app.use('/api/pix-withdrawals', pixWithdrawalRoutes);
app.use('/api/ssv', ssvRoutes);
app.use('/api/checkin', checkinRoutes);
app.use('/api/referral', referralRoutes);
app.use('/api/push', pushRoutes);
app.use('/api/mission-evidence', missionEvidenceRoutes);

// Limpeza diaria de tokens push mortos (03:30 Brasilia). Sem mexer no app:
// tokens que o FCM reporta como invalidos (desinstalacao, reinstalacao,
// aparelho trocado) sao desativados automaticamente, mantendo o contador de
// "dispositivos ativos" do painel fiel e as campanhas com menos falhas.
const { startDailyJob } = require('./services/pushTokenCleanup');
startDailyJob();

// Exclusao automatica de contas abandonadas (04:00 Brasilia): conta sem login
// ha 20+ dias (e sem saque pago/processando) e excluida com registro em
// audit_log (ACCOUNT_DELETED_AUTO), no maximo 50 exclusoes por dia.
const { scheduleJob: scheduleAbandonedJob } = require('./services/abandonedAccounts');
scheduleAbandonedJob();

// Revalida uma unica vez os destinos FaucetPay que ficaram pendentes antes da
// aprovacao automatica. A rotina apenas consulta /checkaddress: nao cria ou
// processa pagamentos e deixa indisponibilidades externas para nova tentativa.
const { runOnStartup: revalidatePendingPayoutsOnStartup } = require('./services/payoutDestinationAutoApproval');
revalidatePendingPayoutsOnStartup();

app.use('/api/missions', missionsRoutes);
app.use('/api/', myIpRoutes);

// Webhook de validacao de saques da Asaas (validacao automatica sem SMS/App):
// o Asaas POSTa aqui ~5s apos cada transferencia via API; o endpoint valida
// o token e o payload contra a fila de pendencias e responde APPROVED/REFUSED.
const asaasWebhookRoutes = require('./routes/asaas_webhook');
app.use('/api/', asaasWebhookRoutes);

// Error handler
app.use((err, req, res, next) => {
  if (err && err.message === 'Origem nao permitida pelo CORS') {
    return res.status(403).json({ error: 'Origem nao permitida', code: 'CORS_DENIED' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Corpo da requisicao muito grande', code: 'PAYLOAD_TOO_LARGE' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'JSON invalido', code: 'INVALID_JSON' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`MadagascarMods Backend running on port ${PORT}`);
});

module.exports = app;
