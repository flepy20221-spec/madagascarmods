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
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : [];

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

// Rate limiting geral (por IP). Limites por usuario nas rotas sensiveis
// ficam em src/middleware/rateLimits.js.
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts, please try again later.' }
});

// O callback SSV vem dos servidores do Google e nao deve ser limitado por IP:
// um unico IP do Google concentra os callbacks de todos os usuarios.
app.use('/api/', (req, res, next) => {
  if (req.path.startsWith('/ssv/')) return next();
  return generalLimiter(req, res, next);
});
app.use('/api/auth/', authLimiter);

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
    version: process.env.APP_VERSION || '1.5.2',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    database: {
      status: dbStatus,
      latencyMs: dbLatency
    },
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
