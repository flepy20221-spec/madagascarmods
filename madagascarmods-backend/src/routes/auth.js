/**
 * CashPix — Rotas de autenticacao do aplicativo
 *
 * ============================================================================================
 * CORRECAO DE AUTENTICACAO SEM CREDENCIAL (auditoria VULN-05)
 *
 * Comportamento anterior: POST /api/auth/login exigia APENAS o e-mail. Quem soubesse o
 * e-mail de outra pessoa entrava na conta dela e sacava o saldo. E qualquer e-mail inedito
 * criava uma conta nova automaticamente, sem limite — a base perfeita para farm de contas.
 *
 * Restricao real encontrada no aplicativo:
 * A tela de login (email_input_screen.dart) possui um unico campo, o e-mail. O
 * device_service.dart nao armazena senha, PIN ou segredo algum. Exigir senha no servidor
 * agora deixaria 100% da base instalada sem conseguir entrar, inclusive quem tem saldo.
 *
 * Mitigacao adotada — vinculo de dispositivo (device binding):
 *   1. A conta e vinculada ao primeiro device_id que a utilizar.
 *   2. Login com e-mail existente a partir de OUTRO dispositivo e recusado (403), a menos
 *      que a conta nao tenha saldo nem historico de saque (troca de aparelho legitima de
 *      usuario novo) ou que um admin tenha liberado a migracao.
 *   3. O numero de contas por dispositivo e por IP passa a ser limitado, cortando o farm.
 *   4. O device_id passa a ser obrigatorio: sem ele nao ha como aplicar o vinculo.
 *
 * Isso preserva a experiencia de "entrar so com e-mail" e, ao mesmo tempo, elimina o
 * roubo trivial de conta. O caminho definitivo (senha ou codigo por e-mail) exige mudanca
 * de interface no app e esta documentado no relatorio final como proxima etapa.
 * ============================================================================================
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { generateTokens, authenticateToken, JWT_REFRESH_SECRET } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimits');
const { clientIp, antifraudMiddleware } = require('../middleware/antiFraud');
const { loginBotDetection } = require('../middleware/botDetection');
const {
  normalizeDeviceAccountKey,
  buildDeviceAccountEmail,
  generateDeviceBindingToken,
  hashDeviceBindingToken,
  normalizeInstallationState,
  INSTALLATION_STATE,
} = require('../utils/deviceIdentity');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Compatibilidade com builds antigos: mesmo o login legado por e-mail respeita
// a nova regra de uma unica conta vinculada a cada device_id.
const MAX_ACCOUNTS_PER_DEVICE = 1;

// ============================================================================================
// TETO DE CONTAS POR IP EM 24H — CORRECAO DE FALSO POSITIVO EM MASSA (CGNAT)
//
// O valor anterior era 8, herdado de uma premissa de "um IP = uma casa". Na pratica a base
// do CashPix acessa por dados moveis, e as operadoras brasileiras usam CGNAT: Claro, Vivo e
// TIM colocam MILHARES de celulares distintos atras de um unico IPv4 publico (faixas como
// 152.233.x.x e 189.x.x.x). Com teto 8, bastavam oito cadastros de pessoas diferentes na
// mesma operadora para que todo usuario novo daquele IP recebesse
// "Muitas contas criadas nesta rede" pelas 24h seguintes — exatamente o bloqueio relatado
// em producao, atingindo usuario legitimo e nao fraudador.
//
// Por que elevar e seguro: o anti-farm real desta base NAO depende do IP. Ele e garantido
// por aparelho, de forma atomica no banco:
//   - idx_users_device_account_key_unique (migration 005): uma conta por device_account_key
//   - idx_users_device_id_unique: mesma garantia para clientes legados
//   - device_account_aliases (PRIMARY KEY): uma chave de aparelho nunca em duas contas
//   - MAX_ACCOUNTS_PER_DEVICE = 1 + pg_advisory_xact_lock na criacao
// Ou seja: criar N contas exige N aparelhos fisicos distintos. O IP passa a ser o que sempre
// deveria ter sido — um freio contra volume anormal, nao a trava de primeira linha.
//
// PISO MINIMO (correcao de configuracao herdada):
// Elevar o padrao no codigo nao bastou em producao. A variavel de ambiente tem precedencia
// sobre o padrao, e o servico continuava com MAX_ACCOUNTS_PER_IP_24H=8 herdado da primeira
// configuracao. O resultado era o bloqueio persistindo mesmo com o codigo corrigido e sem
// nenhum sinal disso no diff — o tipo de defeito mais custoso de diagnosticar.
//
// A partir daqui um valor de ambiente abaixo do piso e RECUSADO, com aviso explicito no log
// de boot. Configuracao nao pode reintroduzir silenciosamente um defeito ja corrigido; para
// operar abaixo do piso e preciso mudar o codigo, o que passa por revisao.
// ============================================================================================
// ============================================================================================
// SEGUNDA CORRECAO — ELEVAR O TETO NAO ERA A SOLUCAO
//
// Com o teto em 60, o audit_log de producao registrou 1087 bloqueios, o ultimo minutos antes
// desta mudanca. Os registros mostram o motivo com precisao:
//
//    ip 152.233.23.193 | devicesFromIp 71 | limit 60
//    ip 152.233.23.194 | devicesFromIp 69 | limit 60
//
// A demanda legitima de um unico gateway de CGNAT passou de 60 aparelhos em 24h. Subir para
// 200 apenas adiaria o mesmo incidente: qualquer teto ACUMULADO sobre um IP compartilhado por
// milhares de assinantes acaba sendo alcancado por uso normal. O erro estava na metrica, nao
// no numero.
//
// A verificacao de que as contas eram legitimas:
//    - 70 contas / 70 aparelhos distintos  -> nenhuma conta duplicada por aparelho
//    - 60 modelos de aparelho distintos     -> farm usa emulador ou poucos aparelhos repetidos
//    - 37 das 70 voltaram ao app depois     -> farm cria, extrai bonus e abandona
//
// O QUE DISTINGUE FARM DE DIVULGACAO ORGANICA E A TAXA, NAO O ACUMULADO.
// Medido em producao nas 48h anteriores:
//    - pico por minuto em toda a base: 3 cadastros no mesmo IP
//    - pico por hora nos IPs afetados: 24 cadastros
// Divulgacao organica gera volume alto e espalhado; automacao gera dezenas em segundos.
//
// Por isso a trava de primeira linha passa a ser uma JANELA CURTA DE RAJADA por IP.
//
// CALIBRACAO (validada em tests/ip_burst_replay.test.js):
// O primeiro valor tentado foi 25, derivado do pico horario de 24. O teste de replay contra o
// trafego real reprovou: a janela de 10 min mais concentrada compativel com o observado chega
// a 24 cadastros, deixando folga de UM. Um dia de divulgacao um pouco mais intensa reproduziria
// o incidente. Um limite que passa raspando nao e um limite calibrado, e uma falha agendada.
//
// O teto foi para 40, que mantem folga de 1.7x sobre o pior caso realista e continua muito
// abaixo do que qualquer automacao produz (um script gera dezenas por minuto). A faixa de
// observacao em 20 avisa no audit_log bem antes de o bloqueio ser alcancado.
//
// O teto de 24h permanece, porem elevado a rede de seguranca (500) contra abuso sustentado de
// escala industrial. Deixa de ser o mecanismo que decide o cadastro do usuario comum.
// ============================================================================================

// Janela curta de rajada: o freio que efetivamente distingue automacao de uso real.
const IP_BURST_WINDOW_MINUTES = 10;
const MIN_IP_BURST_LIMIT = 25;
const DEFAULT_IP_BURST_LIMIT = 40;
// Faixa que apenas REGISTRA no audit_log, sem bloquear. Da visibilidade antecipada de
// mudanca de padrao sem transformar observacao em punicao.
const DEFAULT_IP_BURST_OBSERVE = 20;

// Rede de seguranca de 24h. Alto de proposito: nao e mais a trava de primeira linha.
const MIN_ACCOUNTS_PER_IP_24H = 200;
const DEFAULT_ACCOUNTS_PER_IP_24H = 500;

/**
 * Resolve um limite numerico vindo do ambiente respeitando um piso de seguranca.
 *
 * Valor ausente ou invalido cai no padrao. Valor abaixo do piso e elevado ao piso e o
 * evento e registrado, para que a divergencia entre o que foi configurado e o que esta
 * vigente apareca no log em vez de virar bloqueio invisivel de usuario legitimo.
 */
function resolveLimit(envName, defaultValue, minimumValue) {
  const raw = process.env[envName];
  const parsed = Number(raw);

  if (!raw || !Number.isFinite(parsed) || parsed <= 0) return defaultValue;

  if (parsed < minimumValue) {
    console.warn(
      `[Auth] ${envName}=${raw} esta abaixo do piso de seguranca (${minimumValue}) e foi ignorado. `
      + `Valor em uso: ${minimumValue}. Sob CGNAT de operadora movel, limites baixos por IP `
      + 'bloqueiam usuario legitimo em massa. O anti-farm efetivo e por aparelho.'
    );
    return minimumValue;
  }

  return parsed;
}

const MAX_ACCOUNTS_PER_IP_24H = resolveLimit(
  'MAX_ACCOUNTS_PER_IP_24H',
  DEFAULT_ACCOUNTS_PER_IP_24H,
  MIN_ACCOUNTS_PER_IP_24H
);

const IP_BURST_LIMIT = resolveLimit(
  'IP_BURST_LIMIT',
  DEFAULT_IP_BURST_LIMIT,
  MIN_IP_BURST_LIMIT
);

// A faixa de observacao nunca deve alcancar a de bloqueio: se alcancasse, a faixa que apenas
// registra se tornaria inalcancavel e o sistema perderia o aviso antecipado que ela existe
// para dar. Fica no menor valor entre o configurado e 80% do teto de bloqueio.
const IP_BURST_OBSERVE_LIMIT = Math.min(
  resolveLimit('IP_BURST_OBSERVE_LIMIT', DEFAULT_IP_BURST_OBSERVE, 5),
  Math.max(5, Math.floor(IP_BURST_LIMIT * 0.8))
);

// IPs que nunca devem servir de chave de bloqueio: ausentes, loopback ou private range.
// Sem isto, uma falha na resolucao do IP real colapsaria todos os cadastros num mesmo
// bucket (por exemplo "::1") e bloquearia a base inteira apos algumas contas.
function isUnreliableIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const clean = ip.trim().replace(/^::ffff:/i, '');
  if (!clean) return true;
  if (clean === '::1' || clean === '127.0.0.1' || clean.startsWith('127.')) return true;
  if (clean === 'unknown') return true;
  return false;
}

/**
 * Conta quantos APARELHOS DISTINTOS criaram conta neste IP nas ultimas 24h.
 *
 * A contagem anterior usava COUNT(*) sobre linhas de users, o que inflava o numero:
 * contas antigas do mesmo aparelho (reinstalacao, rotacao de chave de assinatura,
 * migracao de alias) somavam varias unidades e consumiam a cota sem existir farm algum.
 * Contar dispositivos distintos mede o que realmente importa.
 *
 * Retorna null quando o IP nao e confiavel, sinalizando que a checagem deve ser ignorada.
 */
async function countDevicesCreatedByIp(queryable, ip) {
  if (isUnreliableIp(ip)) return null;
  const result = await queryable.query(
    `SELECT COUNT(DISTINCT COALESCE(device_account_key, device_id, id::text)) AS count
       FROM users
      WHERE ip_address = $1
        AND created_at > NOW() - INTERVAL '24 hours'`,
    [ip]
  );
  return parseInt(result.rows[0].count, 10);
}

/**
 * Conta aparelhos que criaram conta neste IP na JANELA CURTA de rajada.
 *
 * Esta e a medida que separa automacao de divulgacao organica. Um gateway de CGNAT acumula
 * dezenas de cadastros legitimos ao longo de um dia, mas espalhados: o pico real medido em
 * producao foi de 3 cadastros no mesmo minuto e 24 na hora mais movimentada. Um script que
 * cria contas em serie produz volume muito superior dentro de poucos minutos.
 *
 * O intervalo e interpolado como literal por ser um inteiro validado no carregamento do
 * modulo; o Postgres nao aceita parametro em INTERVAL.
 *
 * Retorna null quando o IP nao e confiavel, sinalizando que a checagem deve ser ignorada.
 */
async function countIpBurst(queryable, ip) {
  if (isUnreliableIp(ip)) return null;
  const minutes = Number.isInteger(IP_BURST_WINDOW_MINUTES) && IP_BURST_WINDOW_MINUTES > 0
    ? IP_BURST_WINDOW_MINUTES
    : 10;
  const result = await queryable.query(
    `SELECT COUNT(DISTINCT COALESCE(device_account_key, device_id, id::text)) AS count
       FROM users
      WHERE ip_address = $1
        AND created_at > NOW() - INTERVAL '${minutes} minutes'`,
    [ip]
  );
  return parseInt(result.rows[0].count, 10);
}

// Namespace exclusivo da criacao/recuperacao de conta por aparelho. A trava evita
// que duas aberturas simultaneas do app criem duas contas antes do indice unico.
const DEVICE_ACCOUNT_LOCK_NAMESPACE = 8472;
const SUPPORT_EMAIL = 'madagascarmods347@gmail.com';

/**
 * Registra evento de seguranca de autenticacao para investigacao posterior.
 */
async function logAuthEvent(action, userId, detail, req) {
  try {
    await db.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'system', $2, 'user', $3, $4, $5)`,
      [userId || null, action, userId || null, JSON.stringify(detail), clientIp(req)]
    );
  } catch (e) {
    console.error('[Auth] Falha ao registrar evento:', e.message);
  }
}

/**
 * Verifica se a conta possui valor economico associado.
 *
 * Serve para calibrar o rigor do vinculo de dispositivo: uma conta zerada e recem-criada
 * pode trocar de aparelho sem cerimonia (nao ha nada a roubar e travar isso geraria suporte
 * desnecessario). Uma conta com saldo ou historico de saque exige liberacao manual, porque
 * e exatamente ela que um invasor teria interesse em acessar.
 */
async function accountHasValue(userId) {
  const balance = await db.query(
    'SELECT COALESCE(SUM(amount), 0) AS balance FROM points_ledger WHERE user_id = $1',
    [userId]
  );
  if (parseInt(balance.rows[0].balance, 10) > 0) return true;

  const withdrawals = await db.query(
    'SELECT 1 FROM withdrawals WHERE user_id = $1 LIMIT 1',
    [userId]
  );
  return withdrawals.rows.length > 0;
}

// POST /api/auth/device - cria ou recupera uma unica conta por aparelho.
//
// O cliente envia somente o SHA-256 do ANDROID_ID com escopo do app. Contas da
// versao anterior sao migradas de forma silenciosa usando o refresh token salvo
// ou, como fallback, o device_id legado armazenado no mesmo aparelho.
//
// ============================================================================================
// CORRECAO — CONTA DUPLICADA APOS ROTACAO DA CHAVE DE ASSINATURA (1.6.0+8 -> 1.7.0+9)
//
// Settings.Secure.ANDROID_ID e unico por combinacao aparelho + usuario Android + CHAVE DE
// ASSINATURA do aplicativo. Quando o release deixou de usar signingConfigs.debug e passou a
// usar a keystore propria, o ANDROID_ID do mesmo aparelho mudou e, com ele, o hash enviado
// como device_account_key. A versao anterior desta rota procurava apenas a chave atual em
// users.device_account_key; nao encontrando, tratava o aparelho como novo e criava outra conta.
//
// A partir daqui a conta nao depende mais de uma unica chave mutavel: toda chave ja vista e
// registrada em device_account_aliases e a busca acontece pelo alias. Uma chave nunca pertence
// a mais de um usuario (PRIMARY KEY), e a associacao continua exigindo prova de posse da conta
// (chave conhecida, refresh token salvo ou device_id legado do mesmo aparelho). IP e modelo
// jamais associam contas automaticamente.
// ============================================================================================
router.post('/device', authLimiter, loginBotDetection, antifraudMiddleware, async (req, res) => {
  const client = await db.getClient();

  try {
    const {
      device_account_key,
      legacy_device_id,
      migration_refresh_token,
      device_binding_token,
      installation_state,
      device_model,
      app_version,
    } = req.body;

    const deviceAccountKey = normalizeDeviceAccountKey(device_account_key);
    if (!deviceAccountKey) {
      return res.status(400).json({
        error: 'Nao foi possivel validar a identidade deste aparelho.',
        code: 'INVALID_DEVICE_ACCOUNT_KEY',
      });
    }

    const legacyDeviceId = typeof legacy_device_id === 'string'
      ? legacy_device_id.trim().slice(0, 255)
      : '';
    const safeDeviceModel = typeof device_model === 'string'
      ? device_model.trim().slice(0, 255)
      : null;
    const safeAppVersion = typeof app_version === 'string'
      ? app_version.trim().slice(0, 20)
      : null;

    // Estado da instalacao declarado pelo cliente. Ver device_service.dart:
    // `upgraded_without_proof` significa que o aparelho ja rodou o CashPix mas a
    // prova local desapareceu. O valor por si so nao concede acesso a nada; ele
    // apenas IMPEDE a criacao de conta, portanto um cliente malicioso nao ganha
    // nada declarando-o.
    const installationState = normalizeInstallationState(installation_state);

    const bindingTokenHash = typeof device_binding_token === 'string'
      && device_binding_token.trim().length >= 32
      ? hashDeviceBindingToken(device_binding_token.trim())
      : null;

    const ip = clientIp(req);

    await client.query('BEGIN');
    await client.query(
      'SELECT pg_advisory_xact_lock($1, hashtext($2))',
      [DEVICE_ACCOUNT_LOCK_NAMESPACE, deviceAccountKey]
    );

    // Busca pelo alias: resolve tanto a chave atual quanto qualquer chave anterior do mesmo
    // aparelho, inclusive apos rotacao da assinatura do APK. O UNION com users.device_account_key
    // mantem compatibilidade com contas criadas antes da tabela de aliases existir.
    let userResult = await client.query(
      `SELECT u.id, u.email, u.is_active, u.is_banned, u.device_account_key,
              a.source AS alias_source
         FROM device_account_aliases a
         JOIN users u ON u.id = a.user_id
        WHERE a.device_account_key = $1
          AND u.merged_into_user_id IS NULL
        UNION ALL
       SELECT u.id, u.email, u.is_active, u.is_banned, u.device_account_key,
              'device_account_key' AS alias_source
         FROM users u
        WHERE u.device_account_key = $1
          AND u.merged_into_user_id IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM device_account_aliases a2
             WHERE a2.device_account_key = $1
          )
        LIMIT 1`,
      [deviceAccountKey]
    );

    let user = userResult.rows[0] || null;
    let accountCreated = false;
    let accountMigrated = false;
    let migrationMethod = user ? (user.alias_source === 'device_account_key' ? 'device_account_key' : 'device_alias') : null;

    // Primeiro caminho de migracao, e agora o mais confiavel: token de vinculo
    // dedicado. Diferente do refresh token, ele nao e rotacionado pelo ciclo de
    // sessao, portanto continua valido depois de qualquer numero de renovacoes.
    // Ver migrations/009_device_binding_tokens.sql: somente o hash e armazenado.
    if (!user && bindingTokenHash) {
      const boundUser = await client.query(
        `SELECT id, email, is_active, is_banned, device_account_key
           FROM users
          WHERE device_binding_token_hash = $1
            AND merged_into_user_id IS NULL
          LIMIT 1
          FOR UPDATE`,
        [bindingTokenHash]
      );
      user = boundUser.rows[0] || null;
      if (user) migrationMethod = 'binding_token';
    }

    // Segundo caminho de migracao: refresh token valido salvo pela versao antiga.
    if (!user && typeof migration_refresh_token === 'string' && migration_refresh_token.length > 0) {
      try {
        const decoded = jwt.verify(migration_refresh_token, JWT_REFRESH_SECRET);
        const refreshUser = await client.query(
          `SELECT id, email, is_active, is_banned, device_account_key
             FROM users
            WHERE id = $1 AND refresh_token = $2
            LIMIT 1
            FOR UPDATE`,
          [decoded.userId, migration_refresh_token]
        );
        user = refreshUser.rows[0] || null;
        if (user) migrationMethod = 'refresh_token';
      } catch (_) {
        // Token expirado ou invalido: o device_id legado ainda pode migrar a conta.
      }
    }

    // Terceiro caminho: identificador aleatorio persistido pela instalacao antiga.
    if (!user && legacyDeviceId.length >= 8) {
      const legacyUsers = await client.query(
        `SELECT id, email, is_active, is_banned, device_account_key
           FROM users
          WHERE device_id = $1
          ORDER BY created_at ASC
          LIMIT 2
          FOR UPDATE`,
        [legacyDeviceId]
      );

      if (legacyUsers.rows.length > 1) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: `Mais de uma conta antiga esta vinculada a este aparelho. Contate ${SUPPORT_EMAIL}.`,
          code: 'LEGACY_DEVICE_CONFLICT',
          supportEmail: SUPPORT_EMAIL,
        });
      }

      user = legacyUsers.rows[0] || null;
      if (user) migrationMethod = 'legacy_device_id';
    }

    // Chave diferente da atual da conta, porem com posse comprovada (refresh token salvo,
    // device_id legado do mesmo aparelho ou alias anterior). Este e exatamente o caso da
    // rotacao da chave de assinatura: a chave nova passa a ser a principal e a antiga
    // continua resolvivel como alias, sem criar outra conta e sem recorrer a IP ou modelo.
    const requiresKeyRotation = Boolean(
      user && user.device_account_key && user.device_account_key !== deviceAccountKey
    );

    if (requiresKeyRotation) {
      const rotationProved = migrationMethod === 'binding_token'
        || migrationMethod === 'refresh_token'
        || migrationMethod === 'legacy_device_id'
        || migrationMethod === 'device_alias';

      if (!rotationProved) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: `Esta conta ja esta vinculada a outro aparelho. Contate ${SUPPORT_EMAIL}.`,
          code: 'DEVICE_ACCOUNT_CONFLICT',
          supportEmail: SUPPORT_EMAIL,
        });
      }
    }

    if (user && (requiresKeyRotation || !user.device_account_key)) {
      await client.query(
        `UPDATE users SET device_id = $1,
                device_account_key = $1,
                device_model = COALESCE($2, device_model),
                app_version = COALESCE($3, app_version),
                ip_address = $4,
                last_login_at = NOW(),
                updated_at = NOW()
          WHERE id = $5`,
        [deviceAccountKey, safeDeviceModel, safeAppVersion, ip, user.id]
      );
      user.device_account_key = deviceAccountKey;
      accountMigrated = true;
    }

    // ==========================================================================
    // BLOQUEIO DE CRIACAO SILENCIOSA EM ESTADO AMBIGUO
    //
    // Nenhuma prova localizou a conta e o proprio aplicativo informa que este
    // aparelho JA rodou o CashPix antes. Criar uma conta aqui e exatamente o
    // defeito relatado em producao: o usuario reinstalava o app e reaparecia com
    // saldo zero, enquanto a conta antiga continuava existindo intacta.
    //
    // A recusa e deliberada. O saldo anterior permanece no servidor e a conta e
    // religada pelo suporte, usando o codigo CP-XXXX-XXXX-XXXX. Uma instalacao
    // genuinamente nova declara `fresh_install` e segue criando conta normalmente.
    // ==========================================================================
    if (!user && installationState === INSTALLATION_STATE.UPGRADED_WITHOUT_PROOF) {
      await client.query('ROLLBACK');
      await logAuthEvent(
        'DEVICE_ACCOUNT_CREATION_BLOCKED_AMBIGUOUS',
        null,
        { ip, appVersion: safeAppVersion, deviceModel: safeDeviceModel },
        req
      );
      return res.status(409).json({
        error: 'Este aparelho ja possui uma conta CashPix, mas o vinculo local foi '
          + `perdido. Para nao duplicar a conta nem zerar seu saldo, fale com ${SUPPORT_EMAIL}.`,
        code: 'DEVICE_RECOVERY_REQUIRED',
        supportEmail: SUPPORT_EMAIL,
      });
    }

    if (!user) {
      // ======================================================================
      // FREIO POR REDE — RAJADA, NAO ACUMULADO
      //
      // A trava de primeira linha e a taxa de cadastros numa janela curta, porque e ela
      // que distingue automacao de divulgacao organica. O teto de 24h continua adiante,
      // como rede de seguranca contra abuso sustentado.
      //
      // Ignorado quando o IP nao e confiavel (ausente, loopback): nesse caso todos os
      // cadastros cairiam num mesmo bucket e a base inteira seria bloqueada.
      // ======================================================================
      const burstFromIp = await countIpBurst(client, ip);

      if (burstFromIp !== null && burstFromIp >= IP_BURST_LIMIT) {
        await client.query('ROLLBACK');
        await logAuthEvent(
          'DEVICE_REGISTER_BLOCKED_IP_BURST',
          null,
          {
            ip,
            burstFromIp,
            limit: IP_BURST_LIMIT,
            windowMinutes: IP_BURST_WINDOW_MINUTES,
          },
          req
        );
        // A espera aqui e de minutos, nao de horas: a janela e curta e desliza. A mensagem
        // informa o tempo para que o usuario legitimo saiba que basta tentar de novo em
        // seguida, em vez de concluir que o aplicativo o rejeitou.
        return res.status(429).json({
          error: `Muitos cadastros nesta rede em ${IP_BURST_WINDOW_MINUTES} minutos. `
            + `Aguarde ${IP_BURST_WINDOW_MINUTES} minutos e toque em Tentar novamente.`,
          code: 'IP_BURST_LIMIT',
          retryAfterMinutes: IP_BURST_WINDOW_MINUTES,
        });
      }

      // Faixa de observacao: registra sem bloquear, para que uma mudanca de padrao apareca
      // no audit_log antes de virar recusa de usuario.
      if (burstFromIp !== null && burstFromIp >= IP_BURST_OBSERVE_LIMIT) {
        await logAuthEvent(
          'DEVICE_REGISTER_IP_BURST_OBSERVED',
          null,
          {
            ip,
            burstFromIp,
            observeLimit: IP_BURST_OBSERVE_LIMIT,
            blockLimit: IP_BURST_LIMIT,
            windowMinutes: IP_BURST_WINDOW_MINUTES,
          },
          req
        );
      }

      // Rede de seguranca de 24h. Teto alto: destina-se a abuso sustentado de escala
      // industrial, nao ao trafego de um gateway de operadora movel.
      const devicesFromIp = await countDevicesCreatedByIp(client, ip);
      if (devicesFromIp !== null && devicesFromIp >= MAX_ACCOUNTS_PER_IP_24H) {
        await client.query('ROLLBACK');
        await logAuthEvent(
          'DEVICE_REGISTER_BLOCKED_IP_LIMIT',
          null,
          { ip, devicesFromIp, limit: MAX_ACCOUNTS_PER_IP_24H, burstFromIp },
          req
        );
        return res.status(429).json({
          error: 'Muitas contas criadas nesta rede. Tente novamente mais tarde.',
          code: 'IP_ACCOUNT_LIMIT',
        });
      }

      const userId = uuidv4();
      const internalEmail = buildDeviceAccountEmail(deviceAccountKey);
      const inserted = await client.query(
        `INSERT INTO users (
           id, email, device_id, device_account_key, device_model,
           ip_address, app_version, created_at, last_login_at
         )
         VALUES ($1, $2, $3, $3, $4, $5, $6, NOW(), NOW())
         RETURNING id, email, is_active, is_banned, device_account_key`,
        [userId, internalEmail, deviceAccountKey, safeDeviceModel, ip, safeAppVersion || '1.6.0']
      );
      user = inserted.rows[0];
      accountCreated = true;
    } else if (!accountMigrated) {
      await client.query(
        `UPDATE users SET device_id = $1,
                device_account_key = $1,
                device_model = COALESCE($2, device_model),
                app_version = COALESCE($3, app_version),
                ip_address = $4,
                last_login_at = NOW(),
                updated_at = NOW()
          WHERE id = $5`,
        [deviceAccountKey, safeDeviceModel, safeAppVersion, ip, user.id]
      );
    }

    // Registra a chave atual como alias resolvivel da conta. O conflito e ignorado quando o
    // alias ja pertence a este usuario; se pertencer a outro, nada e sobrescrito e o vinculo
    // permanece exclusivo, conforme a PRIMARY KEY da tabela.
    const aliasResult = await client.query(
      `INSERT INTO device_account_aliases (
         device_account_key, user_id, source, first_seen_at, last_seen_at, metadata
       )
       VALUES ($1, $2, $3, NOW(), NOW(), $4::jsonb)
       ON CONFLICT (device_account_key) DO UPDATE
          SET last_seen_at = NOW()
        WHERE device_account_aliases.user_id = EXCLUDED.user_id
       RETURNING user_id`,
      [
        deviceAccountKey,
        user.id,
        accountCreated ? 'account_created' : (migrationMethod || 'device_login'),
        JSON.stringify({ appVersion: safeAppVersion, deviceModel: safeDeviceModel }),
      ]
    );

    if (aliasResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `Este aparelho ja esta vinculado a outra conta. Contate ${SUPPORT_EMAIL}.`,
        code: 'DEVICE_ALIAS_CONFLICT',
        supportEmail: SUPPORT_EMAIL,
      });
    }

    if (user.is_banned) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Conta suspensa.', code: 'BANNED' });
    }

    if (!user.is_active) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Conta inativa.', code: 'INACTIVE' });
    }

    const { accessToken, refreshToken } = generateTokens(user.id, user.email);

    // ==========================================================================
    // EMISSAO / REAPROVEITAMENTO DO TOKEN DE VINCULO
    //
    // Um token novo e emitido somente quando a conta ainda nao possui um. Um
    // token existente e valido NAO e rotacionado: rotacionar traria de volta
    // exatamente a fragilidade do refresh token, em que o valor guardado no
    // aparelho fica obsoleto sem o usuario perceber.
    //
    // O token e devolvido em texto claro uma unica vez, no momento da emissao,
    // porque o servidor guarda apenas o hash e nao tem como reexibi-lo depois.
    // ==========================================================================
    let issuedBindingToken = null;

    if (!bindingTokenHash || migrationMethod !== 'binding_token') {
      const existing = await client.query(
        'SELECT device_binding_token_hash FROM users WHERE id = $1',
        [user.id]
      );
      const storedHash = existing.rows[0]?.device_binding_token_hash || null;

      // Somente contas sem token recebem um. Se a conta ja tem um token e o
      // aparelho apresentou outro (ou nenhum), o token vigente permanece o unico
      // valido: sobrescrever permitiria que um cliente qualquer substituisse a
      // credencial de vinculo de uma conta com saldo.
      if (!storedHash) {
        issuedBindingToken = generateDeviceBindingToken();
        await client.query(
          `UPDATE users
              SET device_binding_token_hash = $1,
                  device_binding_token_issued_at = NOW()
            WHERE id = $2`,
          [hashDeviceBindingToken(issuedBindingToken), user.id]
        );
      }
    }

    await client.query(
      'UPDATE users SET token = $1, refresh_token = $2 WHERE id = $3',
      [accessToken, refreshToken, user.id]
    );

    // O codigo de suporte e derivado do UUID por trigger e nunca muda. E o unico
    // identificador que o usuario pode ler, anotar e informar ao atendimento.
    const supportCodeResult = await client.query(
      'SELECT support_code FROM users WHERE id = $1',
      [user.id]
    );
    const supportCode = supportCodeResult.rows[0]?.support_code || null;

    await client.query(
      `INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, new_value, ip_address)
       VALUES ($1, 'system', $2, 'user', $1, $3, $4)`,
      [
        user.id,
        accountCreated ? 'DEVICE_ACCOUNT_CREATED' : accountMigrated ? 'DEVICE_ACCOUNT_MIGRATED' : 'DEVICE_ACCOUNT_LOGIN',
        JSON.stringify({
          migrationMethod,
          appVersion: safeAppVersion,
          installationState,
          bindingTokenIssued: Boolean(issuedBindingToken),
        }),
        ip,
      ]
    );

    await client.query('COMMIT');

    res.status(accountCreated ? 201 : 200).json({
      success: true,
      accountCreated,
      accountMigrated,
      migrationMethod,
      user: { id: user.id, email: user.email, supportCode },
      accessToken,
      refreshToken,
      // Presente apenas na emissao. Nas chamadas seguintes o campo e omitido e o
      // aplicativo continua usando o token que ja tem salvo.
      ...(issuedBindingToken ? { deviceBindingToken: issuedBindingToken } : {}),
    });
  } catch (error) {
    await client.query('ROLLBACK');

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Este aparelho ja possui uma conta cadastrada.',
        code: 'DEVICE_ACCOUNT_EXISTS',
      });
    }

    console.error('Device account access error:', error);
    res.status(500).json({
      error: 'Falha ao acessar a conta deste aparelho.',
      code: 'DEVICE_ACCOUNT_ERROR',
    });
  } finally {
    client.release();
  }
});

// POST /api/auth/register (legado: mantido temporariamente para builds anteriores)
router.post('/register', authLimiter, loginBotDetection, async (req, res) => {
  try {
    const { email, device_id, device_model, app_version } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    // device_id obrigatorio: e a base do vinculo de dispositivo e do controle de farm.
    if (!device_id || String(device_id).trim().length < 8) {
      return res.status(400).json({
        error: 'Nao foi possivel identificar o aparelho. Atualize o aplicativo.',
        code: 'DEVICE_ID_REQUIRED'
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const deviceId = String(device_id).trim();
    const ip = clientIp(req);

    // Check if user already exists
    const existing = await db.query('SELECT id, email FROM users WHERE email = $1', [normalizedEmail]);

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered', code: 'EMAIL_EXISTS' });
    }

    // Limite de contas por dispositivo (anti-farm)
    const deviceAccounts = await db.query(
      'SELECT COUNT(*) AS count FROM users WHERE device_id = $1',
      [deviceId]
    );
    if (parseInt(deviceAccounts.rows[0].count, 10) >= MAX_ACCOUNTS_PER_DEVICE) {
      await logAuthEvent('REGISTER_BLOCKED_DEVICE_LIMIT', null, { deviceId, email: normalizedEmail }, req);
      return res.status(429).json({
        error: 'Limite de contas por aparelho atingido.',
        code: 'DEVICE_ACCOUNT_LIMIT'
      });
    }

    // Freio por rede: mesma regra da rota por aparelho. Rajada em janela curta como trava de
    // primeira linha, teto de 24h como rede de seguranca. Manter as duas rotas coerentes evita
    // que um cliente antigo continue sofrendo o falso positivo ja corrigido na rota nova.
    const burstFromIp = await countIpBurst(db, ip);
    if (burstFromIp !== null && burstFromIp >= IP_BURST_LIMIT) {
      await logAuthEvent(
        'REGISTER_BLOCKED_IP_BURST',
        null,
        {
          ip,
          email: normalizedEmail,
          burstFromIp,
          limit: IP_BURST_LIMIT,
          windowMinutes: IP_BURST_WINDOW_MINUTES,
        },
        req
      );
      return res.status(429).json({
        error: `Muitos cadastros nesta rede em ${IP_BURST_WINDOW_MINUTES} minutos. `
          + `Aguarde ${IP_BURST_WINDOW_MINUTES} minutos e tente novamente.`,
        code: 'IP_BURST_LIMIT',
        retryAfterMinutes: IP_BURST_WINDOW_MINUTES,
      });
    }

    const devicesFromIp = await countDevicesCreatedByIp(db, ip);
    if (devicesFromIp !== null && devicesFromIp >= MAX_ACCOUNTS_PER_IP_24H) {
      await logAuthEvent(
        'REGISTER_BLOCKED_IP_LIMIT',
        null,
        { ip, email: normalizedEmail, devicesFromIp, limit: MAX_ACCOUNTS_PER_IP_24H, burstFromIp },
        req
      );
      return res.status(429).json({
        error: 'Muitas contas criadas nesta rede. Tente novamente mais tarde.',
        code: 'IP_ACCOUNT_LIMIT'
      });
    }

    const userId = uuidv4();

    await db.query(
      `INSERT INTO users (id, email, device_id, device_model, ip_address, app_version, created_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
      [userId, normalizedEmail, deviceId, device_model || null, ip, app_version || '1.0.0']
    );

    const { accessToken, refreshToken } = generateTokens(userId, normalizedEmail);

    // Save refresh token
    await db.query('UPDATE users SET token = $1, refresh_token = $2 WHERE id = $3', [accessToken, refreshToken, userId]);

    await logAuthEvent('USER_REGISTERED', userId, { email: normalizedEmail, deviceId }, req);

    res.status(201).json({
      success: true,
      user: { id: userId, email: normalizedEmail },
      accessToken,
      refreshToken
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Este aparelho ja possui uma conta cadastrada.',
        code: 'DEVICE_ACCOUNT_EXISTS',
      });
    }
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
//
// Mantem a experiencia de entrar apenas com o e-mail, mas com o vinculo de dispositivo
// descrito no topo do arquivo. Ver VULN-05.
router.post('/login', authLimiter, loginBotDetection, async (req, res) => {
  try {
    const { email, device_id, device_model, app_version } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    if (!device_id || String(device_id).trim().length < 8) {
      return res.status(400).json({
        error: 'Nao foi possivel identificar o aparelho. Atualize o aplicativo.',
        code: 'DEVICE_ID_REQUIRED'
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const deviceId = String(device_id).trim();
    const ip = clientIp(req);

    let user = await db.query(
      'SELECT id, email, is_active, is_banned, device_id, device_migration_allowed FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (user.rows.length === 0) {
      // Auto-registro no primeiro login (comportamento historico do app), agora sujeito
      // aos mesmos limites anti-farm do /register.
      const deviceAccounts = await db.query(
        'SELECT COUNT(*) AS count FROM users WHERE device_id = $1',
        [deviceId]
      );
      if (parseInt(deviceAccounts.rows[0].count, 10) >= MAX_ACCOUNTS_PER_DEVICE) {
        await logAuthEvent('LOGIN_BLOCKED_DEVICE_LIMIT', null, { deviceId, email: normalizedEmail }, req);
        return res.status(429).json({
          error: 'Limite de contas por aparelho atingido.',
          code: 'DEVICE_ACCOUNT_LIMIT'
        });
      }

      // Este ponto cria conta durante o login (auto-registro de cliente legado), portanto
      // segue a mesma regra de rede das rotas de cadastro: rajada primeiro, teto de 24h depois.
      const burstFromIp = await countIpBurst(db, ip);
      if (burstFromIp !== null && burstFromIp >= IP_BURST_LIMIT) {
        await logAuthEvent(
          'LOGIN_BLOCKED_IP_BURST',
          null,
          {
            ip,
            email: normalizedEmail,
            burstFromIp,
            limit: IP_BURST_LIMIT,
            windowMinutes: IP_BURST_WINDOW_MINUTES,
          },
          req
        );
        return res.status(429).json({
          error: `Muitos cadastros nesta rede em ${IP_BURST_WINDOW_MINUTES} minutos. `
            + `Aguarde ${IP_BURST_WINDOW_MINUTES} minutos e tente novamente.`,
          code: 'IP_BURST_LIMIT',
          retryAfterMinutes: IP_BURST_WINDOW_MINUTES,
        });
      }

      const devicesFromIp = await countDevicesCreatedByIp(db, ip);
      if (devicesFromIp !== null && devicesFromIp >= MAX_ACCOUNTS_PER_IP_24H) {
        await logAuthEvent(
          'LOGIN_BLOCKED_IP_LIMIT',
          null,
          { ip, email: normalizedEmail, devicesFromIp, limit: MAX_ACCOUNTS_PER_IP_24H, burstFromIp },
          req
        );
        return res.status(429).json({
          error: 'Muitas contas criadas nesta rede. Tente novamente mais tarde.',
          code: 'IP_ACCOUNT_LIMIT'
        });
      }

      const userId = uuidv4();
      await db.query(
        `INSERT INTO users (id, email, device_id, device_model, ip_address, app_version, created_at, last_login_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
        [userId, normalizedEmail, deviceId, device_model || null, ip, app_version || '1.0.0']
      );
      await logAuthEvent('USER_AUTO_REGISTERED', userId, { email: normalizedEmail, deviceId }, req);

      user = {
        rows: [{
          id: userId,
          email: normalizedEmail,
          is_active: true,
          is_banned: false,
          device_id: deviceId,
          device_migration_allowed: false
        }]
      };
    } else {
      const existingUser = user.rows[0];

      // ------------------------------------------------------------------------------
      // VINCULO DE DISPOSITIVO
      //
      // Se a conta ja esta associada a um aparelho e a tentativa vem de outro, o acesso
      // e negado quando a conta tem valor (saldo ou historico de saque). Sem isso, saber
      // o e-mail de alguem bastava para sacar o dinheiro da pessoa.
      // ------------------------------------------------------------------------------
      const boundDevice = existingUser.device_id;
      const isDifferentDevice = boundDevice && boundDevice !== deviceId;

      if (isDifferentDevice && !existingUser.device_migration_allowed) {
        const hasValue = await accountHasValue(existingUser.id);

        if (hasValue) {
          await logAuthEvent('LOGIN_BLOCKED_DEVICE_MISMATCH', existingUser.id, {
            email: normalizedEmail,
            boundDevice,
            attemptedDevice: deviceId
          }, req);

          return res.status(403).json({
            error: 'Esta conta esta vinculada a outro aparelho. Fale com o suporte para liberar a troca.',
            code: 'DEVICE_MISMATCH'
          });
        }

        // Conta sem saldo e sem historico: liberar a troca e apenas registrar.
        await logAuthEvent('DEVICE_REBOUND_EMPTY_ACCOUNT', existingUser.id, {
          email: normalizedEmail,
          previousDevice: boundDevice,
          newDevice: deviceId
        }, req);
      }

      // Update login info.
      // O device_id e gravado com COALESCE apenas quando ainda nao havia vinculo; caso de
      // migracao autorizada, o vinculo e transferido e a autorizacao e consumida (one-shot),
      // para que a liberacao dada pelo suporte nao permaneca valida indefinidamente.
      await db.query(
        `UPDATE users SET
           last_login_at = NOW(),
           ip_address = $1,
           device_id = $2,
           device_model = COALESCE($3, device_model),
           app_version = COALESCE($4, app_version),
           device_migration_allowed = false,
           updated_at = NOW()
         WHERE id = $5`,
        [ip, deviceId, device_model, app_version, existingUser.id]
      );
    }

    const userData = user.rows[0];

    if (userData.is_banned) {
      return res.status(403).json({ error: 'Account suspended', code: 'BANNED' });
    }

    if (!userData.is_active) {
      return res.status(403).json({ error: 'Account inactive', code: 'INACTIVE' });
    }

    const { accessToken, refreshToken } = generateTokens(userData.id, userData.email);

    await db.query('UPDATE users SET token = $1, refresh_token = $2 WHERE id = $3', [accessToken, refreshToken, userData.id]);

    res.json({
      success: true,
      user: { id: userData.id, email: userData.email },
      accessToken,
      refreshToken
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Este aparelho ja possui uma conta cadastrada.',
        code: 'DEVICE_ACCOUNT_EXISTS',
      });
    }
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const user = await db.query(
      'SELECT id, email, is_active, is_banned FROM users WHERE id = $1 AND refresh_token = $2',
      [decoded.userId, refreshToken]
    );

    if (user.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const userData = user.rows[0];

    // Conta banida ou inativa nao renova sessao.
    // Antes desta checagem, um usuario banido continuava trocando o refresh token
    // indefinidamente e mantinha acesso as rotas autenticadas apesar do ban.
    if (userData.is_banned) {
      return res.status(403).json({ error: 'Account suspended', code: 'BANNED' });
    }
    if (!userData.is_active) {
      return res.status(403).json({ error: 'Account inactive', code: 'INACTIVE' });
    }

    const tokens = generateTokens(userData.id, userData.email);

    await db.query('UPDATE users SET token = $1, refresh_token = $2 WHERE id = $3', [tokens.accessToken, tokens.refreshToken, userData.id]);

    res.json({
      success: true,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// POST /api/auth/logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await db.query('UPDATE users SET token = NULL, refresh_token = NULL WHERE id = $1', [req.user.userId]);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// O router continua sendo a exportacao principal (app.use('/api/auth', authRoutes)).
// Os limites vigentes acompanham como propriedades para que o /health possa reporta-los
// sem duplicar a leitura do ambiente nem reimplementar a regra do piso.
module.exports = router;
module.exports.limits = {
  // Trava de primeira linha: rajada em janela curta.
  ipBurstLimit: IP_BURST_LIMIT,
  ipBurstObserveLimit: IP_BURST_OBSERVE_LIMIT,
  ipBurstWindowMinutes: IP_BURST_WINDOW_MINUTES,
  ipBurstConfigured: process.env.IP_BURST_LIMIT || null,
  // Rede de seguranca de 24h.
  maxAccountsPerIp24h: MAX_ACCOUNTS_PER_IP_24H,
  maxAccountsPerIp24hDefault: DEFAULT_ACCOUNTS_PER_IP_24H,
  maxAccountsPerIp24hFloor: MIN_ACCOUNTS_PER_IP_24H,
  maxAccountsPerDevice: MAX_ACCOUNTS_PER_DEVICE,
  configuredValue: process.env.MAX_ACCOUNTS_PER_IP_24H || null,
};
