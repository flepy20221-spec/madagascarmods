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

// Teto de contas criadas pelo mesmo IP em 24h. Redes compartilhadas (escola, trabalho,
// CGNAT de operadora movel) justificam um valor mais folgado.
const MAX_ACCOUNTS_PER_IP_24H = 8;

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
      const ipAccounts = await client.query(
        `SELECT COUNT(*) AS count FROM users
          WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
        [ip]
      );
      if (parseInt(ipAccounts.rows[0].count, 10) >= MAX_ACCOUNTS_PER_IP_24H) {
        await client.query('ROLLBACK');
        await logAuthEvent('DEVICE_REGISTER_BLOCKED_IP_LIMIT', null, { ip }, req);
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

    // Limite de contas por IP em 24h (anti-farm)
    const ipAccounts = await db.query(
      `SELECT COUNT(*) AS count FROM users
        WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
      [ip]
    );
    if (parseInt(ipAccounts.rows[0].count, 10) >= MAX_ACCOUNTS_PER_IP_24H) {
      await logAuthEvent('REGISTER_BLOCKED_IP_LIMIT', null, { ip, email: normalizedEmail }, req);
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

      const ipAccounts = await db.query(
        `SELECT COUNT(*) AS count FROM users
          WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
        [ip]
      );
      if (parseInt(ipAccounts.rows[0].count, 10) >= MAX_ACCOUNTS_PER_IP_24H) {
        await logAuthEvent('LOGIN_BLOCKED_IP_LIMIT', null, { ip, email: normalizedEmail }, req);
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

module.exports = router;
