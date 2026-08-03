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
const { clientIp } = require('../middleware/antiFraud');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Teto de contas distintas por dispositivo. Uma familia pode compartilhar um aparelho,
// por isso o limite nao e 1; mas um farm com dezenas de contas no mesmo device para.
const MAX_ACCOUNTS_PER_DEVICE = 3;

// Teto de contas criadas pelo mesmo IP em 24h. Redes compartilhadas (escola, trabalho,
// CGNAT de operadora movel) justificam um valor mais folgado.
const MAX_ACCOUNTS_PER_IP_24H = 8;

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

// POST /api/auth/register
router.post('/register', authLimiter, async (req, res) => {
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
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
//
// Mantem a experiencia de entrar apenas com o e-mail, mas com o vinculo de dispositivo
// descrito no topo do arquivo. Ver VULN-05.
router.post('/login', authLimiter, async (req, res) => {
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
