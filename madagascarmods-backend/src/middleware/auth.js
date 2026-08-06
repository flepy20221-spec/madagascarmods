const jwt = require('jsonwebtoken');
const db = require('../models/db');

// Os segredos agora vem de src/config/secrets.js, que valida presenca, tamanho minimo e
// rejeita valores publicados no repositorio. Em producao, um segredo invalido aborta o boot
// em vez de deixar o servidor subir num estado onde tokens de admin podem ser forjados.
// (Auditoria: VULN-04)
const { JWT_SECRET, JWT_REFRESH_SECRET } = require('../config/secrets');

function generateTokens(userId, email) {
  const accessToken = jwt.sign(
    { userId, email },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  const refreshToken = jwt.sign(
    { userId, email, type: 'refresh' },
    JWT_REFRESH_SECRET,
    { expiresIn: '30d' }
  );
  return { accessToken, refreshToken };
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
      }
      return res.status(403).json({ error: 'Invalid token' });
    }

    // Verificacao de banimento e de existencia da conta.
    //
    // CORRECAO (auditoria VULN-11): o comportamento anterior era fail-open — se a consulta
    // ao banco falhasse, a request seguia adiante. Isso significa que uma instabilidade no
    // banco (ou uma sobrecarga provocada de proposito) reabilitava contas banidas para
    // continuar pontuando. Alem disso, se o usuario nao existisse mais (rows.length === 0),
    // o token continuava valido. Agora ambos os casos bloqueiam.
    try {
      const userCheck = await db.query(
        'SELECT is_banned, is_active FROM users WHERE id = $1',
        [decoded.userId]
      );

      if (userCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Conta nao encontrada', code: 'USER_NOT_FOUND' });
      }
      if (userCheck.rows[0].is_banned) {
        return res.status(403).json({ error: 'Conta suspensa', code: 'BANNED' });
      }
      if (!userCheck.rows[0].is_active) {
        return res.status(403).json({ error: 'Conta inativa', code: 'INACTIVE' });
      }
    } catch (dbErr) {
      console.error('Ban check error:', dbErr.message);
      return res.status(503).json({
        error: 'Servico temporariamente indisponivel. Tente novamente.',
        code: 'SERVICE_UNAVAILABLE'
      });
    }

    req.user = decoded;
    next();
  });
}

async function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Admin access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Admin privileges required' });
    }

    const result = await db.query(
      'SELECT id, email, role, is_active FROM admin_users WHERE id = $1 AND is_active = true',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Admin account not found or inactive' });
    }

    req.admin = result.rows[0];
    next();
  } catch (err) {
    // Token expirado retorna 401 + TOKEN_EXPIRED (e nao 403), para o painel admin
    // conseguir redirecionar ao login. Antes, a expiracao caia no mesmo 403 de token
    // invalido e gerava "sessao-zumbi": o admin parecia logado, mas o dashboard exibia
    // "Falha ao carregar / Invalid admin token" com os contadores em zero.
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Sessao administrativa expirada. Faca login novamente.',
        code: 'TOKEN_EXPIRED'
      });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Token administrativo invalido.',
        code: 'TOKEN_INVALID'
      });
    }
    console.error('authenticateAdmin error:', err.message);
    return res.status(403).json({ error: 'Invalid admin token' });
  }
}

/**
 * Exige que o admin autenticado tenha um dos papeis informados.
 *
 * CORRECAO (auditoria VULN-09): o campo `role` era gravado no token e lido do banco,
 * mas nunca comparado. Qualquer conta administrativa ativa — inclusive uma criada como
 * `viewer` para apenas consultar relatorios — podia aprovar saques, creditar pontos
 * manualmente e editar dados de usuarios. Agora as acoes financeiras e destrutivas
 * exigem papel explicito.
 *
 * Uso: router.post('/rota', authenticateAdmin, requireRole('super_admin', 'finance'), handler)
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const role = req.admin?.role;

    if (!role) {
      return res.status(403).json({
        error: 'Perfil administrativo sem papel definido.',
        code: 'ROLE_MISSING'
      });
    }

    // super_admin sempre tem acesso total
    if (role === 'super_admin' || allowedRoles.includes(role)) {
      return next();
    }

    return res.status(403).json({
      error: 'Seu perfil nao tem permissao para esta acao.',
      code: 'INSUFFICIENT_ROLE',
      requiredRoles: allowedRoles
    });
  };
}

module.exports = {
  generateTokens,
  authenticateToken,
  authenticateAdmin,
  requireRole,
  JWT_SECRET,
  JWT_REFRESH_SECRET
};
