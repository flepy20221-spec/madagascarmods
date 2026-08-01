const jwt = require('jsonwebtoken');
const db = require('../models/db');

const JWT_SECRET = process.env.JWT_SECRET || 'madagascarmods-secret-key-change-in-production';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'madagascarmods-refresh-secret-change-in-production';

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
    
    // Check if user is banned
    try {
      const userCheck = await db.query(
        'SELECT is_banned, is_active FROM users WHERE id = $1',
        [decoded.userId]
      );
      if (userCheck.rows.length > 0) {
        if (userCheck.rows[0].is_banned) {
          return res.status(403).json({ error: 'Conta suspensa', code: 'BANNED' });
        }
        if (!userCheck.rows[0].is_active) {
          return res.status(403).json({ error: 'Conta inativa', code: 'INACTIVE' });
        }
      }
    } catch (dbErr) {
      // If DB check fails, allow request to proceed (fail-open for availability)
      console.error('Ban check error:', dbErr.message);
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
    return res.status(403).json({ error: 'Invalid admin token' });
  }
}

module.exports = {
  generateTokens,
  authenticateToken,
  authenticateAdmin,
  JWT_SECRET,
  JWT_REFRESH_SECRET
};
