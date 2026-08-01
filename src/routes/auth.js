const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const db = require('../models/db');
const { generateTokens, authenticateToken, JWT_REFRESH_SECRET } = require('../middleware/auth');
const jwt = require('jsonwebtoken');

const router = express.Router();

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { email, device_id, device_model, app_version } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existing = await db.query('SELECT id, email FROM users WHERE email = $1', [normalizedEmail]);
    
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered', code: 'EMAIL_EXISTS' });
    }

    const userId = uuidv4();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    await db.query(
      `INSERT INTO users (id, email, device_id, device_model, ip_address, app_version, created_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
      [userId, normalizedEmail, device_id || null, device_model || null, ip, app_version || '1.0.0']
    );

    const { accessToken, refreshToken } = generateTokens(userId, normalizedEmail);

    // Save refresh token
    await db.query('UPDATE users SET token = $1, refresh_token = $2 WHERE id = $3', [accessToken, refreshToken, userId]);

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
router.post('/login', async (req, res) => {
  try {
    const { email, device_id, device_model, app_version } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Find or create user
    let user = await db.query('SELECT id, email, is_active, is_banned FROM users WHERE email = $1', [normalizedEmail]);

    if (user.rows.length === 0) {
      // Auto-register on first login (similar to original app behavior)
      const userId = uuidv4();
      await db.query(
        `INSERT INTO users (id, email, device_id, device_model, ip_address, app_version, created_at, last_login_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
        [userId, normalizedEmail, device_id || null, device_model || null, ip, app_version || '1.0.0']
      );
      user = { rows: [{ id: userId, email: normalizedEmail, is_active: true, is_banned: false }] };
    } else {
      // Update login info
      await db.query(
        `UPDATE users SET last_login_at = NOW(), ip_address = $1, device_id = COALESCE($2, device_id), 
         device_model = COALESCE($3, device_model), app_version = COALESCE($4, app_version) WHERE id = $5`,
        [ip, device_id, device_model, app_version, user.rows[0].id]
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
    
    const user = await db.query('SELECT id, email, is_active, is_banned FROM users WHERE id = $1 AND refresh_token = $2', [decoded.userId, refreshToken]);

    if (user.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const userData = user.rows[0];
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
