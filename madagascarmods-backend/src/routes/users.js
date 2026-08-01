const express = require('express');
const db = require('../models/db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// GET /api/users/me - Get current user profile
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.query(
      `SELECT u.id, u.email, u.device_id, u.app_version, u.is_active, u.created_at, u.last_login_at,
       COALESCE(SUM(pl.amount), 0) as balance
       FROM users u
       LEFT JOIN points_ledger pl ON pl.user_id = u.id
       WHERE u.id = $1
       GROUP BY u.id`,
      [req.user.userId]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = user.rows[0];

    // Get payout destination status
    const payout = await db.query(
      `SELECT id, status, value_masked, submitted_at, reviewed_at 
       FROM payout_destinations 
       WHERE user_id = $1 AND is_active = true 
       ORDER BY version DESC LIMIT 1`,
      [req.user.userId]
    );

    res.json({
      success: true,
      user: {
        id: userData.id,
        email: userData.email,
        balance: parseInt(userData.balance),
        appVersion: userData.app_version,
        createdAt: userData.created_at,
        lastLoginAt: userData.last_login_at
      },
      payoutDestination: payout.rows.length > 0 ? {
        id: payout.rows[0].id,
        status: payout.rows[0].status,
        maskedEmail: payout.rows[0].value_masked,
        submittedAt: payout.rows[0].submitted_at,
        reviewedAt: payout.rows[0].reviewed_at
      } : null
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

// GET /api/users/balance - Get user balance
router.get('/balance', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT COALESCE(SUM(amount), 0) as balance FROM points_ledger WHERE user_id = $1',
      [req.user.userId]
    );

    res.json({
      success: true,
      balance: parseInt(result.rows[0].balance)
    });
  } catch (error) {
    console.error('Balance error:', error);
    res.status(500).json({ error: 'Failed to get balance' });
  }
});

module.exports = router;
