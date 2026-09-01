const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const db = require('../models/db');
const { authenticateAdmin, requireRole } = require('../middleware/auth');

const router = express.Router();
const MAX_EVIDENCE_BYTES = 8 * 1024 * 1024;
const MISSION_SLUG = 'manus-account-proof';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 1, fileSize: MAX_EVIDENCE_BYTES, fields: 8 },
  fileFilter: (_req, file, callback) => {
    const accepted = new Set(['image/jpeg', 'image/png', 'image/webp']);
    if (!accepted.has(file.mimetype)) {
      return callback(new Error('UNSUPPORTED_EVIDENCE_TYPE'));
    }
    return callback(null, true);
  },
});

const submissionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => normalizeSupportCode(req.body?.support_code) || 'missing-support-code',
  message: {
    error: 'Muitas tentativas para este codigo de suporte. Aguarde antes de enviar novamente.',
    code: 'EVIDENCE_RATE_LIMIT',
  },
});

const statusLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => normalizeSupportCode(req.body?.support_code) || 'missing-support-code',
  message: {
    error: 'Muitas consultas. Aguarde alguns minutos e tente novamente.',
    code: 'EVIDENCE_STATUS_RATE_LIMIT',
  },
});

function receiveEvidence(req, res, next) {
  upload.single('evidence')(req, res, (error) => {
    if (!error) return next();

    if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: 'A imagem deve ter no maximo 8 MB.',
        code: 'EVIDENCE_TOO_LARGE',
      });
    }
    if (error.message === 'UNSUPPORTED_EVIDENCE_TYPE') {
      return res.status(400).json({
        error: 'Envie uma imagem JPG, PNG ou WebP.',
        code: 'EVIDENCE_UNSUPPORTED_TYPE',
      });
    }
    return next(error);
  });
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function normalizeSupportCode(value) {
  return typeof value === 'string' ? value.trim().toUpperCase() : '';
}

function validIdentity(email, supportCode) {
  return /^\S+@\S+\.\S+$/.test(email)
    && /^CP-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/.test(supportCode);
}

function detectedImageMime(buffer) {
  if (!buffer || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (
    buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  ) return 'image/png';
  if (
    buffer.subarray(0, 4).toString('ascii') === 'RIFF'
    && buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) return 'image/webp';
  return null;
}

function safeFilename(value) {
  if (typeof value !== 'string') return null;
  return value.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 255) || null;
}

function publicSubmission(row) {
  return {
    id: row.id,
    protocol: row.public_protocol,
    status: row.status,
    rewardPoints: Number(row.reward_points || 500),
    minimumCredits: Number(row.minimum_external_credits || 1800),
    submittedAt: row.submitted_at,
    reviewedAt: row.reviewed_at,
    rejectionReason: row.rejection_reason || null,
  };
}

async function findPortalUser(queryable, email, supportCode) {
  const result = await queryable.query(
    `SELECT id, email, support_code
       FROM users
      WHERE lower(email) = $1
        AND upper(support_code) = $2
        AND is_active = true
        AND is_banned = false
        AND merged_into_user_id IS NULL
      LIMIT 1`,
    [email, supportCode]
  );
  return result.rows[0] || null;
}

async function findActiveMission(queryable) {
  const result = await queryable.query(
    `SELECT id, reward_points, minimum_external_credits, target_value
       FROM missions
      WHERE slug = $1
        AND verification_mode = 'manual_evidence'
        AND evidence_required = true
        AND is_active = true
      LIMIT 1`,
    [MISSION_SLUG]
  );
  return result.rows[0] || null;
}

router.post('/submit', receiveEvidence, submissionLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const supportCode = normalizeSupportCode(req.body?.support_code);
  const missionSlug = String(req.body?.mission_slug || '');
  const attestationAccepted = String(req.body?.attestation || '').toLowerCase() === 'true';

  if (!validIdentity(email, supportCode)) {
    return res.status(400).json({
      error: 'Confira o e-mail e o codigo de suporte da sua conta CashPix.',
      code: 'INVALID_CASHPIX_IDENTITY',
    });
  }
  if (missionSlug !== MISSION_SLUG) {
    return res.status(400).json({ error: 'Missao invalida.', code: 'INVALID_MISSION' });
  }
  if (!attestationAccepted) {
    return res.status(400).json({
      error: 'Confirme que a captura e verdadeira e pertence a sua conta.',
      code: 'ATTESTATION_REQUIRED',
    });
  }
  if (!req.file?.buffer) {
    return res.status(400).json({
      error: 'Anexe a captura da sua conta Manus.',
      code: 'EVIDENCE_REQUIRED',
    });
  }

  const actualMime = detectedImageMime(req.file.buffer);
  if (!actualMime || actualMime !== req.file.mimetype) {
    return res.status(400).json({
      error: 'O conteudo do arquivo nao corresponde a uma imagem JPG, PNG ou WebP valida.',
      code: 'INVALID_EVIDENCE_CONTENT',
    });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const user = await findPortalUser(client, email, supportCode);
    const mission = await findActiveMission(client);

    if (!user) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        error: 'Nao foi possivel confirmar a conta CashPix com os dados informados.',
        code: 'CASHPIX_ACCOUNT_NOT_FOUND',
      });
    }
    if (!mission) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Esta missao ainda nao esta disponivel para envios.',
        code: 'MISSION_NOT_AVAILABLE',
      });
    }

    const existing = await client.query(
      `SELECT s.*, m.reward_points, m.minimum_external_credits
         FROM mission_evidence_submissions s
         JOIN missions m ON m.id = s.mission_id
        WHERE s.user_id = $1 AND s.mission_id = $2
          AND s.status IN ('pending', 'approved')
        ORDER BY s.submitted_at DESC
        LIMIT 1
        FOR UPDATE OF s`,
      [user.id, mission.id]
    );
    if (existing.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: existing.rows[0].status === 'approved'
          ? 'Sua comprovacao ja foi aprovada. Volte ao CashPix para resgatar.'
          : 'Ja existe uma comprovacao em analise para esta conta.',
        code: existing.rows[0].status === 'approved'
          ? 'EVIDENCE_ALREADY_APPROVED'
          : 'EVIDENCE_ALREADY_PENDING',
        submission: publicSubmission(existing.rows[0]),
      });
    }

    const sha256 = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    const duplicate = await client.query(
      'SELECT id FROM mission_evidence_submissions WHERE evidence_sha256 = $1 LIMIT 1',
      [sha256]
    );
    if (duplicate.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Esta imagem ja foi usada em uma solicitacao. Tire uma nova captura da sua conta.',
        code: 'EVIDENCE_ALREADY_USED',
      });
    }

    const id = crypto.randomUUID();
    const protocol = `CPM-${id.replace(/-/g, '').slice(0, 12).toUpperCase()}`;
    const result = await client.query(
      `INSERT INTO mission_evidence_submissions (
         id, public_protocol, mission_id, user_id, status,
         evidence_data, evidence_sha256, evidence_mime, evidence_size,
         original_filename, attestation_accepted, submitted_ip
       ) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9, true, $10)
       RETURNING id, public_protocol, status, submitted_at, reviewed_at, rejection_reason`,
      [
        id,
        protocol,
        mission.id,
        user.id,
        req.file.buffer,
        sha256,
        actualMime,
        req.file.size,
        safeFilename(req.file.originalname),
        req.ip,
      ]
    );

    await client.query(
      `INSERT INTO audit_log (
         actor_id, actor_type, action, target_type, target_id,
         new_value, ip_address
       ) VALUES ($1, 'USER', 'MISSION_EVIDENCE_SUBMITTED', 'MISSION_EVIDENCE', $2, $3, $4)`,
      [
        user.id,
        id,
        JSON.stringify({ missionId: mission.id, protocol, evidenceSha256: sha256 }),
        req.ip,
      ]
    );

    await client.query('COMMIT');
    return res.status(201).json({
      success: true,
      submission: publicSubmission({ ...result.rows[0], ...mission }),
    });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Ja existe uma solicitacao ativa ou esta imagem ja foi utilizada.',
        code: 'EVIDENCE_CONFLICT',
      });
    }
    console.error('Mission evidence submit error:', error);
    return res.status(500).json({ error: 'Erro ao enviar comprovacao.' });
  } finally {
    client.release();
  }
});

router.post('/status', statusLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const supportCode = normalizeSupportCode(req.body?.support_code);
  const missionSlug = String(req.body?.mission_slug || '');

  if (!validIdentity(email, supportCode) || missionSlug !== MISSION_SLUG) {
    return res.status(400).json({
      error: 'Confira os dados informados.',
      code: 'INVALID_STATUS_LOOKUP',
    });
  }

  try {
    const user = await findPortalUser(db, email, supportCode);
    if (!user) {
      return res.status(404).json({
        error: 'Nenhuma solicitacao foi encontrada para os dados informados.',
        code: 'EVIDENCE_NOT_FOUND',
      });
    }

    const result = await db.query(
      `SELECT s.id, s.public_protocol, s.status, s.submitted_at,
              s.reviewed_at, s.rejection_reason,
              m.reward_points, m.minimum_external_credits
         FROM mission_evidence_submissions s
         JOIN missions m ON m.id = s.mission_id
        WHERE s.user_id = $1 AND m.slug = $2
        ORDER BY s.submitted_at DESC
        LIMIT 1`,
      [user.id, MISSION_SLUG]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'Nenhuma solicitacao foi encontrada para os dados informados.',
        code: 'EVIDENCE_NOT_FOUND',
      });
    }
    return res.json({ success: true, submission: publicSubmission(result.rows[0]) });
  } catch (error) {
    console.error('Mission evidence status error:', error);
    return res.status(500).json({ error: 'Erro ao consultar comprovacao.' });
  }
});

router.get('/admin/list', authenticateAdmin, async (req, res) => {
  const allowedStatuses = new Set(['pending', 'approved', 'rejected', 'all']);
  const status = allowedStatuses.has(String(req.query.status))
    ? String(req.query.status)
    : 'pending';
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : null;
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);

  try {
    const result = await db.query(
      `SELECT s.id, s.public_protocol, s.status, s.evidence_sha256,
              s.evidence_mime, s.evidence_size, s.original_filename,
              s.attestation_accepted, s.submitted_ip, s.rejection_reason,
              s.submitted_at, s.reviewed_at, s.reviewer_id,
              u.id AS user_id, u.email AS user_email, u.support_code,
              m.id AS mission_id, m.title AS mission_title, m.reward_points,
              m.minimum_external_credits,
              a.name AS reviewer_name, a.email AS reviewer_email
         FROM mission_evidence_submissions s
         JOIN users u ON u.id = s.user_id
         JOIN missions m ON m.id = s.mission_id
         LEFT JOIN admin_users a ON a.id = s.reviewer_id
        WHERE ($1::text = 'all' OR s.status = $1)
          AND ($2::uuid IS NULL OR s.mission_id = $2)
        ORDER BY
          CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
          s.submitted_at DESC
        LIMIT $3`,
      [status, missionId, limit]
    );
    return res.json({ success: true, submissions: result.rows });
  } catch (error) {
    console.error('Admin evidence list error:', error);
    return res.status(500).json({ error: 'Erro ao buscar comprovacoes.' });
  }
});

router.get('/admin/:id/image', authenticateAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT evidence_data, evidence_mime, evidence_sha256
         FROM mission_evidence_submissions WHERE id = $1`,
      [req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Comprovacao nao encontrada.' });

    const row = result.rows[0];
    res.set({
      'Content-Type': row.evidence_mime,
      'Content-Length': row.evidence_data.length,
      'Cache-Control': 'private, no-store, max-age=0',
      Pragma: 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      ETag: `"${row.evidence_sha256}"`,
    });
    return res.send(row.evidence_data);
  } catch (error) {
    console.error('Admin evidence image error:', error);
    return res.status(500).json({ error: 'Erro ao carregar imagem.' });
  }
});

router.post(
  '/admin/:id/approve',
  authenticateAdmin,
  requireRole('admin', 'finance'),
  async (req, res) => {
    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT s.*, m.target_value, m.title, m.reward_points
           FROM mission_evidence_submissions s
           JOIN missions m ON m.id = s.mission_id
          WHERE s.id = $1
          FOR UPDATE OF s`,
        [req.params.id]
      );
      const submission = result.rows[0];
      if (!submission) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Comprovacao nao encontrada.' });
      }
      if (submission.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Esta comprovacao ja foi analisada.',
          code: 'EVIDENCE_ALREADY_REVIEWED',
        });
      }

      await client.query(
        `UPDATE mission_evidence_submissions
            SET status = 'approved', reviewer_id = $2, reviewed_at = NOW(),
                rejection_reason = NULL, updated_at = NOW()
          WHERE id = $1`,
        [submission.id, req.admin.id]
      );

      const today = new Date().toISOString().split('T')[0];
      await client.query(
        `INSERT INTO mission_progress (
           user_id, mission_id, current_value, is_completed, is_claimed,
           completed_at, reset_date
         ) VALUES ($1, $2, $3, true, false, NOW(), $4)
         ON CONFLICT (user_id, mission_id, reset_date) DO UPDATE
            SET current_value = GREATEST(mission_progress.current_value, EXCLUDED.current_value),
                is_completed = true,
                completed_at = COALESCE(mission_progress.completed_at, NOW())`,
        [submission.user_id, submission.mission_id, submission.target_value, today]
      );

      await client.query(
        `INSERT INTO audit_log (
           actor_id, actor_type, action, target_type, target_id,
           old_value, new_value, ip_address
         ) VALUES ($1, 'ADMIN', 'MISSION_EVIDENCE_APPROVED', 'MISSION_EVIDENCE', $2,
                   $3, $4, $5)`,
        [
          req.admin.id,
          submission.id,
          JSON.stringify({ status: 'pending' }),
          JSON.stringify({ status: 'approved', userId: submission.user_id, missionId: submission.mission_id }),
          req.ip,
        ]
      );

      await client.query('COMMIT');
      return res.json({
        success: true,
        message: 'Comprovacao aprovada. A recompensa esta liberada para coleta.',
      });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Admin evidence approve error:', error);
      return res.status(500).json({ error: 'Erro ao aprovar comprovacao.' });
    } finally {
      client.release();
    }
  }
);

router.post(
  '/admin/:id/reject',
  authenticateAdmin,
  requireRole('admin', 'finance'),
  async (req, res) => {
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
    if (reason.length < 5 || reason.length > 500) {
      return res.status(400).json({
        error: 'Informe um motivo de rejeicao entre 5 e 500 caracteres.',
        code: 'REJECTION_REASON_REQUIRED',
      });
    }

    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT * FROM mission_evidence_submissions WHERE id = $1 FOR UPDATE`,
        [req.params.id]
      );
      const submission = result.rows[0];
      if (!submission) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Comprovacao nao encontrada.' });
      }
      if (submission.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Esta comprovacao ja foi analisada.',
          code: 'EVIDENCE_ALREADY_REVIEWED',
        });
      }

      await client.query(
        `UPDATE mission_evidence_submissions
            SET status = 'rejected', reviewer_id = $2, reviewed_at = NOW(),
                rejection_reason = $3, updated_at = NOW()
          WHERE id = $1`,
        [submission.id, req.admin.id, reason]
      );
      await client.query(
        `INSERT INTO audit_log (
           actor_id, actor_type, action, target_type, target_id,
           old_value, new_value, ip_address
         ) VALUES ($1, 'ADMIN', 'MISSION_EVIDENCE_REJECTED', 'MISSION_EVIDENCE', $2,
                   $3, $4, $5)`,
        [
          req.admin.id,
          submission.id,
          JSON.stringify({ status: 'pending' }),
          JSON.stringify({ status: 'rejected', reason }),
          req.ip,
        ]
      );

      await client.query('COMMIT');
      return res.json({ success: true, message: 'Comprovacao rejeitada.' });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Admin evidence reject error:', error);
      return res.status(500).json({ error: 'Erro ao rejeitar comprovacao.' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;
