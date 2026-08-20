import { Router, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { pool, query } from '../db.js';
import { authenticateToken, requireGlobalAdmin, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';

const router = Router();

const normaliseKey = (value: unknown) => String(value ?? '').trim().toUpperCase();
const normaliseFingerprint = (value: unknown) => String(value ?? '').trim();

const writeLog = async (licenseKey: string, fingerprint: string, result: string, req: any, details: Record<string, unknown> = {}) => {
  await query(
    `INSERT INTO license_verification_log (license_key, device_fingerprint, result, ip_address, details)
     VALUES ($1, $2, $3, $4, $5)`,
    [licenseKey || 'UNKNOWN', fingerprint || null, result, req.ip || null, JSON.stringify(details)],
  );
};

const evaluateLicense = async (licenseKey: string, fingerprint: string, req: any, activate: boolean) => {
  if (!licenseKey || !fingerprint) {
    await writeLog(licenseKey, fingerprint, 'missing_input', req);
    return { ok: false, status: 400, error: 'License key and device fingerprint are required' };
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query('SELECT * FROM licenses WHERE license_key = $1 FOR UPDATE', [licenseKey]);
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      await writeLog(licenseKey, fingerprint, 'invalid_key', req);
      return { ok: false, status: 401, error: 'Invalid license key' };
    }
    const license = result.rows[0];
    if (license.status === 'revoked') {
      await client.query('ROLLBACK');
      await writeLog(licenseKey, fingerprint, 'revoked', req);
      return { ok: false, status: 403, error: 'This license has been revoked' };
    }
    if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      await writeLog(licenseKey, fingerprint, 'expired', req);
      return { ok: false, status: 403, error: 'This license has expired' };
    }
    if (license.device_fingerprint && license.device_fingerprint !== fingerprint) {
      await client.query('ROLLBACK');
      await writeLog(licenseKey, fingerprint, 'different_device', req);
      return { ok: false, status: 409, error: 'This license is already in use on another device' };
    }
    if (!activate && license.status !== 'active') {
      await client.query('ROLLBACK');
      await writeLog(licenseKey, fingerprint, 'not_activated', req);
      return { ok: false, status: 403, error: 'This license has not been activated' };
    }
    if (!license.device_fingerprint) {
      await client.query(
        `UPDATE licenses SET device_fingerprint = $1, activated_at = CURRENT_TIMESTAMP, status = 'active' WHERE id = $2`,
        [fingerprint, license.id],
      );
    }
    await client.query('COMMIT');
    await writeLog(licenseKey, fingerprint, activate ? 'activated' : 'success', req);
    return { ok: true, license: { id: license.id, expires_at: license.expires_at, status: 'active' } };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};

export const activateLicenseForLogin = (licenseKey: string, fingerprint: string, req: any) =>
  evaluateLicense(normaliseKey(licenseKey), normaliseFingerprint(fingerprint), req, true);

router.post('/activate', async (req, res) => {
  try {
    const result = await evaluateLicense(normaliseKey(req.body.license_key), normaliseFingerprint(req.body.device_fingerprint), req, true);
    return res.status(result.status || 200).json(result.ok ? result : { error: result.error });
  } catch (error) {
    logger.error({ error }, 'License activation failed');
    return res.status(500).json({ error: 'License service unavailable' });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const result = await evaluateLicense(normaliseKey(req.body.license_key), normaliseFingerprint(req.body.device_fingerprint), req, false);
    return res.status(result.status || 200).json(result.ok ? result : { error: result.error, revoked: result.error?.includes('revoked') });
  } catch (error) {
    logger.error({ error }, 'License verification failed');
    return res.status(503).json({ error: 'License verification temporarily unavailable' });
  }
});

const newLicenseKey = () => {
  const raw = crypto.randomBytes(10).toString('hex').toUpperCase();
  return raw.match(/.{1,5}/g)!.join('-');
};

router.get('/admin/licenses', authenticateToken, requireGlobalAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const result = await query(
      `SELECT l.*, u.email AS admin_username
       FROM licenses l
       LEFT JOIN users u ON u.license_id = l.id
       ORDER BY l.created_at DESC`,
    );
    return res.json({ licenses: result.rows });
  } catch (error) {
    logger.error({ error }, 'Failed to list licenses');
    return res.status(500).json({ error: 'Failed to list licenses' });
  }
});

router.post('/admin/licenses', authenticateToken, requireGlobalAdmin, async (req: AuthRequest, res: Response) => {
  const issuedTo = String(req.body.issued_to ?? '').trim() || null;
  const expiresAt = req.body.expires_at ? new Date(req.body.expires_at) : null;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ error: 'Invalid expiry date' });
  try {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const key = newLicenseKey();
      try {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const result = await client.query(
            `INSERT INTO licenses (license_key, issued_to, expires_at) VALUES ($1, $2, $3) RETURNING *`,
            [key, issuedTo, expiresAt],
          );
          const username = `admin_${key.replace(/-/g, '').slice(-8).toLowerCase()}`;
          const generatedPassword = crypto.randomBytes(9).toString('base64url');
          const passwordHash = await bcrypt.hash(generatedPassword, 12);
          await client.query(
            `INSERT INTO users (email, password_hash, role, license_id) VALUES ($1, $2, 'admin', $3)`,
            [username, passwordHash, result.rows[0].id],
          );
          await client.query('COMMIT');
          return res.status(201).json({
            license: result.rows[0],
            credentials: { username, password: generatedPassword },
            warning: 'Save these credentials now. The password is not shown again.',
          });
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        } finally {
          client.release();
        }
      } catch (error: any) {
        if (error.code !== '23505') throw error;
      }
    }
    return res.status(500).json({ error: 'Could not generate a unique license key' });
  } catch (error) {
    logger.error({ error }, 'Failed to generate license');
    return res.status(500).json({ error: 'Failed to generate license' });
  }
});

router.post('/admin/licenses/:id/revoke', authenticateToken, requireGlobalAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const result = await query(
      `UPDATE licenses SET status = 'revoked', device_fingerprint = NULL WHERE id = $1 RETURNING license_key`,
      [req.params.id],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'License not found' });
    await writeLog(result.rows[0].license_key, '', 'revoked_by_admin', req, { admin_id: req.user?.id });
    return res.json({ success: true });
  } catch (error) {
    logger.error({ error }, 'Failed to revoke license');
    return res.status(500).json({ error: 'Failed to revoke license' });
  }
});

export default router;
