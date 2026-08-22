import { Router, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { pool, query } from '../db.js';
import { authenticateToken, requireGlobalAdmin, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';

const router = Router();

const normaliseKey = (value: unknown) => String(value ?? '').trim().toUpperCase();
const normaliseFingerprint = (value: unknown) => String(value ?? '').trim();

// Passwords are never stored as plaintext.  The global administrator can
// reveal a generated password through the protected console while this key is
// present on the server.  Set LICENSE_CREDENTIAL_KEY in Render; the fallback
// keeps existing installations working until that variable is added.
const credentialKey = crypto.createHash('sha256')
  .update(process.env.LICENSE_CREDENTIAL_KEY || process.env.JWT_SECRET || 'mobile-ic-credential-key')
  .digest();
const encryptCredential = (value: string) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', credentialKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
};
const decryptCredential = (value: string) => {
  const [ivText, tagText, dataText] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', credentialKey, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(dataText, 'base64url')), decipher.final()]).toString('utf8');
};

const requestDevice = (req: any) => ({
  name: String(req.headers['x-device-name'] || '').trim() || null,
  model: String(req.headers['x-device-model'] || req.headers['user-agent'] || '').trim().slice(0, 255) || null,
  location: String(req.headers['x-device-location'] || '').trim().slice(0, 255) || null,
  ip: req.ip || null,
});

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
      await client.query(`UPDATE licenses SET status = 'revoked' WHERE id = $1 AND status <> 'revoked'`, [license.id]);
      await client.query('COMMIT');
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
        `UPDATE licenses SET device_fingerprint = $1, activated_at = CURRENT_TIMESTAMP, status = 'active',
          device_name = $3, device_model = $4, device_location = $5, last_ip = $6 WHERE id = $2`,
        [fingerprint, license.id, requestDevice(req).name, requestDevice(req).model, requestDevice(req).location, requestDevice(req).ip],
      );
    } else {
      const device = requestDevice(req);
      await client.query(
        `UPDATE licenses SET device_name = COALESCE($1, device_name), device_model = COALESCE($2, device_model),
          device_location = COALESCE($3, device_location), last_ip = COALESCE($4, last_ip) WHERE id = $5`,
        [device.name, device.model, device.location, device.ip, license.id],
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
    // Expiry is enforced here as well as during login, so the console never
    // presents an expired license as active after the clock has passed.
    await query(`UPDATE licenses SET status = 'revoked' WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND status <> 'revoked'`);
    const result = await query(
      `SELECT l.*, u.email AS admin_username,
              (l.expires_at IS NOT NULL AND l.expires_at <= CURRENT_TIMESTAMP) AS expired
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

router.get('/admin/licenses/:id/credentials', authenticateToken, requireGlobalAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const result = await query(`SELECT l.license_key, u.email AS username, l.admin_password_ciphertext
      FROM licenses l LEFT JOIN users u ON u.license_id = l.id WHERE l.id = $1`, [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'License not found' });
    const row = result.rows[0];
    if (!row.admin_password_ciphertext) return res.status(404).json({ error: 'Password is unavailable for this older license' });
    return res.json({ license_key: row.license_key, username: row.username, password: decryptCredential(row.admin_password_ciphertext) });
  } catch (error) {
    logger.error({ error }, 'Failed to reveal license credentials');
    return res.status(500).json({ error: 'Could not reveal credentials' });
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
          await client.query(`UPDATE licenses SET admin_password_ciphertext = $1 WHERE id = $2`, [encryptCredential(generatedPassword), result.rows[0].id]);
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
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const license = await client.query('SELECT id, license_key FROM licenses WHERE id = $1 FOR UPDATE', [req.params.id]);
    if (!license.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'License not found' });
    }
    await client.query(`UPDATE licenses SET status = 'revoked' WHERE id = $1`, [req.params.id]);
    await client.query('COMMIT');
    await writeLog(license.rows[0].license_key, '', 'revoked', req, { admin_id: req.user?.id });
    return res.json({ success: true, revoked: true });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    logger.error({ error }, 'Failed to revoke license');
    return res.status(500).json({ error: 'Failed to revoke license' });
  } finally {
    client.release();
  }
});

router.delete('/admin/licenses/:id', authenticateToken, requireGlobalAdmin, async (req: AuthRequest, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const license = await client.query('SELECT id, license_key FROM licenses WHERE id = $1 FOR UPDATE', [req.params.id]);
    if (!license.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'License not found' }); }
    const admins = await client.query(`SELECT id FROM users WHERE license_id = $1 AND role = 'admin'`, [req.params.id]);
    for (const admin of admins.rows) {
      await client.query(`DELETE FROM users WHERE id IN (SELECT id FROM panels WHERE owner_admin_id = $1)`, [admin.id]);
    }
    await client.query('DELETE FROM users WHERE license_id = $1', [req.params.id]);
    await client.query('DELETE FROM licenses WHERE id = $1', [req.params.id]);
    await client.query('COMMIT');
    await writeLog(license.rows[0].license_key, '', 'deleted', req, { admin_id: req.user?.id });
    return res.json({ success: true, deleted: true });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    logger.error({ error }, 'Failed to delete license');
    return res.status(500).json({ error: 'Failed to delete license' });
  } finally { client.release(); }
});

export default router;
