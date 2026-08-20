import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import { pool, query } from '../db.js';
import { authenticateToken, requireAdmin, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';
import { updateLiveKitParticipantPermissions } from '../services/livekit.js';

const router = Router();

// Remove a panel account and all of its routes. The database foreign keys
// cascade the panel and permission rows, while audit history is retained.
router.delete('/panels/:panelId', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
  const { panelId } = req.params;
  try {
    const result = await query(
      `DELETE FROM users
       WHERE id = $1 AND role = 'panel_user'
         AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM panels p WHERE p.id = users.id AND p.owner_admin_id = $2))
       RETURNING id`,
      [panelId, req.user?.license_id ? req.user.id : null],
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Panel not found' });
    logger.info({ adminId: req.user?.id, panelId }, 'Admin removed panel');
    return res.json({ success: true, panelId });
  } catch (err: any) {
    logger.error({ err, panelId }, 'Failed to remove panel');
    return res.status(500).json({ error: 'Failed to remove panel' });
  }
});

// Provision a station account. New stations begin fully blocked; the admin
// explicitly enables routes in the matrix after provisioning.
router.post('/panels', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
  const { panel_code, name, location, password } = req.body;
  const username = String(req.body.username ?? req.body.email ?? '').trim();
  if (![panel_code, name, location, username, password].every(value => typeof value === 'string' && value.trim())) {
    return res.status(400).json({ error: 'Panel code, name, location, username, and password are required' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Station password must be at least 4 characters' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const duplicate = await client.query(
      `SELECT id FROM panels WHERE (LOWER(name) = LOWER($1) OR LOWER(panel_code) = LOWER($2))
       AND ($3::uuid IS NULL OR owner_admin_id = $3) LIMIT 1`,
      [name.trim(), panel_code.trim(), req.user?.license_id ? req.user.id : null],
    );
    if (duplicate.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'A panel with that name or panel code already exists' });
    }
    const duplicateLogin = await client.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [username]);
    if (duplicateLogin.rowCount) {
      // Usernames are tenant-scoped. Retire an old account only when its
      // administrator's license is no longer usable; never reattach it.
      await client.query(
        `UPDATE users old_user
         SET email = 'retired_' || REPLACE(old_user.id::text, '-', '') || '_' || old_user.email
         FROM panels old_panel
         JOIN users old_admin ON old_admin.id = old_panel.owner_admin_id
         JOIN licenses old_license ON old_license.id = old_admin.license_id
         WHERE old_user.id = old_panel.id AND old_user.role = 'panel_user'
           AND LOWER(old_user.email) = LOWER($1)
           AND (old_license.status = 'revoked' OR (old_license.expires_at IS NOT NULL AND old_license.expires_at <= CURRENT_TIMESTAMP))`,
        [username],
      );
      const stillUsed = await client.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [username]);
      if (stillUsed.rowCount) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'That panel username is already in use by an active administrator' });
      }
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const userRes = await client.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
      [username.toLowerCase(), passwordHash, 'panel_user']
    );
    const panelId = userRes.rows[0].id;
    const panelRes = await client.query(
      `INSERT INTO panels (id, panel_code, name, location, status, owner_admin_id)
       VALUES ($1, $2, $3, $4, 'offline', $5)
       RETURNING id, panel_code, name, location, status, created_at`,
      [panelId, panel_code.trim().toUpperCase(), name.trim(), location.trim(), req.user?.license_id ? req.user.id : null]
    );

    // Add both directions for every pair. All routes are blocked by default.
    const existing = await client.query(
      `SELECT id FROM panels WHERE id <> $1 AND ($2::uuid IS NULL OR owner_admin_id = $2)`,
      [panelId, req.user?.license_id ? req.user.id : null],
    );
    for (const other of existing.rows) {
      await client.query(
        `INSERT INTO permissions (panel_a_id, panel_b_id, state, updated_by_admin_id)
         VALUES ($1, $2, 'blocked', $3), ($2, $1, 'blocked', $3)`,
        [panelId, other.id, req.user?.id]
      );
    }
    await client.query(
      `INSERT INTO audit_logs (event_type, admin_id, panel_from, details)
       VALUES ('system_event', $1, $2, $3)`,
      [req.user?.id, panelId, JSON.stringify({ action: 'station_provisioned', panel_code: panelRes.rows[0].panel_code })]
    );
    await client.query('COMMIT');
    return res.status(201).json(panelRes.rows[0]);
  } catch (err: any) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: 'That station code or login email is already in use' });
    }
    logger.error({ err }, 'Failed to provision station');
    return res.status(500).json({ error: 'Failed to provision station' });
  } finally {
    client.release();
  }
});

// Edit an existing panel account. Password is optional; when omitted the
// existing password remains unchanged. This route is admin-only.
router.put('/panels/:panelId', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
  const { panelId } = req.params;
  const { panel_code, name, location, password } = req.body;
  const username = String(req.body.username ?? req.body.email ?? '').trim();
  if (![panel_code, name, location, username].every(value => typeof value === 'string' && value.trim())) {
    return res.status(400).json({ error: 'Panel code, name, location, and username are required' });
  }
  if (password !== undefined && password !== '' && (typeof password !== 'string' || password.length < 4)) {
    return res.status(400).json({ error: 'Station password must be at least 4 characters' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const duplicate = await client.query(
      `SELECT id FROM panels WHERE id <> $1 AND (LOWER(name) = LOWER($2) OR LOWER(panel_code) = LOWER($3))
       AND ($4::uuid IS NULL OR owner_admin_id = $4) LIMIT 1`,
      [panelId, name.trim(), panel_code.trim(), req.user?.license_id ? req.user.id : null],
    );
    if (duplicate.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'A panel with that name or panel code already exists' });
    }
    const duplicateLogin = await client.query('SELECT id FROM users WHERE id <> $1 AND LOWER(email) = LOWER($2) LIMIT 1', [panelId, username]);
    if (duplicateLogin.rowCount) {
      await client.query(
        `UPDATE users old_user
         SET email = 'retired_' || REPLACE(old_user.id::text, '-', '') || '_' || old_user.email
         FROM panels old_panel
         JOIN users old_admin ON old_admin.id = old_panel.owner_admin_id
         JOIN licenses old_license ON old_license.id = old_admin.license_id
         WHERE old_user.id = old_panel.id AND old_user.role = 'panel_user'
           AND LOWER(old_user.email) = LOWER($2)
           AND (old_license.status = 'revoked' OR (old_license.expires_at IS NOT NULL AND old_license.expires_at <= CURRENT_TIMESTAMP))`,
        [panelId, username],
      );
      const stillUsed = await client.query('SELECT id FROM users WHERE id <> $1 AND LOWER(email) = LOWER($2) LIMIT 1', [panelId, username]);
      if (stillUsed.rowCount) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'That panel username is already in use by an active administrator' });
      }
    }
    await client.query(
      'UPDATE users SET email = $1 WHERE id = $2 AND role = \'panel_user\' AND ($3::uuid IS NULL OR EXISTS (SELECT 1 FROM panels p WHERE p.id = users.id AND p.owner_admin_id = $3))',
      [username.toLowerCase(), panelId, req.user?.license_id ? req.user.id : null],
    );
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      await client.query('UPDATE users SET password_hash = $1 WHERE id = $2 AND role = \'panel_user\'', [hash, panelId]);
    }
    const result = await client.query(
      `UPDATE panels SET panel_code = $1, name = $2, location = $3 WHERE id = $4
       AND ($5::uuid IS NULL OR owner_admin_id = $5)
       RETURNING id, panel_code, name, location, status, created_at`,
      [panel_code.trim().toUpperCase(), name.trim(), location.trim(), panelId, req.user?.license_id ? req.user.id : null],
    );
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Panel not found' });
    }
    await client.query('COMMIT');
    return res.json(result.rows[0]);
  } catch (err: any) {
    await client.query('ROLLBACK');
    logger.error({ err, panelId }, 'Failed to edit panel');
    return res.status(err.code === '23505' ? 409 : 500).json({ error: err.code === '23505' ? 'Panel details already exist' : 'Failed to edit panel' });
  } finally { client.release(); }
});

// Update permission state between panel_a and panel_b
router.put('/permissions', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
  const { panel_a_id, panel_b_id, state } = req.body;
  const adminId = req.user?.id;

  const validStates = ['blocked', 'listen', 'talk', 'both'];
  if (!panel_a_id || !panel_b_id || !state || !validStates.includes(state)) {
    return res.status(400).json({ error: 'Invalid parameters. Require panel_a_id, panel_b_id, and state (blocked|listen|talk|both)' });
  }

  try {
    if (req.user?.license_id) {
      const owned = await query(
        `SELECT COUNT(*)::int AS count FROM panels
         WHERE id = ANY($1::uuid[]) AND owner_admin_id = $2`,
        [[panel_a_id, panel_b_id], req.user.id],
      );
      if (Number(owned.rows[0]?.count || 0) !== 2) {
        return res.status(403).json({ error: 'You can only edit your own matrix' });
      }
    }
    // 1. Get old state
    const existingRes = await query(
      'SELECT state FROM permissions WHERE panel_a_id = $1 AND panel_b_id = $2',
      [panel_a_id, panel_b_id]
    );
    const oldState = existingRes.rows.length > 0 ? existingRes.rows[0].state : 'blocked';

    // 2. Upsert permission state
    await query(
      `INSERT INTO permissions (panel_a_id, panel_b_id, state, updated_by_admin_id, updated_at)
       VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
       ON CONFLICT (panel_a_id, panel_b_id)
       DO UPDATE SET state = $3, updated_by_admin_id = $4, updated_at = CURRENT_TIMESTAMP`,
      [panel_a_id, panel_b_id, state, adminId]
    );

    // 3. Write immutable audit log
    await query(
      `INSERT INTO audit_logs (event_type, admin_id, panel_from, panel_to, old_state, new_state, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        'permission_change',
        adminId,
        panel_a_id,
        panel_b_id,
        oldState,
        state,
        JSON.stringify({ updated_by: req.user?.email, timestamp: new Date().toISOString() }),
      ]
    );

    logger.info(
      { adminId, panel_a_id, panel_b_id, oldState, newState: state },
      'Admin updated panel intercom permission matrix'
    );

    // 4. Fetch updated permissions for panel_a to push to LiveKit participant metadata
    const permsRes = await query(
      'SELECT panel_b_id, state FROM permissions WHERE panel_a_id = $1',
      [panel_a_id]
    );

    const activePermissionsMap: Record<string, string> = {};
    permsRes.rows.forEach((r) => {
      activePermissionsMap[r.panel_b_id] = r.state;
    });

    const metadataString = JSON.stringify({
      updatedAt: Date.now(),
      permissions: activePermissionsMap,
    });

    // Notify LiveKit server to update participant metadata dynamically
    await updateLiveKitParticipantPermissions(panel_a_id, metadataString);

    return res.json({
      success: true,
      panel_a_id,
      panel_b_id,
      old_state: oldState,
      new_state: state,
    });
  } catch (err: any) {
    logger.error({ err }, 'Failed to update admin permissions matrix');
    return res.status(500).json({ error: 'Failed to update permissions' });
  }
});

export default router;
