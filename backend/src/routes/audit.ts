import { Router, Response } from 'express';
import { query } from '../db.js';
import { authenticateToken, requireAdmin, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';

const router = Router();

// GET /api/admin/audit-logs - Filterable table
router.get('/', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
  const { event_type, panel_id, start_date, end_date, limit = '100', offset = '0' } = req.query;

  try {
    let whereClause = 'WHERE 1=1';
    const params: any[] = [];
    let paramIdx = 1;

    if (event_type) {
      whereClause += ` AND a.event_type = $${paramIdx++}`;
      params.push(event_type);
    }

    if (panel_id) {
      whereClause += ` AND (a.panel_from = $${paramIdx} OR a.panel_to = $${paramIdx})`;
      paramIdx++;
      params.push(panel_id);
    }

    if (start_date) {
      whereClause += ` AND a.created_at >= $${paramIdx++}`;
      params.push(start_date);
    }

    if (end_date) {
      whereClause += ` AND a.created_at <= $${paramIdx++}`;
      params.push(end_date);
    }

    const queryText = `
      SELECT 
        a.id,
        a.event_type,
        a.admin_id,
        u.email as admin_email,
        a.panel_from,
        pf.name as panel_from_name,
        pf.panel_code as panel_from_code,
        a.panel_to,
        pt.name as panel_to_name,
        pt.panel_code as panel_to_code,
        a.old_state,
        a.new_state,
        a.details,
        a.created_at
      FROM audit_logs a
      LEFT JOIN users u ON a.admin_id = u.id
      LEFT JOIN panels pf ON a.panel_from = pf.id
      LEFT JOIN panels pt ON a.panel_to = pt.id
      ${whereClause}
      ORDER BY a.created_at DESC
      LIMIT $${paramIdx++} OFFSET $${paramIdx++}
    `;

    params.push(parseInt(limit as string, 10), parseInt(offset as string, 10));

    const result = await query(queryText, params);

    const countRes = await query(`SELECT COUNT(*) FROM audit_logs a ${whereClause}`, params.slice(0, paramIdx - 3));

    return res.json({
      logs: result.rows,
      total: parseInt(countRes.rows[0].count, 10),
    });
  } catch (err: any) {
    logger.error({ err }, 'Error querying audit logs');
    return res.status(500).json({ error: 'Failed to retrieve audit logs' });
  }
});

// POST /api/audit/session - Record session start/end
router.post('/session', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { event_type, panel_to, details } = req.body;
  const panel_from = req.user?.id;

  if (!event_type || !['session_start', 'session_end'].includes(event_type)) {
    return res.status(400).json({ error: 'Invalid event_type. Must be session_start or session_end' });
  }

  try {
    await query(
      `INSERT INTO audit_logs (event_type, panel_from, panel_to, details)
       VALUES ($1, $2, $3, $4)`,
      [event_type, panel_from, panel_to || null, JSON.stringify(details || {})]
    );

    logger.info({ panel_from, panel_to, event_type }, 'Logged intercom session event');

    return res.json({ success: true });
  } catch (err: any) {
    logger.error({ err }, 'Failed to record session audit log');
    return res.status(500).json({ error: 'Failed to log session' });
  }
});

export default router;
