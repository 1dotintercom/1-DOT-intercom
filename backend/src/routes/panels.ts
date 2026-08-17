import { Router, Response } from 'express';
import { query } from '../db.js';
import { authenticateToken, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';

const router = Router();

// Get all panels
router.get('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const result = await query(
      'SELECT id, panel_code, name, location, status, created_at FROM panels ORDER BY panel_code ASC'
    );
    return res.json(result.rows);
  } catch (err: any) {
    logger.error({ err }, 'Error fetching panels');
    return res.status(500).json({ error: 'Failed to fetch panels' });
  }
});

// Get permission matrix for all panels
router.get('/permissions', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const result = await query(
      'SELECT panel_a_id, panel_b_id, state, updated_by_admin_id, updated_at FROM permissions'
    );
    return res.json(result.rows);
  } catch (err: any) {
    logger.error({ err }, 'Error fetching permissions matrix');
    return res.status(500).json({ error: 'Failed to fetch permissions' });
  }
});

export default router;
