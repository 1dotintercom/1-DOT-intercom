import { Router, Response } from 'express';
import { query } from '../db.js';
import { authenticateToken, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';
import { generateLiveKitToken } from '../services/livekit.js';

const router = Router();

router.post('/token', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'User unauthorized' });
    }

    // Get panel info
    const panelRes = await query('SELECT * FROM panels WHERE id = $1', [userId]);
    const panel = panelRes.rows[0];

    const identity = userId;
    const name = panel ? `${panel.panel_code} - ${panel.name}` : req.user?.email || 'Unknown';
    const panelCode = panel?.panel_code || 'ADM';

    // Retrieve active permission matrix for this panel
    const permsRes = await query(
      'SELECT panel_b_id, state FROM permissions WHERE panel_a_id = $1',
      [userId]
    );

    const activePermissionsMap: Record<string, string> = {};
    permsRes.rows.forEach((r) => {
      activePermissionsMap[r.panel_b_id] = r.state;
    });

    const metadata = JSON.stringify({
      panelCode,
      location: panel?.location || 'Global Admin',
      permissions: activePermissionsMap,
    });

    const token = await generateLiveKitToken({
      identity,
      name,
      panelCode,
      metadata,
    });

    logger.info({ userId, identity }, 'Generated LiveKit access token');

    return res.json({
      token,
      // The server SDK uses LIVEKIT_HOST (https), while mobile WebRTC uses
      // LIVEKIT_URL (wss). Keep both protocols explicit for cross-network use.
      livekitHost: process.env.LIVEKIT_URL || process.env.LIVEKIT_HOST || 'http://localhost:7880',
      identity,
      room: 'mobile-ic-main',
    });
  } catch (err: any) {
    logger.error({ err }, 'Error generating LiveKit token');
    return res.status(500).json({ error: 'Failed to generate token' });
  }
});

export default router;
