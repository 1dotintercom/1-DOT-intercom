import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query } from '../db.js';
import { authenticateToken, AuthRequest } from '../middleware/auth.js';
import { logger } from '../logger.js';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-mobile-ic-jwt-key-2026';

router.post('/login', async (req: AuthRequest, res: Response) => {
  const identifier = String(req.body.username ?? req.body.email ?? '').trim();
  const { password } = req.body;

  if (!identifier || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  try {
    const userRes = await query(
      `SELECT u.* FROM users u
       LEFT JOIN panels p ON p.id = u.id
       WHERE LOWER(u.email) = LOWER($1)
          OR LOWER(COALESCE(p.panel_code, '')) = LOWER($1)
       LIMIT 1`,
      [identifier],
    );
    if (userRes.rows.length === 0) {
      logger.warn({ identifier }, 'Login failed: user not found');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userRes.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      logger.warn({ identifier }, 'Login failed: incorrect password');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Get associated panel info if user is a panel_user
    let panelInfo: any = null;
    if (user.role === 'panel_user' || true) {
      const panelRes = await query('SELECT * FROM panels WHERE id = $1', [user.id]);
      if (panelRes.rows.length > 0) {
        panelInfo = panelRes.rows[0];
        // Mark panel as online
        await query("UPDATE panels SET status = 'online' WHERE id = $1", [user.id]);
      }
    }

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role,
      panel_code: panelInfo?.panel_code,
      panel_name: panelInfo?.name,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });

    logger.info({ userId: user.id, role: user.role, email: user.email }, 'User logged in successfully');

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      panel: panelInfo,
    });
  } catch (err: any) {
    logger.error({ err }, 'Error during login process');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.id) {
      await query("UPDATE panels SET status = 'offline' WHERE id = $1", [req.user.id]);
      logger.info({ userId: req.user.id }, 'User logged out');
    }
    return res.json({ success: true });
  } catch (err: any) {
    logger.error({ err }, 'Error during logout');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/me', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const userRes = await query('SELECT id, email, role, created_at FROM users WHERE id = $1', [req.user?.id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRes.rows[0];
    const panelRes = await query('SELECT * FROM panels WHERE id = $1', [user.id]);

    return res.json({
      user,
      panel: panelRes.rows[0] || null,
    });
  } catch (err: any) {
    logger.error({ err }, 'Error fetching current user info');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
