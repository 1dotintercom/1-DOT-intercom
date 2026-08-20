import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { logger } from '../logger.js';

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: 'admin' | 'panel_user';
    license_id?: string | null;
    panel_code?: string;
    panel_name?: string;
  };
}

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-mobile-ic-jwt-key-2026';

export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn({ path: req.path }, 'Authentication failed: missing token');
    return res.status(401).json({ error: 'Authentication token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = decoded;
    next();
  } catch (err) {
    logger.warn({ path: req.path, err }, 'Authentication failed: invalid token');
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user || req.user.role !== 'admin') {
    logger.warn({ user: req.user?.email, path: req.path }, 'Forbidden access attempt to admin route');
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

export const requireGlobalAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user || req.user.role !== 'admin' || req.user.license_id) {
    logger.warn({ user: req.user?.email, path: req.path }, 'Forbidden access attempt to global administrator route');
    return res.status(403).json({ error: 'Global administrator access required' });
  }
  next();
};
