import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { logger } from './logger.js';
import authRoutes from './routes/auth.js';
import panelsRoutes from './routes/panels.js';
import adminRoutes from './routes/admin.js';
import auditRoutes from './routes/audit.js';
import livekitRoutes from './routes/livekit.js';
import licenseRoutes from './routes/licenses.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  logger.info({ method: req.method, url: req.url, ip: req.ip }, 'Incoming HTTP Request');
  next();
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/panels', panelsRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin/audit-logs', auditRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/livekit', livekitRoutes);
app.use('/api/license', licenseRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error({ err, url: req.url }, 'Unhandled application error');
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  logger.info({ port: PORT }, `Mobile IC Agent Backend running on port ${PORT}`);
});
