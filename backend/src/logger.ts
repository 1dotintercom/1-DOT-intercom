import pino from 'pino';
import fs from 'fs';
import path from 'path';

const logDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  base: { service: 'mobile-ic-backend' },
  timestamp: pino.stdTimeFunctions.isoTime,
  transport: {
    targets: [
      {
        target: 'pino/file',
        options: { destination: 1 }, // stdout
        level: process.env.LOG_LEVEL || 'info',
      },
      {
        target: 'pino-roll',
        options: {
          file: path.join(logDir, 'app-log'),
          frequency: 'daily',
          mkdir: true,
        },
        level: process.env.LOG_LEVEL || 'info',
      },
    ],
  },
});
