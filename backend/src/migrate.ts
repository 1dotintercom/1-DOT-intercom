import fs from 'fs';
import path from 'path';
import { pool } from './db.js';
import { logger } from './logger.js';

export const runMigrations = async () => {
  try {
    const schemaPath = path.join(process.cwd(), '..', 'db', 'schema.sql');
    const sql = fs.readFileSync(schemaPath, 'utf8');

    logger.info('Running database migrations...');
    await pool.query(sql);
    logger.info('Database migrations completed successfully');
  } catch (err: any) {
    logger.error({ err }, 'Error executing database migrations');
    throw err;
  }
};

if (process.argv[1] && process.argv[1].includes('migrate')) {
  runMigrations()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
