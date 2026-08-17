import pg from 'pg';
import dotenv from 'dotenv';
import { logger } from './logger.js';

dotenv.config();

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  logger.error({ err }, 'Unexpected error on idle PostgreSQL client');
});

export const query = (text: string, params?: any[]) => pool.query(text, params);
