import bcrypt from 'bcryptjs';
import { pool, query } from './db.js';
import { logger } from './logger.js';
import { runMigrations } from './migrate.js';

export const seedDatabase = async () => {
  try {
    await runMigrations();

    logger.info('Seeding database with the default administrator...');

    // 1. Create Admin User
    const adminPasswordHash = await bcrypt.hash('admin@1234', 10);
    await query(`UPDATE users SET email = 'admin' WHERE role = 'admin' AND email = 'admin@mobileic.com'`);
    const adminUserRes = await query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE SET password_hash = $2
       RETURNING id`,
      ['admin', adminPasswordHash, 'admin']
    );

    logger.info('Database seeding completed successfully!');
  } catch (err: any) {
    logger.error({ err }, 'Error during database seeding');
    throw err;
  }
};

if (process.argv[1] && process.argv[1].includes('seed')) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
