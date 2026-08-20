import bcrypt from 'bcryptjs';
import { pool, query } from './db.js';
import { logger } from './logger.js';
import { runMigrations } from './migrate.js';

export const seedDatabase = async () => {
  try {
    await runMigrations();

    logger.info('Seeding database accounts...');

    const adminUsername = process.env.ADMIN_USERNAME?.trim();
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminUsername || !adminPassword) {
      throw new Error('ADMIN_USERNAME and ADMIN_PASSWORD must be configured privately before seeding');
    }

    // 1. Create Admin User
    const adminPasswordHash = await bcrypt.hash(adminPassword, 10);
    const adminUserRes = await query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE SET password_hash = $2
       RETURNING id`,
      [adminUsername, adminPasswordHash, 'admin']
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
