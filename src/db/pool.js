import pg from 'pg';
import { config } from '../config.js';
import { logger } from '../logger.js';

// Timeouts en todas las operaciones de BD (A10): una BD lenta no debe colgar la app.
export const pool = new pg.Pool({
  connectionString: config.DATABASE_URL,
  ssl: config.DATABASE_SSL === 'true' ? { rejectUnauthorized: true } : false,
  max: 10,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
  statement_timeout: 5_000,
  query_timeout: 6_000,
});

pool.on('error', (err) => {
  logger.error({ err: { message: err.message, code: err.code } }, 'error en cliente inactivo de PostgreSQL');
});

// Todas las consultas pasan por aquí y SIEMPRE usan parámetros ($1, $2...) (A05).
export const query = (text, params = []) => pool.query(text, params);

export const withTransaction = async (fn) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
};
