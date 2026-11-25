// RF-08: estado del servicio sin versiones, hostnames ni detalles internos.
import { Router } from 'express';
import { query } from '../db/pool.js';
import { logger } from '../logger.js';

export const healthRouter = Router();

healthRouter.get('/health', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    await query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    logger.error({ err: { message: err.message } }, 'health check: base de datos no disponible');
    res.status(503).json({ status: 'unavailable' });
  }
});
