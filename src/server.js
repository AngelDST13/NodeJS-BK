import { config } from './config.js';
import { logger } from './logger.js';
import { pool } from './db/pool.js';
import { migrate } from './db/migrate.js';
import { createApp } from './app.js';

// A10: un error no controlado deja el proceso en estado desconocido.
// Se registra y se sale; el gestor de procesos / plataforma lo reinicia limpio.
process.on('unhandledRejection', (reason) => {
  logger.fatal({ err: { message: reason?.message ?? String(reason), stack: reason?.stack } }, 'unhandledRejection');
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  logger.fatal({ err: { message: err.message, stack: err.stack } }, 'uncaughtException');
  process.exit(1);
});

await migrate();
const server = createApp().listen(config.PORT, () => {
  logger.info({ port: config.PORT, env: config.NODE_ENV }, 'SecureVault escuchando');
});

// Timeouts del servidor HTTP: evita conexiones colgadas (A10).
server.requestTimeout = 30_000;
server.headersTimeout = 15_000;

const shutdown = (signal) => {
  logger.info({ signal }, 'apagando');
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
