// Logs estructurados en JSON (A09). La redacción es una red de seguridad:
// el código nunca debe pasar contraseñas, tokens ni datos cifrados al logger.
import pino from 'pino';
import { config } from './config.js';

export const logger = pino({
  level: config.isTest ? 'silent' : config.LOG_LEVEL,
  base: { service: 'securevault' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'password',
      '*.password',
      'token',
      '*.token',
      'req.headers.cookie',
      'req.headers.authorization',
      'body',
      '*.body',
      'phone',
      '*.phone',
    ],
    censor: '[REDACTED]',
  },
});
