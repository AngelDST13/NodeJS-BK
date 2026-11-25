// Limitación de tasa (A07). Responde HTTP 429 al superar el límite.
// Nota: el almacén en memoria sirve para una sola instancia; con varias réplicas
// habría que usar un almacén compartido (Redis/PostgreSQL).
import { rateLimit } from 'express-rate-limit';
import { recordEvent, AuditEvent } from '../services/audit.js';

const onLimit = (scope) => async (req, res, _next, options) => {
  await recordEvent({
    eventType: AuditEvent.RATE_LIMITED,
    actorId: req.session?.userId ?? null,
    ip: req.ip,
    details: { scope, path: req.originalUrl },
  });
  res.status(options.statusCode).render('error', {
    title: 'Demasiados intentos',
    message: 'Has realizado demasiadas solicitudes. Espera unos minutos e inténtalo de nuevo.',
  });
};

const common = { standardHeaders: 'draft-8', legacyHeaders: false };

// Global: 300 peticiones por IP cada 15 minutos.
export const globalLimiter = rateLimit({ ...common, windowMs: 15 * 60 * 1000, limit: 300, handler: onLimit('global') });

// Login: 5 intentos fallidos por IP cada 15 minutos (los exitosos no cuentan).
export const loginLimiter = rateLimit({
  ...common,
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  handler: onLimit('login'),
});

// Registro y recuperación: 5 por IP por hora.
export const sensitiveFormLimiter = rateLimit({
  ...common,
  windowMs: 60 * 60 * 1000,
  limit: 5,
  handler: onLimit('sensitive-form'),
});
