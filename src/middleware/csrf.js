// Protección CSRF con token sincronizador guardado en la sesión + verificación de Origin.
// Junto con SameSite=Strict, impide que otro sitio dispare acciones con la cookie del usuario.
// No se emiten cabeceras CORS: ningún origen externo puede leer respuestas (CORS restringido).
import { generateToken, safeEqual } from '../crypto/tokens.js';
import { config } from '../config.js';
import { recordEvent, AuditEvent } from '../services/audit.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const allowedOrigin = new URL(config.APP_ORIGIN).origin;

export const csrfProtection = async (req, res, next) => {
  req.session.csrfToken ??= generateToken();
  res.locals.csrfToken = req.session.csrfToken;
  if (SAFE_METHODS.has(req.method)) return next();

  const origin = req.get('origin');
  const originOk = !origin || origin === allowedOrigin;
  const tokenOk = typeof req.body?._csrf === 'string' && safeEqual(req.body._csrf, req.session.csrfToken);
  if (originOk && tokenOk) return next();

  await recordEvent({
    eventType: AuditEvent.CSRF_REJECTED,
    actorId: req.session.userId ?? null,
    ip: req.ip,
    details: { path: req.originalUrl, reason: originOk ? 'token' : 'origin' },
  });
  return res.status(403).render('error', {
    title: 'Solicitud rechazada',
    message: 'La solicitud no es válida o el formulario expiró. Recarga la página e inténtalo de nuevo.',
  });
};
