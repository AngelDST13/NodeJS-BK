// Autenticación y autorización (A01 / A07 / RF-03).
// El rol se lee SIEMPRE de la BD en cada petición: nunca se confía en la sesión,
// en un campo oculto del formulario ni en nada que envíe el cliente.
import { query } from '../db/pool.js';
import { recordEvent, AuditEvent } from '../services/audit.js';

// 8 horas máximo por sesión, aunque haya actividad (expiración absoluta).
export const ABSOLUTE_SESSION_MS = 8 * 60 * 60 * 1000;

export const loadUser = async (req, res, next) => {
  res.locals.currentUser = null;
  const userId = req.session?.userId;
  if (!userId) return next();

  if (!req.session.authAt || Date.now() - req.session.authAt > ABSOLUTE_SESSION_MS) {
    return req.session.destroy(() => next());
  }
  const { rows } = await query('SELECT id, email, name, role FROM users WHERE id = $1', [userId]);
  if (!rows[0]) return req.session.destroy(() => next());
  req.user = rows[0];
  res.locals.currentUser = rows[0];
  next();
};

export const requireAuth = (req, res, next) => {
  if (req.user) return next();
  if (req.accepts(['html', 'json']) === 'json') return res.status(401).json({ error: 'No autenticado' });
  return res.redirect(303, '/login');
};

export const requireRole = (role) => async (req, res, next) => {
  if (req.user?.role === role) return next();
  await recordEvent({
    eventType: AuditEvent.ACCESS_DENIED,
    actorId: req.user?.id,
    ip: req.ip,
    details: { path: req.originalUrl, method: req.method, requiredRole: role },
  });
  return res.status(403).render('error', { title: 'Acceso denegado', message: 'No tienes permiso para ver esta página.' });
};

export const redirectIfAuthenticated = (req, res, next) => (req.user ? res.redirect(303, '/notes') : next());
