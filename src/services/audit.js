// Bitácora de eventos de seguridad (A09 / RF-07).
// Se escribe en la BD (para el panel) y en el log JSON (para la plataforma).
// Cada fila lleva HMAC-SHA256 con una llave secreta: si alguien edita la fila
// directamente en la BD, el panel la marca como alterada (A08 integridad).
import { query } from '../db/pool.js';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { hmacSha256, safeEqual } from '../crypto/tokens.js';

export const AuditEvent = Object.freeze({
  REGISTER: 'auth.register',
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILURE: 'auth.login.failure',
  ACCOUNT_LOCKED: 'auth.account.locked',
  LOGOUT: 'auth.logout',
  PASSWORD_RESET_REQUESTED: 'auth.password_reset.requested',
  PASSWORD_RESET_COMPLETED: 'auth.password_reset.completed',
  ACCESS_DENIED: 'authz.access_denied',
  ROLE_CHANGED: 'admin.role_changed',
  RATE_LIMITED: 'security.rate_limited',
  CSRF_REJECTED: 'security.csrf_rejected',
});

const stableStringify = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value ?? null);
};

const signEvent = ({ occurredAt, eventType, actorId, targetId, ip, details }) =>
  hmacSha256(
    config.auditHmacKey,
    stableStringify([occurredAt.toISOString(), eventType, actorId ?? null, targetId ?? null, ip ?? null, details]),
  );

export const recordEvent = async ({ eventType, actorId = null, targetId = null, ip = null, details = {} }) => {
  const occurredAt = new Date();
  const hmac = signEvent({ occurredAt, eventType, actorId, targetId, ip, details });
  logger.info({ audit: { eventType, actorId, targetId, ip, details } }, eventType);
  try {
    await query(
      `INSERT INTO audit_events (occurred_at, event_type, actor_id, target_id, ip, details, hmac)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [occurredAt, eventType, actorId, targetId, ip, details, hmac],
    );
  } catch (err) {
    // La auditoría no debe tumbar la petición, pero el fallo queda registrado.
    logger.error({ err: { message: err.message }, eventType }, 'no se pudo guardar el evento de auditoría');
  }
};

export const listEvents = async (limit = 100) => {
  const { rows } = await query(
    `SELECT e.id, e.occurred_at, e.event_type, e.actor_id, e.target_id, e.ip, e.details, e.hmac,
            u.email AS actor_email
       FROM audit_events e
       LEFT JOIN users u ON u.id = e.actor_id
      ORDER BY e.occurred_at DESC, e.id DESC
      LIMIT $1`,
    [limit],
  );
  return rows.map((r) => ({
    ...r,
    intact: safeEqual(
      r.hmac,
      signEvent({
        occurredAt: r.occurred_at,
        eventType: r.event_type,
        actorId: r.actor_id,
        targetId: r.target_id,
        ip: r.ip,
        details: r.details,
      }),
    ),
  }));
};
