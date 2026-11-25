import { query, withTransaction } from '../db/pool.js';
import { hashPassword, verifyPassword, burnPasswordCheck } from '../crypto/passwords.js';
import { encrypt, decrypt, aadFor, currentKeyVersion } from '../crypto/encryption.js';
import { generateToken, sha256 } from '../crypto/tokens.js';
import { config } from '../config.js';
import { recordEvent, AuditEvent } from './audit.js';
import { sendSecurityAlert } from './alerts.js';

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;
const MAX_LOCK_MINUTES = 60;

// --- Registro (RF-01) -------------------------------------------------------

export const registerUser = async ({ email, name, password }, ip) => {
  const passwordHash = await hashPassword(password);
  const { rows } = await query(
    `INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [email, name, passwordHash],
  );
  if (rows[0]) await recordEvent({ eventType: AuditEvent.REGISTER, actorId: rows[0].id, ip });
  return rows[0]?.id ?? null;
};

// --- Login con bloqueo progresivo (RF-02 / A07) -----------------------------

// Tras N fallos consecutivos la cuenta se bloquea 1, 2, 4, 8... minutos (máx. 60).
const lockMinutesFor = (failures) =>
  failures < config.LOGIN_ALERT_THRESHOLD
    ? 0
    : Math.min(2 ** (failures - config.LOGIN_ALERT_THRESHOLD), MAX_LOCK_MINUTES);

export const authenticate = async ({ email, password }, ip) => {
  const { rows } = await query(
    'SELECT id, password_hash, failed_login_count, locked_until FROM users WHERE email = $1',
    [email],
  );
  const user = rows[0];

  if (!user) {
    await burnPasswordCheck(password);
    await recordEvent({ eventType: AuditEvent.LOGIN_FAILURE, ip, details: { reason: 'unknown_email' } });
    return null;
  }

  if (user.locked_until && user.locked_until > new Date()) {
    await burnPasswordCheck(password);
    await recordEvent({ eventType: AuditEvent.LOGIN_FAILURE, targetId: user.id, ip, details: { reason: 'locked' } });
    return null;
  }

  if (!(await verifyPassword(user.password_hash, password))) {
    const failures = user.failed_login_count + 1;
    const lockMinutes = lockMinutesFor(failures);
    await query(
      `UPDATE users SET failed_login_count = $2,
              locked_until = CASE WHEN $3::int > 0 THEN now() + make_interval(mins => $3::int) ELSE NULL END
        WHERE id = $1`,
      [user.id, failures, lockMinutes],
    );
    await recordEvent({
      eventType: AuditEvent.LOGIN_FAILURE,
      targetId: user.id,
      ip,
      details: { reason: 'bad_password', consecutiveFailures: failures },
    });
    if (lockMinutes > 0) {
      await recordEvent({ eventType: AuditEvent.ACCOUNT_LOCKED, targetId: user.id, ip, details: { minutes: lockMinutes } });
    }
    if (failures === config.LOGIN_ALERT_THRESHOLD) {
      await sendSecurityAlert(`${failures} intentos de login fallidos consecutivos para una cuenta`, {
        targetId: user.id,
        ip,
      });
    }
    return null;
  }

  await query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1', [user.id]);
  await recordEvent({ eventType: AuditEvent.LOGIN_SUCCESS, actorId: user.id, ip });
  return user.id;
};

// --- Perfil y dato sensible (RF-05) -----------------------------------------

export const maskPhone = (phone) => {
  const digits = phone.replace(/\D/g, '');
  return `***-***-${digits.slice(-4)}`;
};

export const getProfile = async (userId) => {
  const { rows } = await query('SELECT id, email, name, role, phone_enc, created_at FROM users WHERE id = $1', [
    userId,
  ]);
  const user = rows[0];
  if (!user) return null;
  const phone = user.phone_enc ? decrypt(user.phone_enc, aadFor('users', 'phone', user.id)) : null;
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    createdAt: user.created_at,
    maskedPhone: phone ? maskPhone(phone) : null,
  };
};

export const updateProfile = async (userId, { name, phone }) => {
  if (phone === '') {
    await query(
      'UPDATE users SET name = $2, phone_enc = NULL, phone_key_version = NULL, updated_at = now() WHERE id = $1',
      [userId, name],
    );
    return;
  }
  await query('UPDATE users SET name = $2, phone_enc = $3, phone_key_version = $4, updated_at = now() WHERE id = $1', [
    userId,
    name,
    encrypt(phone, aadFor('users', 'phone', userId)),
    currentKeyVersion(),
  ]);
};

// --- Recuperación de contraseña (RF-06) -------------------------------------

// Devuelve el token en claro SOLO para enviarlo por correo; en BD queda su SHA-256.
export const createPasswordResetToken = async (email, ip) => {
  const { rows } = await query('SELECT id FROM users WHERE email = $1', [email]);
  const user = rows[0];
  await recordEvent({
    eventType: AuditEvent.PASSWORD_RESET_REQUESTED,
    targetId: user?.id ?? null,
    ip,
    details: { knownAccount: Boolean(user) },
  });
  if (!user) return null;

  const token = generateToken();
  await withTransaction(async (client) => {
    // Un solo token vigente por usuario: los anteriores quedan inutilizados.
    await client.query('UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL', [
      user.id,
    ]);
    await client.query('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)', [
      user.id,
      sha256(token),
      new Date(Date.now() + RESET_TOKEN_TTL_MS),
    ]);
  });
  return token;
};

export const isResetTokenValid = async (token) => {
  const { rows } = await query(
    'SELECT 1 FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()',
    [sha256(token)],
  );
  return rows.length === 1;
};

export const resetPassword = async (token, newPassword, ip) => {
  const passwordHash = await hashPassword(newPassword);
  const userId = await withTransaction(async (client) => {
    // FOR UPDATE: dos peticiones simultáneas con el mismo token no pueden usarlo dos veces.
    const { rows } = await client.query(
      `SELECT id, user_id FROM password_reset_tokens
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        FOR UPDATE`,
      [sha256(token)],
    );
    const row = rows[0];
    if (!row) return null;
    await client.query('UPDATE password_reset_tokens SET used_at = now() WHERE id = $1', [row.id]);
    await client.query(
      `UPDATE users SET password_hash = $2, failed_login_count = 0, locked_until = NULL, updated_at = now()
        WHERE id = $1`,
      [row.user_id, passwordHash],
    );
    // Cerrar todas las sesiones abiertas del usuario.
    await client.query("DELETE FROM session WHERE sess->>'userId' = $1", [row.user_id]);
    return row.user_id;
  });
  if (userId) await recordEvent({ eventType: AuditEvent.PASSWORD_RESET_COMPLETED, targetId: userId, ip });
  return Boolean(userId);
};

// --- Administración (RF-07) -------------------------------------------------

export const listUsers = async () => {
  const { rows } = await query(
    `SELECT id, email, name, role, created_at, failed_login_count,
            (locked_until IS NOT NULL AND locked_until > now()) AS locked
       FROM users ORDER BY created_at DESC LIMIT 500`,
  );
  return rows;
};

export const changeRole = async ({ adminId, targetId, role }, ip) => {
  if (adminId === targetId) return { error: 'No puedes cambiar tu propio rol.' };
  const { rows } = await query(
    `UPDATE users SET role = $2, updated_at = now()
      WHERE id = $1 AND role <> $2
      RETURNING id`,
    [targetId, role],
  );
  if (!rows[0]) return { error: 'Usuario no encontrado o ya tiene ese rol.' };
  await recordEvent({ eventType: AuditEvent.ROLE_CHANGED, actorId: adminId, targetId, ip, details: { newRole: role } });
  return { ok: true };
};
