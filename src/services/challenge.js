// "El reto del sello": una cuenta pública que cualquiera puede intentar abrir.
// Su contraseña es aleatoria (192 bits), se genera una vez y NUNCA se guarda ni se registra:
// solo existe su hash Argon2id. Los intentos pasan por la misma lógica que el login real
// (Argon2id, bloqueo progresivo, bitácora, alertas), así que el reto demuestra A04, A07 y A09.
import { randomBytes } from 'node:crypto';
import { query } from '../db/pool.js';
import { hashPassword } from '../crypto/passwords.js';
import { authenticate } from './users.js';
import { createNote, getNote } from './notes.js';
import { AuditEvent } from './audit.js';

export const CHALLENGE_EMAIL = 'sello@reto.sigilo';

const CHALLENGE_NOTE = {
  title: 'Abriste el sello',
  body: 'Si estás leyendo esto, adivinaste una contraseña aleatoria de 32 caracteres protegida con Argon2id y limitada a pocos intentos por hora. Avísale al equipo de Sigilo: queremos saber cómo lo hiciste.',
};

let cachedId = null;

export const ensureChallenge = async () => {
  if (cachedId) {
    const { rows } = await query('SELECT 1 FROM users WHERE id = $1', [cachedId]);
    if (rows.length) return cachedId;
    cachedId = null;
  }
  const { rows: existing } = await query('SELECT id FROM users WHERE email = $1', [CHALLENGE_EMAIL]);
  if (existing[0]) return (cachedId = existing[0].id);

  const passwordHash = await hashPassword(randomBytes(24).toString('base64url'));
  const { rows } = await query(
    `INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)
     ON CONFLICT (email) DO NOTHING RETURNING id`,
    [CHALLENGE_EMAIL, 'Caja del reto', passwordHash],
  );
  if (rows[0]) {
    await createNote(rows[0].id, CHALLENGE_NOTE);
    return (cachedId = rows[0].id);
  }
  // Otra petición la creó al mismo tiempo.
  const { rows: again } = await query('SELECT id FROM users WHERE email = $1', [CHALLENGE_EMAIL]);
  return (cachedId = again[0].id);
};

// Lo que vería alguien que robe la base de datos: hash y texto cifrado, tal cual.
export const getEvidence = async () => {
  const id = await ensureChallenge();
  const { rows } = await query(
    `SELECT u.password_hash, u.failed_login_count, u.locked_until,
            n.title_enc, n.body_enc
       FROM users u
       LEFT JOIN LATERAL (SELECT title_enc, body_enc FROM notes WHERE owner_id = u.id ORDER BY created_at LIMIT 1) n ON true
      WHERE u.id = $1`,
    [id],
  );
  const { rows: stats } = await query(
    `SELECT
       count(*) FILTER (WHERE event_type = $2 AND target_id = $1)::int AS attempts,
       count(*) FILTER (WHERE event_type = $3 AND details->>'scope' = 'challenge')::int AS throttled,
       count(*) FILTER (WHERE event_type = $4 AND target_id = $1)::int AS locks,
       count(*) FILTER (WHERE event_type = $5 AND actor_id = $1)::int AS opened
     FROM audit_events`,
    [id, AuditEvent.LOGIN_FAILURE, AuditEvent.RATE_LIMITED, AuditEvent.ACCOUNT_LOCKED, AuditEvent.LOGIN_SUCCESS],
  );
  const r = rows[0];
  const lockedMs = r.locked_until ? r.locked_until.getTime() - Date.now() : 0;
  return {
    email: CHALLENGE_EMAIL,
    passwordHash: r.password_hash,
    noteCipher: r.body_enc,
    titleCipher: r.title_enc,
    failedInARow: r.failed_login_count,
    lockedMinutes: lockedMs > 0 ? Math.ceil(lockedMs / 60_000) : 0,
    stats: stats[0],
  };
};

// Un intento de abrir el sello. Nunca crea sesión: solo muestra la nota si acierta.
export const attemptChallenge = async (password, ip) => {
  const id = await ensureChallenge();
  const startedAt = process.hrtime.bigint();
  const userId = await authenticate({ email: CHALLENGE_EMAIL, password }, ip);
  const ms = Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
  if (!userId) return { opened: false, ms };
  const { rows } = await query('SELECT id FROM notes WHERE owner_id = $1 ORDER BY created_at LIMIT 1', [id]);
  const note = rows[0] ? await getNote(id, rows[0].id) : null;
  return { opened: true, ms, note: note && { title: note.title, body: note.body } };
};

export const isChallengeEmail = (email) => email === CHALLENGE_EMAIL;
