import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import { getEvidence, attemptChallenge } from '../services/challenge.js';
import { recordEvent, AuditEvent } from '../services/audit.js';
import { validate } from '../validation/schemas.js';

export const homeRouter = Router();

const CHALLENGE_WINDOW_MS = 15 * 60 * 1000;
export const CHALLENGE_LIMIT = 5;

const attemptSchema = z.object({
  password: z.string().min(1, 'Escribe una contraseña para intentarlo.').max(128, 'Máximo 128 caracteres.'),
});

// Cuánto tomaría abrir el sello por fuerza bruta. La contraseña del reto son 24 bytes
// aleatorios en base64url: 32 caracteres de un alfabeto de 64 → 64^32 combinaciones.
const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹';
const sci = (digits) => `${digits[0]},${digits.slice(1, 3)} × 10${String(digits.length - 1).replace(/\d/g, (d) => SUP[d])}`;
const UNIVERSE_S = 1.38e10 * 365.25 * 86400;
const timesUniverse = (seconds) => sci(BigInt(Math.round(seconds / UNIVERSE_S)).toString());
const RETO_COMBOS = 64n ** 32n;
const RETO_AVERAGE = Number(RETO_COMBOS / 2n);
export const CHALLENGE_FACTS = Object.freeze({
  alphabet: 64,
  length: 32,
  combos: sci(RETO_COMBOS.toString()),
  online: timesUniverse(RETO_AVERAGE * 3600), // 1 intento por hora contra Sigilo
  offline: timesUniverse(RETO_AVERAGE / 1e3), // base robada, Argon2id en una tarjeta gráfica
  md5: timesUniverse(RETO_AVERAGE / 1.6e11), // incluso si estuviera en MD5
});

const renderHome = async (req, res, status = 200) => {
  const evidence = await getEvidence();
  const result = req.session.challengeResult ?? null;
  delete req.session.challengeResult;
  res.status(status).render('home', {
    title: 'Notas privadas que nadie más puede abrir',
    evidence,
    result: res.locals.challengeResult ?? result,
    challengeLimit: CHALLENGE_LIMIT,
    facts: CHALLENGE_FACTS,
  });
};

// Límite propio del reto (5 intentos por IP cada 15 min). Es independiente del login real
// para que jugar al reto no bloquee tu propia cuenta, pero se comporta igual: HTTP 429.
const challengeLimiter = rateLimit({
  windowMs: CHALLENGE_WINDOW_MS,
  limit: CHALLENGE_LIMIT,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: async (req, res) => {
    await recordEvent({
      eventType: AuditEvent.RATE_LIMITED,
      ip: req.ip,
      details: { scope: 'challenge', path: req.originalUrl },
    });
    const retryMinutes = Math.max(1, Math.ceil((req.rateLimit.resetTime - Date.now()) / 60_000));
    res.locals.challengeResult = { outcome: 'throttled', retryMinutes };
    await renderHome(req, res, 429);
  },
});

homeRouter.get('/', async (req, res) => {
  if (req.user) return res.redirect(303, '/notes');
  return renderHome(req, res);
});

homeRouter.post('/reto', challengeLimiter, async (req, res) => {
  const { data, errors } = validate(attemptSchema, req.body);
  if (errors) {
    req.session.challengeResult = { outcome: 'invalid', message: errors[0] };
    return res.redirect(303, '/#reto');
  }
  const attempt = await attemptChallenge(data.password, req.ip);
  const evidence = await getEvidence();
  req.session.challengeResult = attempt.opened
    ? { outcome: 'opened', ms: attempt.ms, note: attempt.note }
    : {
        outcome: evidence.lockedMinutes > 0 ? 'locked' : 'wrong',
        ms: attempt.ms,
        remaining: req.rateLimit.remaining,
        failedInARow: evidence.failedInARow,
        lockedMinutes: evidence.lockedMinutes,
        ip: req.ip,
      };
  return res.redirect(303, '/#reto');
});
