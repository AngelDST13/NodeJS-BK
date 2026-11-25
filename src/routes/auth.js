import { Router } from 'express';
import { promisify } from 'node:util';
import { config } from '../config.js';
import { redirectIfAuthenticated, requireAuth } from '../middleware/auth.js';
import { loginLimiter, sensitiveFormLimiter } from '../middleware/rateLimit.js';
import {
  validate,
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '../validation/schemas.js';
import {
  registerUser,
  authenticate,
  createPasswordResetToken,
  isResetTokenValid,
  resetPassword,
} from '../services/users.js';
import { sendPasswordResetEmail } from '../services/mailer.js';
import { recordEvent, AuditEvent } from '../services/audit.js';
import { generateToken } from '../crypto/tokens.js';

export const authRouter = Router();

// Mensaje genérico: no revela si el correo existe ni si la cuenta está bloqueada (A07).
const LOGIN_ERROR = 'Correo o contraseña incorrectos, o la cuenta está bloqueada temporalmente.';

authRouter.get('/register', redirectIfAuthenticated, (req, res) => {
  res.render('register', { title: 'Crear cuenta', errors: [], values: {} });
});

authRouter.post('/register', sensitiveFormLimiter, redirectIfAuthenticated, async (req, res) => {
  const { data, errors } = validate(registerSchema, req.body);
  if (errors) {
    return res.status(400).render('register', {
      title: 'Crear cuenta',
      errors,
      values: { email: req.body.email, name: req.body.name },
    });
  }
  await registerUser(data, req.ip);
  // Misma respuesta exista o no el correo: evita enumerar cuentas.
  req.session.flash = 'Si el correo no estaba registrado, tu cuenta ya fue creada. Inicia sesión.';
  return res.redirect(303, '/login');
});

authRouter.get('/login', redirectIfAuthenticated, (req, res) => {
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('login', { title: 'Iniciar sesión', errors: [], flash, values: {} });
});

authRouter.post('/login', loginLimiter, redirectIfAuthenticated, async (req, res) => {
  const { data, errors } = validate(loginSchema, req.body);
  const userId = errors ? null : await authenticate(data, req.ip);
  if (!userId) {
    return res.status(401).render('login', {
      title: 'Iniciar sesión',
      errors: [LOGIN_ERROR],
      flash: null,
      values: { email: typeof req.body.email === 'string' ? req.body.email : '' },
    });
  }
  // Nuevo ID de sesión al autenticarse: evita fijación de sesión (A07).
  await promisify(req.session.regenerate.bind(req.session))();
  req.session.userId = userId;
  req.session.authAt = Date.now();
  req.session.csrfToken = generateToken();
  return res.redirect(303, '/notes');
});

authRouter.post('/logout', requireAuth, async (req, res) => {
  const userId = req.user.id;
  // destroy() borra la sesión en el servidor: la cookie robada deja de servir.
  await promisify(req.session.destroy.bind(req.session))();
  await recordEvent({ eventType: AuditEvent.LOGOUT, actorId: userId, ip: req.ip });
  res.clearCookie('sv.sid', { path: '/' });
  return res.redirect(303, '/login');
});

const FORGOT_MESSAGE = 'Si el correo está registrado, recibirás un enlace para restablecer la contraseña.';

authRouter.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { title: 'Recuperar contraseña', errors: [], info: null });
});

authRouter.post('/forgot-password', sensitiveFormLimiter, async (req, res) => {
  const { data, errors } = validate(forgotPasswordSchema, req.body);
  if (errors) {
    return res.status(400).render('forgot-password', { title: 'Recuperar contraseña', errors, info: null });
  }
  const token = await createPasswordResetToken(data.email, req.ip);
  if (token) {
    const url = new URL('/reset-password', config.APP_ORIGIN);
    url.searchParams.set('token', token);
    await sendPasswordResetEmail(data.email, url.toString());
  }
  return res.render('forgot-password', { title: 'Recuperar contraseña', errors: [], info: FORGOT_MESSAGE });
});

authRouter.get('/reset-password', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  const valid = /^[A-Za-z0-9_-]{43}$/.test(token) && (await isResetTokenValid(token));
  res.status(valid ? 200 : 400).render('reset-password', {
    title: 'Nueva contraseña',
    token: valid ? token : null,
    errors: valid ? [] : ['El enlace no es válido o ya expiró. Solicita uno nuevo.'],
  });
});

authRouter.post('/reset-password', sensitiveFormLimiter, async (req, res) => {
  const { data, errors } = validate(resetPasswordSchema, req.body);
  const token = typeof req.body.token === 'string' ? req.body.token : null;
  if (errors) return res.status(400).render('reset-password', { title: 'Nueva contraseña', token, errors });

  if (!(await resetPassword(data.token, data.password, req.ip))) {
    return res.status(400).render('reset-password', {
      title: 'Nueva contraseña',
      token: null,
      errors: ['El enlace no es válido o ya expiró. Solicita uno nuevo.'],
    });
  }
  req.session.flash = 'Tu contraseña fue actualizada. Inicia sesión.';
  return res.redirect(303, '/login');
});
