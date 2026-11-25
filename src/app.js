import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { pool } from './db/pool.js';
import { loadUser } from './middleware/auth.js';
import { csrfProtection } from './middleware/csrf.js';
import { globalLimiter } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errors.js';
import { healthRouter } from './routes/health.js';
import { authRouter } from './routes/auth.js';
import { notesRouter } from './routes/notes.js';
import { profileRouter } from './routes/profile.js';
import { adminRouter } from './routes/admin.js';

const rootDir = path.dirname(fileURLToPath(import.meta.url));

// Hoja de estilos de CDN con Subresource Integrity (A08): si el CDN la altera, el navegador no la carga.
export const CDN_STYLESHEET = Object.freeze({
  href: 'https://cdn.jsdelivr.net/npm/@picocss/pico@2.1.1/css/pico.min.css',
  integrity: 'sha384-L1dWfspMTHU/ApYnFiMz2QID/PlP1xCW9visvBdbEkOLkSSWsP6ZJWhPw6apiXxU',
});

export const createApp = () => {
  const app = express();
  const PgSession = connectPgSimple(session);

  // --- A02: configuración segura ---------------------------------------------
  app.disable('x-powered-by');
  // Detrás de un proxy (Render, Railway, Nginx) hace que req.ip y req.secure sean correctos,
  // necesario para cookies Secure y para que el rate limit cuente por IP real.
  app.set('trust proxy', config.TRUST_PROXY);
  app.set('view engine', 'ejs');
  app.set('views', path.join(rootDir, 'views'));

  // HTTP -> HTTPS obligatorio en producción (/health se exime para los chequeos internos).
  if (config.isProduction) {
    app.use((req, res, next) => {
      if (req.secure || req.path === '/health') return next();
      return res.redirect(308, `https://${req.hostname}${req.originalUrl}`);
    });
  }

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"], // sin 'unsafe-inline': un <script> inyectado no se ejecuta
          styleSrc: ["'self'", 'https://cdn.jsdelivr.net'],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          ...(config.isProduction ? { upgradeInsecureRequests: [] } : {}),
        },
      },
      strictTransportSecurity: config.isProduction ? { maxAge: 31_536_000, includeSubDomains: true } : false,
      // same-origin: nunca envía la URL (p. ej. con el token de recuperación) a otros sitios,
      // pero mantiene la cabecera Origin real en los POST propios (no-referrer la vuelve "null").
      referrerPolicy: { policy: 'same-origin' },
      crossOriginEmbedderPolicy: false, // la hoja de estilos del CDN se carga con SRI + CORS
    }),
  );
  app.use((req, res, next) => {
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  app.use('/static', express.static(path.join(rootDir, '..', 'public'), { maxAge: '7d', index: false }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); // páginas con datos privados no se guardan en caché
    res.locals.cdnStylesheet = CDN_STYLESHEET;
    res.locals.title = 'SecureVault';
    res.locals.currentUser = null;
    next();
  });
  app.use(healthRouter);
  app.use(globalLimiter);

  // Límite de tamaño de cuerpo (A06): peticiones gigantes se rechazan con 413.
  app.use(express.urlencoded({ extended: false, limit: '64kb', parameterLimit: 20 }));

  app.use(
    session({
      name: 'sv.sid',
      store: new PgSession({
        pool,
        tableName: 'session',
        createTableIfMissing: false,
        pruneSessionInterval: config.isTest ? false : 15 * 60,
      }),
      secret: config.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      rolling: true, // expiración por inactividad: 30 min desde la última petición
      cookie: {
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000,
        path: '/',
      },
    }),
  );

  app.use(loadUser);
  app.use(csrfProtection);

  app.get('/', (req, res) => res.redirect(303, req.user ? '/notes' : '/login'));
  app.use(authRouter);
  app.use('/notes', notesRouter);
  app.use('/profile', profileRouter);
  app.use('/admin', adminRouter);

  app.use(notFound);
  app.use(errorHandler);
  return app;
};
