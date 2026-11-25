import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { pool } from './db/pool.js';
import { loadUser } from './middleware/auth.js';
import { csrfProtection } from './middleware/csrf.js';
import { globalLimiter } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errors.js';
import { healthRouter } from './routes/health.js';
import { homeRouter } from './routes/home.js';
import { authRouter } from './routes/auth.js';
import { notesRouter } from './routes/notes.js';
import { profileRouter } from './routes/profile.js';
import { adminRouter } from './routes/admin.js';
import { DEMO_ACCOUNTS } from './demo.js';

const rootDir = path.dirname(fileURLToPath(import.meta.url));

// Hojas de estilo (tipografías) de CDN con versión fija y Subresource Integrity (A08):
// si el CDN las altera, el navegador no las carga.
export const CDN_STYLESHEETS = Object.freeze([
  {
    href: 'https://cdn.jsdelivr.net/npm/@fontsource/gloock@5.2.5/latin.css',
    integrity: 'sha384-313qU6yoESmrWmKYarsPOs2SdlhjQeZ90M2iqBAUvGrpDDDNnMJotfqPezVfxUXA',
  },
  {
    href: 'https://cdn.jsdelivr.net/npm/@fontsource-variable/schibsted-grotesk@5.2.8/wght.css',
    integrity: 'sha384-+QBjh8Rf2AeMZ97jKneMOAzYlmUZVgvG+wIQm9+YdOYQGlz5eP08S9+QYKyIYhDc',
  },
]);

// Versión de la hoja de estilos según su contenido: cada cambio genera una URL nueva,
// así el navegador nunca mezcla HTML nuevo con un CSS viejo guardado en caché.
const versionedAssets = ['css/app.css', 'js/meter.js'].map((f) => path.join(rootDir, '..', 'public', f));
const hashAssets = () => {
  const hash = createHash('sha256');
  for (const file of versionedAssets) hash.update(readFileSync(file));
  return hash.digest('hex').slice(0, 12);
};
const productionAssetVersion = config.isProduction ? hashAssets() : null;
const assetVersion = () => productionAssetVersion ?? hashAssets();

const dateFormatters = new Map();
const formatDate = (date, options = { dateStyle: 'medium', timeStyle: 'short' }) => {
  const key = JSON.stringify(options);
  if (!dateFormatters.has(key)) dateFormatters.set(key, new Intl.DateTimeFormat('es', options));
  return dateFormatters.get(key).format(date);
};

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
          fontSrc: ["'self'", 'https://cdn.jsdelivr.net'],
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
      crossOriginEmbedderPolicy: false, // las tipografías del CDN se cargan con SRI + CORS
    }),
  );
  app.use((req, res, next) => {
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  app.use('/static', express.static(path.join(rootDir, '..', 'public'), {
      index: false,
      // Con ?v=<hash> la URL cambia en cada versión: se puede cachear un año sin riesgo.
      setHeaders: (res, _file) => {
        res.set('Cache-Control', res.req.query.v ? 'public, max-age=31536000, immutable' : 'no-cache');
      },
    }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); // páginas con datos privados no se guardan en caché
    res.locals.cdnStylesheets = CDN_STYLESHEETS;
    res.locals.formatDate = formatDate;
    res.locals.assetVersion = assetVersion();
    // Credenciales de prueba visibles en el login SOLO en desarrollo local.
    res.locals.demoAccounts = config.NODE_ENV === 'development' ? DEMO_ACCOUNTS : [];
    res.locals.title = 'Sigilo';
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

  app.use(homeRouter);
  app.use(authRouter);
  app.use('/notes', notesRouter);
  app.use('/profile', profileRouter);
  app.use('/admin', adminRouter);

  app.use(notFound);
  app.use(errorHandler);
  return app;
};
