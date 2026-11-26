// Configuración validada al arrancar (A02 / A10: fail closed).
// Si falta un secreto o tiene un formato inválido, la app NO arranca.
import { z } from 'zod';

const base64Key = (bytes) =>
  z.string().refine((v) => Buffer.from(v, 'base64').length === bytes, {
    message: `debe ser una llave de ${bytes} bytes en base64`,
  });

const isUrl = (v) => {
  try {
    new URL(v);
    return true;
  } catch {
    return false;
  }
};

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  DATABASE_URL: z.string().min(1),
  // 'true' exige TLS hacia la BD (obligatorio en producción).
  DATABASE_SSL: z.enum(['true', 'false']).default('false'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET debe tener al menos 32 caracteres'),
  DATA_ENCRYPTION_KEY: base64Key(32),
  DATA_ENCRYPTION_KEY_VERSION: z.coerce.number().int().positive().default(1),
  // Llaves anteriores para rotación: "1:base64,2:base64"
  DATA_ENCRYPTION_OLD_KEYS: z.string().optional().default(''),
  AUDIT_HMAC_KEY: base64Key(32),
  APP_ORIGIN: z.string().refine(isUrl, 'APP_ORIGIN debe ser una URL').default('http://localhost:3000'),
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),
  // Cabecera con la IP real del cliente puesta por la CDN (solo si la CDN la sobrescribe siempre).
  CLIENT_IP_HEADER: z.enum(['cf-connecting-ip', 'true-client-ip', 'x-real-ip']).optional(),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  SMTP_URL: z.string().optional(),
  MAIL_FROM: z.string().default('SecureVault <no-reply@securevault.local>'),
  ALERT_WEBHOOK_URL: z.string().refine(isUrl).optional(),
  // Lista blanca de hosts a los que la app puede hacer peticiones salientes (A01 SSRF).
  ALERT_ALLOWED_HOSTS: z.string().default('hooks.slack.com,discord.com'),
  LOGIN_ALERT_THRESHOLD: z.coerce.number().int().positive().default(5),
});

// Una variable vacía (VAR=) se trata como no definida.
const rawEnv = Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== ''));
const parsed = schema.safeParse(rawEnv);
if (!parsed.success) {
  // Solo nombres de variables y motivo, nunca sus valores.
  const problems = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
  console.error(`Configuración inválida, la aplicación no arrancará:\n${problems}`);
  process.exit(1);
}

const env = parsed.data;
const isProduction = env.NODE_ENV === 'production';

if (isProduction) {
  const errors = [];
  if (env.DATABASE_SSL !== 'true') errors.push('DATABASE_SSL debe ser true en producción');
  if (!env.APP_ORIGIN.startsWith('https://')) errors.push('APP_ORIGIN debe usar https:// en producción');
  if (errors.length) {
    console.error(`Configuración insegura para producción:\n  - ${errors.join('\n  - ')}`);
    process.exit(1);
  }
}

const parseOldKeys = (raw) =>
  Object.fromEntries(
    raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((pair) => {
        const [version, key] = pair.split(':');
        const buf = Buffer.from(key ?? '', 'base64');
        if (!/^\d+$/.test(version) || buf.length !== 32) {
          console.error('DATA_ENCRYPTION_OLD_KEYS tiene un formato inválido (esperado "1:base64,2:base64")');
          process.exit(1);
        }
        return [Number(version), buf];
      }),
  );

export const config = Object.freeze({
  ...env,
  isProduction,
  isTest: env.NODE_ENV === 'test',
  encryptionKeys: {
    current: env.DATA_ENCRYPTION_KEY_VERSION,
    keys: {
      ...parseOldKeys(env.DATA_ENCRYPTION_OLD_KEYS),
      [env.DATA_ENCRYPTION_KEY_VERSION]: Buffer.from(env.DATA_ENCRYPTION_KEY, 'base64'),
    },
  },
  auditHmacKey: Buffer.from(env.AUDIT_HMAC_KEY, 'base64'),
  alertAllowedHosts: env.ALERT_ALLOWED_HOSTS.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean),
  limits: Object.freeze({
    maxNotesPerUser: 100,
    maxNoteTitle: 120,
    maxNoteBody: 5000,
  }),
});
