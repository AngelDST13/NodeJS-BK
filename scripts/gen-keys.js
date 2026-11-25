// Genera secretos nuevos para un archivo .env o para el panel de secretos de la plataforma.
// Uso: npm run gen-keys   (copia la salida; NO la subas al repositorio)
import { randomBytes } from 'node:crypto';

console.log(`SESSION_SECRET=${randomBytes(48).toString('base64url')}`);
console.log(`DATA_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}`);
console.log(`AUDIT_HMAC_KEY=${randomBytes(32).toString('base64')}`);
