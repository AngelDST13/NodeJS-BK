// Tokens aleatorios criptográficamente seguros (nunca Math.random()).
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

// 32 bytes = 256 bits de entropía, en base64url para usarlo en URLs.
export const generateToken = () => randomBytes(32).toString('base64url');

// SHA-256 simple es suficiente para tokens de alta entropía (no para contraseñas).
export const sha256 = (value) => createHash('sha256').update(value, 'utf8').digest('hex');

export const hmacSha256 = (key, value) => createHmac('sha256', key).update(value, 'utf8').digest('hex');

// Comparación en tiempo constante para evitar ataques de temporización.
export const safeEqual = (a, b) => {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
};
