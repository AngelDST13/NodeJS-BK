// Cifrado autenticado AES-256-GCM (A04) con versión de llave para permitir rotación.
// Formato guardado en BD: v<versión>.<iv>.<tag>.<datos>  (iv, tag y datos en base64)
// - IV aleatorio de 12 bytes por cada cifrado (nunca se reutiliza).
// - Tag de autenticación de 16 bytes: si alguien altera el dato, descifrar falla.
// - AAD (datos asociados): liga el texto cifrado a su registro y campo, de modo que
//   copiar el cifrado de la nota de otro usuario a la propia no se puede descifrar.
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { config } from '../config.js';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

const keyFor = (version) => {
  const key = config.encryptionKeys.keys[version];
  if (!key) throw new Error(`No hay llave de cifrado para la versión ${version}`);
  return key;
};

export const currentKeyVersion = () => config.encryptionKeys.current;

export const encrypt = (plaintext, aad) => {
  const version = currentKeyVersion();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, keyFor(version), iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v${version}.${[iv, tag, data].map((b) => b.toString('base64')).join('.')}`;
};

export const keyVersionOf = (payload) => {
  const match = /^v(\d+)\./.exec(payload);
  if (!match) throw new Error('Formato de dato cifrado inválido');
  return Number(match[1]);
};

export const decrypt = (payload, aad) => {
  const parts = payload.split('.');
  if (parts.length !== 4) throw new Error('Formato de dato cifrado inválido');
  const version = keyVersionOf(payload);
  const [iv, tag, data] = parts.slice(1).map((s) => Buffer.from(s, 'base64'));
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('Formato de dato cifrado inválido');
  const decipher = createDecipheriv(ALGORITHM, keyFor(version), iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag); // lanza error en final() si el dato fue alterado
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
};

// AAD estándar por campo, para que todos los módulos usen la misma convención.
export const aadFor = (table, field, id) => `securevault:${table}:${field}:${id}`;
