import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, aadFor } from '../src/crypto/encryption.js';
import { hashPassword, verifyPassword } from '../src/crypto/passwords.js';
import { generateToken, sha256 } from '../src/crypto/tokens.js';
import { isAllowedOutboundUrl } from '../src/services/alerts.js';
import { maskPhone } from '../src/services/users.js';
import { pool } from '../src/db/pool.js';
import { clientIp } from '../src/middleware/clientIp.js';

test.after(() => pool.end());

const aad = aadFor('notes', 'body', '00000000-0000-0000-0000-000000000001');

test('AES-256-GCM: cifra y descifra; formato v<n>.iv.tag.datos', () => {
  const payload = encrypt('hola mundo', aad);
  assert.match(payload, /^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
  assert.equal(decrypt(payload, aad), 'hola mundo');
  const [, iv, tag] = payload.split('.').map((s) => Buffer.from(s, 'base64'));
  assert.equal(iv.length, 12);
  assert.equal(tag.length, 16);
});

test('AES-256-GCM: IV único por cifrado (mismo texto, distinto resultado)', () => {
  const ivs = new Set(Array.from({ length: 200 }, () => encrypt('igual', aad).split('.')[1]));
  assert.equal(ivs.size, 200);
});

test('AES-256-GCM: detecta manipulación del texto cifrado', () => {
  const [v, iv, tag, data] = encrypt('dato íntegro', aad).split('.');
  const bytes = Buffer.from(data, 'base64');
  bytes[0] ^= 0xff;
  assert.throws(() => decrypt([v, iv, tag, bytes.toString('base64')].join('.'), aad));
});

test('AES-256-GCM: el cifrado de un registro no sirve en otro (AAD)', () => {
  const payload = encrypt('nota de B', aad);
  assert.throws(() => decrypt(payload, aadFor('notes', 'body', '00000000-0000-0000-0000-000000000002')));
});

test('Argon2id: hash con sal, prefijo $argon2id$ y parámetros OWASP', async () => {
  const [h1, h2] = await Promise.all([hashPassword('Secreta!123A'), hashPassword('Secreta!123A')]);
  assert.match(h1, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  assert.notEqual(h1, h2, 'cada hash usa una sal distinta');
  assert.equal(await verifyPassword(h1, 'Secreta!123A'), true);
  assert.equal(await verifyPassword(h1, 'otra'), false);
  assert.equal(await verifyPassword('no-es-un-hash', 'x'), false);
});

test('Tokens: 256 bits aleatorios y SHA-256 para almacenarlos', () => {
  const token = generateToken();
  assert.equal(Buffer.from(token, 'base64url').length, 32);
  assert.notEqual(generateToken(), token);
  assert.match(sha256(token), /^[0-9a-f]{64}$/);
});

test('SSRF: solo HTTPS a hosts en lista blanca', () => {
  const allowed = ['hooks.slack.com'];
  assert.equal(isAllowedOutboundUrl('https://hooks.slack.com/services/x', allowed), true);
  assert.equal(isAllowedOutboundUrl('http://hooks.slack.com/services/x', allowed), false);
  assert.equal(isAllowedOutboundUrl('https://169.254.169.254/latest/meta-data', allowed), false);
  assert.equal(isAllowedOutboundUrl('https://hooks.slack.com.evil.com/x', allowed), false);
  assert.equal(isAllowedOutboundUrl('https://user:pass@hooks.slack.com/x', allowed), false);
  assert.equal(isAllowedOutboundUrl('no-es-url', allowed), false);
});

test('Enmascarado del teléfono', () => {
  assert.equal(maskPhone('+57 300 555 1234'), '***-***-1234');
});

test('IP del cliente: usa la cabecera de la CDN si es una IP válida; si no, req.ip', () => {
  const make = (headers) => {
    const req = { headers, get: (h) => headers[h.toLowerCase()] };
    Object.defineProperty(req, 'ip', { value: '10.0.0.1', configurable: true });
    return req;
  };
  const mw = clientIp('cf-connecting-ip');
  const a = make({ 'cf-connecting-ip': '190.85.12.34' });
  mw(a, {}, () => {});
  assert.equal(a.ip, '190.85.12.34');
  const b = make({ 'cf-connecting-ip': 'no-es-ip; DROP TABLE' });
  mw(b, {}, () => {});
  assert.equal(b.ip, '10.0.0.1');
  const c = make({ 'cf-connecting-ip': '190.85.12.34' });
  clientIp(undefined)(c, {}, () => {});
  assert.equal(c.ip, '10.0.0.1', 'sin configurar no se confía en la cabecera');
});
