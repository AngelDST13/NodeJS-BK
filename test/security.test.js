import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import { setup, teardown, newAgent, registerAndLogin, getCsrf } from './helpers.js';
import { query } from '../src/db/pool.js';
import { errorHandler } from '../src/middleware/errors.js';

let user;
let admin;

before(async () => {
  await setup();
  user = await registerAndLogin('user@example.com');
  admin = await registerAndLogin('admin@example.com');
  await query("UPDATE users SET role = 'admin' WHERE email = 'admin@example.com'");
});
after(teardown);

test('A02: cabeceras de seguridad y sin X-Powered-By', async () => {
  const res = await newAgent().get('/login');
  assert.equal(res.headers['x-powered-by'], undefined);
  const csp = res.headers['content-security-policy'];
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['referrer-policy'], 'same-origin');
  assert.equal(res.headers['access-control-allow-origin'], undefined, 'sin CORS abierto');
});

test('A08: la hoja de estilos del CDN usa Subresource Integrity', async () => {
  const html = (await newAgent().get('/login')).text;
  assert.match(html, /<link rel="stylesheet" href="https:\/\/cdn\.jsdelivr\.net\/[^"]+" integrity="sha384-[^"]+" crossorigin="anonymous">/);
});

test('RF-08: /health responde sin revelar versiones ni datos internos', async () => {
  const res = await newAgent().get('/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { status: 'ok' });
  assert.equal(res.headers['set-cookie'], undefined);
});

test('CSRF: un POST sin token es rechazado con 403', async () => {
  const res = await user.post('/notes').type('form').send({ title: 'x', body: 'y' });
  assert.equal(res.status, 403);
});

test('CSRF: un POST desde otro origen es rechazado aunque traiga token', async () => {
  const _csrf = await getCsrf(user, '/notes/new');
  const res = await user.post('/notes').set('Origin', 'https://evil.example').type('form').send({ _csrf, title: 'x' });
  assert.equal(res.status, 403);
});

test('RF-03 / A01: un usuario normal recibe 403 en /admin y queda registrado', async () => {
  const res = await user.get('/admin');
  assert.equal(res.status, 403);
  const { rows } = await query(
    "SELECT details FROM audit_events WHERE event_type = 'authz.access_denied' ORDER BY id DESC LIMIT 1",
  );
  assert.equal(rows[0].details.path, '/admin');
});

test('RF-07: el admin ve usuarios y bitácora, y el cambio de rol se registra', async () => {
  const page = await admin.get('/admin');
  assert.equal(page.status, 200);
  assert.match(page.text, /user@example.com/);
  assert.match(page.text, /Bitácora de seguridad/);

  const { rows } = await query("SELECT id FROM users WHERE email = 'user@example.com'");
  const _csrf = await getCsrf(admin, '/admin');
  const res = await admin.post(`/admin/users/${rows[0].id}/role`).type('form').send({ _csrf, role: 'admin' });
  assert.equal(res.status, 303);
  const ev = await query("SELECT actor_id, target_id, details FROM audit_events WHERE event_type = 'admin.role_changed'");
  assert.equal(ev.rows[0].target_id, rows[0].id);
  assert.equal(ev.rows[0].details.newRole, 'admin');

  // El rol se lee de la BD en cada petición: el cambio aplica de inmediato.
  assert.equal((await user.get('/admin')).status, 200);
  await query("UPDATE users SET role = 'user' WHERE email = 'user@example.com'");
  assert.equal((await user.get('/admin')).status, 403);
});

test('A08/A09: el panel detecta registros de bitácora alterados (HMAC)', async () => {
  await query(
    "UPDATE audit_events SET details = '{\"path\":\"/falso\"}' WHERE id = (SELECT min(id) FROM audit_events)",
  );
  const html = (await admin.get('/admin')).text;
  assert.match(html, /ALTERADO/);
});

test('A10: errores no controlados devuelven respuesta genérica sin stack', async () => {
  const app = express();
  app.get('/boom', () => {
    throw new Error('detalle interno: password=secreto en tabla users');
  });
  app.use(errorHandler);
  const res = await request(app).get('/boom').set('Accept', 'application/json');
  assert.equal(res.status, 500);
  assert.match(res.body.error, /error inesperado/);
  assert.match(res.body.errorId, /^[0-9a-f-]{36}$/);
  assert.ok(!JSON.stringify(res.body).includes('detalle interno'));
  assert.ok(!JSON.stringify(res.body).includes('at '));
});

test('A10: rutas inexistentes y cuerpos gigantes no filtran detalles', async () => {
  const notFound = await newAgent().get('/debug');
  assert.equal(notFound.status, 404);
  const huge = await user.post('/notes').type('form').send({ body: 'x'.repeat(100_000) });
  assert.equal(huge.status, 413);
  assert.ok(!huge.text.includes('PayloadTooLargeError'));
});

test('Las credenciales de prueba no aparecen fuera de desarrollo', async () => {
  const html = (await newAgent().get('/login')).text;
  assert.ok(!html.includes('sigilo.test'));
  assert.ok(!html.includes('Cuentas de prueba'));
});
