import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setup, teardown, newAgent, register, login, getCsrf, registerAndLogin, STRONG_PASSWORD } from './helpers.js';
import { query } from '../src/db/pool.js';
import { outbox } from '../src/services/mailer.js';

before(setup);
after(teardown);

test('RF-01: registro guarda la contraseña solo como hash Argon2id', async () => {
  const res = await register(newAgent(), { email: 'Ana@Example.com' });
  assert.equal(res.status, 303);
  const { rows } = await query('SELECT email, password_hash FROM users WHERE email = $1', ['ana@example.com']);
  assert.equal(rows.length, 1);
  assert.match(rows[0].password_hash, /^\$argon2id\$/);
  assert.ok(!rows[0].password_hash.includes(STRONG_PASSWORD));
});

test('RF-01: política de complejidad rechaza contraseñas débiles', async () => {
  const res = await register(newAgent(), { email: 'debil@example.com', password: 'password' });
  assert.equal(res.status, 400);
  assert.match(res.text, /al menos 12 caracteres/);
  const { rows } = await query('SELECT 1 FROM users WHERE email = $1', ['debil@example.com']);
  assert.equal(rows.length, 0);
});

test('RF-01: correo duplicado recibe la misma respuesta (sin enumeración)', async () => {
  const res = await register(newAgent(), { email: 'ana@example.com' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/login');
});

test('RF-02: cookie de sesión HttpOnly + SameSite=Strict y regeneración del ID al iniciar sesión', async () => {
  const agent = newAgent();
  const pre = await agent.get('/login');
  const preCookie = pre.headers['set-cookie']?.[0] ?? '';
  const res = await login(agent, { email: 'ana@example.com' });
  assert.equal(res.status, 303);
  const cookie = res.headers['set-cookie'][0];
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.notEqual(cookie.split(';')[0], preCookie.split(';')[0], 'el ID de sesión cambia al autenticarse');
});

test('A07: login fallido da mensaje genérico, igual para correo inexistente', async () => {
  const a = await login(newAgent(), { email: 'ana@example.com', password: 'Incorrecta-123!' });
  const b = await login(newAgent(), { email: 'nadie@example.com', password: 'Incorrecta-123!' });
  assert.equal(a.status, 401);
  assert.equal(b.status, 401);
  const msg = /Correo o contraseña incorrectos/;
  assert.match(a.text, msg);
  assert.match(b.text, msg);
});

test('A05: inyección SQL en el login no autentica', async () => {
  const res = await login(newAgent(), { email: "' OR 1=1 --", password: "' OR '1'='1" });
  assert.equal(res.status, 401);
});

test('RF-02: el cierre de sesión invalida la sesión en el servidor', async () => {
  await register(newAgent(), { email: 'logout@example.com' });
  const agent = newAgent();
  const loginRes = await login(agent, { email: 'logout@example.com' });
  const stolenCookie = loginRes.headers['set-cookie'][0].split(';')[0];
  assert.equal((await newAgent().get('/notes').set('Cookie', stolenCookie)).status, 200);
  const _csrf = await getCsrf(agent, '/notes');
  assert.equal((await agent.post('/logout').type('form').send({ _csrf })).status, 303);
  // Reusar la cookie antigua ya no da acceso.
  const replay = await newAgent().get('/notes').set('Cookie', stolenCookie);
  assert.equal(replay.status, 303);
  assert.equal(replay.headers.location, '/login');
});

test('A07: fuerza bruta en login devuelve HTTP 429', async () => {
  const agent = newAgent();
  const statuses = [];
  for (let i = 0; i < 7; i++) {
    statuses.push((await login(agent, { email: 'ana@example.com', password: `Mala-${i}-Clave!` })).status);
  }
  assert.deepEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401]);
  assert.equal(statuses[5], 429);
  assert.equal(statuses[6], 429);
});

test('A07: bloqueo progresivo de la cuenta aunque el atacante cambie de IP', async () => {
  await register(newAgent(), { email: 'victima@example.com' });
  for (let i = 0; i < 5; i++) await login(newAgent(), { email: 'victima@example.com', password: `Mala-${i}-Clave!` });
  // Con la contraseña correcta tampoco entra mientras está bloqueada.
  const res = await login(newAgent(), { email: 'victima@example.com' });
  assert.equal(res.status, 401);
  const { rows } = await query("SELECT event_type FROM audit_events WHERE event_type = 'auth.account.locked'");
  assert.ok(rows.length >= 1);
});

test('A09: la bitácora registra eventos sin contraseñas ni tokens', async () => {
  const { rows } = await query('SELECT details::text AS d FROM audit_events');
  assert.ok(rows.length > 0);
  for (const { d } of rows) {
    assert.ok(!d.includes(STRONG_PASSWORD));
    assert.ok(!/Mala-\d-Clave/.test(d));
  }
});

test('RF-06: recuperación con token de un solo uso; en BD solo su SHA-256', async () => {
  await register(newAgent(), { email: 'olvido@example.com' });
  const agent = newAgent();
  const _csrf = await getCsrf(agent, '/forgot-password');
  const res = await agent.post('/forgot-password').type('form').send({ _csrf, email: 'olvido@example.com' });
  assert.equal(res.status, 200);

  const link = outbox.at(-1).text.match(/https?:\/\/\S+/)[0];
  const token = new URL(link).searchParams.get('token');
  const { rows } = await query('SELECT token_hash FROM password_reset_tokens');
  assert.ok(rows.every((r) => r.token_hash !== token && /^[0-9a-f]{64}$/.test(r.token_hash)));

  const newPassword = 'Otra-Clave-Segura-9';
  const pageCsrf = await getCsrf(agent, `/reset-password?token=${token}`);
  const done = await agent
    .post('/reset-password')
    .type('form')
    .send({ _csrf: pageCsrf, token, password: newPassword, confirmPassword: newPassword });
  assert.equal(done.status, 303);
  assert.equal((await login(newAgent(), { email: 'olvido@example.com', password: newPassword })).status, 303);

  // Segundo uso del mismo token: rechazado.
  const again = await agent
    .post('/reset-password')
    .type('form')
    .send({ _csrf: await getCsrf(agent, '/forgot-password'), token, password: newPassword, confirmPassword: newPassword });
  assert.equal(again.status, 400);
});

test('RF-06: token expirado es rechazado', async () => {
  const agent = newAgent();
  const _csrf = await getCsrf(agent, '/forgot-password');
  await agent.post('/forgot-password').type('form').send({ _csrf, email: 'ana@example.com' });
  const token = new URL(outbox.at(-1).text.match(/https?:\/\/\S+/)[0]).searchParams.get('token');
  await query("UPDATE password_reset_tokens SET expires_at = now() - interval '1 minute'");
  assert.equal((await agent.get(`/reset-password?token=${token}`)).status, 400);
});

test('RF-06: correo inexistente recibe la misma respuesta y no envía nada', async () => {
  const before = outbox.length;
  const agent = newAgent();
  const _csrf = await getCsrf(agent, '/forgot-password');
  const res = await agent.post('/forgot-password').type('form').send({ _csrf, email: 'fantasma@example.com' });
  assert.equal(res.status, 200);
  assert.match(res.text, /Si el correo está registrado/);
  assert.equal(outbox.length, before);
});
