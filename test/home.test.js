import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setup, teardown, newAgent, getCsrf, registerAndLogin, login } from './helpers.js';
import { query } from '../src/db/pool.js';
import { hashPassword } from '../src/crypto/passwords.js';
import { CHALLENGE_EMAIL } from '../src/services/challenge.js';
import { outbox } from '../src/services/mailer.js';

before(setup);
after(teardown);

const attempt = async (agent, password) => {
  const _csrf = await getCsrf(agent, '/');
  return agent.post('/reto').type('form').send({ _csrf, password });
};

test('Inicio público: muestra el hash Argon2id y la nota cifrada reales de la cuenta del reto', async () => {
  const res = await newAgent().get('/');
  assert.equal(res.status, 200);
  const { rows } = await query(
    'SELECT u.password_hash, n.body_enc FROM users u JOIN notes n ON n.owner_id = u.id WHERE u.email = $1',
    [CHALLENGE_EMAIL],
  );
  assert.match(rows[0].password_hash, /^\$argon2id\$/);
  assert.ok(res.text.includes(rows[0].password_hash));
  assert.ok(res.text.includes(rows[0].body_enc));
  assert.ok(!res.text.includes('Abriste el sello'), 'la nota no se muestra descifrada');
});

test('Inicio: la calculadora es un script propio (CSP sin inline) y no envía la contraseña', async () => {
  const res = await newAgent().get('/');
  assert.match(res.text, /<script src="\/static\/js\/meter\.js\?v=[0-9a-f]{12}" defer><\/script>/);
  assert.ok(!/<script>(?!<\/script>)/.test(res.text), 'sin scripts en línea');
  const js = await newAgent().get('/static/js/meter.js');
  assert.ok(!/fetch|XMLHttpRequest|sendBeacon/.test(js.text));
});

test('Reto: un intento fallido se comprueba con Argon2id y queda en la bitácora', async () => {
  const agent = newAgent();
  const res = await attempt(agent, 'adivinanza-1');
  assert.equal(res.status, 303);
  const page = await agent.get('/');
  assert.match(page.text, /Contraseña incorrecta/);
  assert.match(page.text, /Te quedan <strong>4<\/strong>/);
  const { rows } = await query(
    "SELECT count(*)::int AS n FROM audit_events e JOIN users u ON u.id = e.target_id WHERE e.event_type = 'auth.login.failure' AND u.email = $1",
    [CHALLENGE_EMAIL],
  );
  assert.equal(rows[0].n, 1);
});

test('Reto: fuerza bruta frenada con HTTP 429 al sexto intento', async () => {
  const agent = newAgent();
  for (let i = 0; i < 5; i++) assert.equal((await attempt(agent, `intento-${i}`)).status, 303);
  const blocked = await attempt(agent, 'intento-6');
  assert.equal(blocked.status, 429);
  assert.match(blocked.text, /HTTP 429/);
});

test('Reto: tras 5 fallos seguidos la cuenta se bloquea aunque se acierte', async () => {
  const known = 'Clave-De-Prueba-Conocida-1!';
  await query('UPDATE users SET password_hash = $2 WHERE email = $1', [CHALLENGE_EMAIL, await hashPassword(known)]);
  // Ya hubo 6 fallos sobre la cuenta en las pruebas anteriores (bloqueada).
  const agent = newAgent();
  await attempt(agent, known);
  const page = await agent.get('/');
  assert.match(page.text, /La cuenta está bloqueada/);
  assert.ok(!page.text.includes('Abriste el sello.'));
});

test('Reto: si se acierta, se muestra la nota pero NO se inicia sesión', async () => {
  const known = 'Clave-De-Prueba-Conocida-1!';
  await query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE email = $1', [CHALLENGE_EMAIL]);
  const agent = newAgent();
  await attempt(agent, known);
  const page = await agent.get('/');
  assert.match(page.text, /Abriste el sello\./);
  assert.match(page.text, /adivinaste una contraseña aleatoria/);
  const notes = await agent.get('/notes');
  assert.equal(notes.status, 303, 'sigue sin sesión');
});

test('Reto: la cuenta del reto nunca recibe enlace de recuperación', async () => {
  const before = outbox.length;
  const agent = newAgent();
  const _csrf = await getCsrf(agent, '/forgot-password');
  const res = await agent.post('/forgot-password').type('form').send({ _csrf, email: CHALLENGE_EMAIL });
  assert.equal(res.status, 200);
  assert.equal(outbox.length, before);
});

test('Admin: puede desbloquear una cuenta y queda registrado', async () => {
  const admin = await registerAndLogin('jefa@example.com');
  await query("UPDATE users SET role = 'admin' WHERE email = 'jefa@example.com'");
  await query("UPDATE users SET failed_login_count = 9, locked_until = now() + interval '1 hour' WHERE email = $1", [
    CHALLENGE_EMAIL,
  ]);
  const { rows } = await query('SELECT id FROM users WHERE email = $1', [CHALLENGE_EMAIL]);
  const _csrf = await getCsrf(admin, '/admin');
  const res = await admin.post(`/admin/users/${rows[0].id}/unlock`).type('form').send({ _csrf });
  assert.equal(res.status, 303);
  const after = await query('SELECT failed_login_count, locked_until FROM users WHERE id = $1', [rows[0].id]);
  assert.equal(after.rows[0].failed_login_count, 0);
  assert.equal(after.rows[0].locked_until, null);
  const ev = await query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'admin.account_unlocked'");
  assert.equal(ev.rows[0].n, 1);
});

test('Inicio: con sesión iniciada redirige a las notas', async () => {
  const agent = newAgent();
  await registerAndLogin('ines@example.com');
  await login(agent, { email: 'ines@example.com' });
  const res = await agent.get('/');
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/notes');
});
