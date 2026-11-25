import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setup, teardown, registerAndLogin, createNote, getCsrf } from './helpers.js';
import { query } from '../src/db/pool.js';

let alice;
let bob;
let bobNoteId;

before(async () => {
  await setup();
  alice = await registerAndLogin('alice@example.com');
  bob = await registerAndLogin('bob@example.com');
  bobNoteId = await createNote(bob, 'Secreto de Bob', 'La clave del wifi es 1234');
});
after(teardown);

test('RF-04: el contenido de la nota se guarda cifrado en la BD', async () => {
  const { rows } = await query('SELECT title_enc, body_enc, enc_key_version FROM notes WHERE id = $1', [bobNoteId]);
  assert.match(rows[0].body_enc, /^v1\.[^.]+\.[^.]+\.[^.]+$/);
  assert.ok(!rows[0].body_enc.includes('wifi'));
  assert.ok(!rows[0].title_enc.includes('Bob'));
  assert.equal(rows[0].enc_key_version, 1);
});

test('RF-04: el dueño lee, edita y elimina su nota', async () => {
  const id = await createNote(alice, 'Mi nota', 'contenido original');
  assert.match((await alice.get(`/notes/${id}`)).text, /contenido original/);

  let _csrf = await getCsrf(alice, `/notes/${id}/edit`);
  const upd = await alice.post(`/notes/${id}`).type('form').send({ _csrf, title: 'Mi nota', body: 'editada' });
  assert.equal(upd.status, 303);
  assert.match((await alice.get(`/notes/${id}`)).text, /editada/);

  _csrf = await getCsrf(alice, `/notes/${id}`);
  assert.equal((await alice.post(`/notes/${id}/delete`).type('form').send({ _csrf })).status, 303);
  assert.equal((await alice.get(`/notes/${id}`)).status, 404);
});

test('A01 (IDOR): Alice no puede leer, editar ni borrar la nota de Bob', async () => {
  assert.equal((await alice.get(`/notes/${bobNoteId}`)).status, 404);
  assert.equal((await alice.get(`/notes/${bobNoteId}/edit`)).status, 404);
  const _csrf = await getCsrf(alice, '/notes');
  const upd = await alice.post(`/notes/${bobNoteId}`).type('form').send({ _csrf, title: 'hackeado', body: 'x' });
  assert.equal(upd.status, 404);
  assert.equal((await alice.post(`/notes/${bobNoteId}/delete`).type('form').send({ _csrf })).status, 404);

  // La nota de Bob sigue intacta y los intentos quedaron en la bitácora.
  assert.match((await bob.get(`/notes/${bobNoteId}`)).text, /wifi es 1234/);
  const { rows } = await query(
    "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authz.access_denied' AND target_id = $1",
    [bobNoteId],
  );
  assert.equal(rows[0].n, 4);
});

test('A01: sin sesión no hay acceso a notas', async () => {
  const { newAgent } = await import('./helpers.js');
  const res = await newAgent().get(`/notes/${bobNoteId}`);
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/login');
});

test('A05 (XSS): un <script> en la nota se muestra escapado', async () => {
  const id = await createNote(alice, '<img src=x onerror=alert(1)>', '<script>alert("xss")</script>');
  const html = (await alice.get(`/notes/${id}`)).text;
  assert.ok(!html.includes('<script>alert'));
  assert.match(html, /&lt;script&gt;alert\(&#34;xss&#34;\)&lt;\/script&gt;/);
  assert.ok(!html.includes('<img src=x'));
});

test('A05: un id con inyección SQL no llega a la consulta', async () => {
  const res = await alice.get(`/notes/${encodeURIComponent("1' OR '1'='1")}`);
  assert.equal(res.status, 404);
});

test('A06: límite de tamaño de nota', async () => {
  const _csrf = await getCsrf(alice, '/notes/new');
  const res = await alice.post('/notes').type('form').send({ _csrf, title: 't', body: 'x'.repeat(5001) });
  assert.equal(res.status, 400);
});

test('A06: límite de cantidad de notas por usuario', async () => {
  const carol = await registerAndLogin('carol@example.com');
  const { rows } = await query("SELECT id FROM users WHERE email = 'carol@example.com'");
  // Llenar hasta el máximo directamente en BD (rápido) y probar que la siguiente falla.
  await query(
    `INSERT INTO notes (owner_id, title_enc, body_enc, enc_key_version)
     SELECT $1, 'v1.x.x.x', 'v1.x.x.x', 1 FROM generate_series(1, 100)`,
    [rows[0].id],
  );
  const _csrf = await getCsrf(carol, '/notes/new');
  const res = await carol.post('/notes').type('form').send({ _csrf, title: 'una más', body: '' });
  assert.equal(res.status, 409);
});

test('RF-05: el teléfono se guarda cifrado y se muestra enmascarado', async () => {
  let _csrf = await getCsrf(alice, '/profile');
  const res = await alice.post('/profile').type('form').send({ _csrf, name: 'Alice', phone: '+57 300 555 1234' });
  assert.equal(res.status, 303);
  const html = (await alice.get('/profile')).text;
  assert.match(html, /\*\*\*-\*\*\*-1234/);
  assert.ok(!html.includes('300 555'));
  const { rows } = await query("SELECT phone_enc FROM users WHERE email = 'alice@example.com'");
  assert.match(rows[0].phone_enc, /^v1\./);
  assert.ok(!rows[0].phone_enc.includes('1234'));
  _csrf = await getCsrf(alice, '/profile');
});

test('A01: el perfil ignora campos extra (sin mass assignment de rol)', async () => {
  const _csrf = await getCsrf(alice, '/profile');
  await alice.post('/profile').type('form').send({ _csrf, name: 'Alice', phone: '', role: 'admin' });
  const { rows } = await query("SELECT role FROM users WHERE email = 'alice@example.com'");
  assert.equal(rows[0].role, 'user');
});
