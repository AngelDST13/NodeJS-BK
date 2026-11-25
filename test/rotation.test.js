// Bonificación: rotación de la llave de cifrado sin pérdida de datos.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { setup, teardown, registerAndLogin, createNote } from './helpers.js';
import { query } from '../src/db/pool.js';

const run = promisify(execFile);
let agent;
let noteId;

before(async () => {
  await setup();
  agent = await registerAndLogin('rota@example.com');
  noteId = await createNote(agent, 'Antes de rotar', 'contenido que debe sobrevivir');
});
after(teardown);

test('rotate-keys re-cifra con la versión nueva y los datos siguen legibles', async () => {
  const newKey = randomBytes(32).toString('base64');
  const env = {
    ...process.env,
    DATA_ENCRYPTION_OLD_KEYS: `1:${process.env.DATA_ENCRYPTION_KEY}`,
    DATA_ENCRYPTION_KEY: newKey,
    DATA_ENCRYPTION_KEY_VERSION: '2',
  };
  const { stdout } = await run(process.execPath, ['scripts/rotate-keys.js'], { env });
  assert.match(stdout, /Pendientes: 0 notas, 0 teléfonos/);

  const { rows } = await query('SELECT body_enc, enc_key_version FROM notes WHERE id = $1', [noteId]);
  assert.equal(rows[0].enc_key_version, 2);
  assert.match(rows[0].body_enc, /^v2\./);

  // Un proceso que solo conoce la llave nueva puede leer el dato re-cifrado.
  const check = `
    const { decrypt, aadFor } = await import('./src/crypto/encryption.js');
    console.log(decrypt(process.argv[1], aadFor('notes', 'body', process.argv[2])));
    process.exit(0);`;
  const out = await run(process.execPath, ['--input-type=module', '-e', check, rows[0].body_enc, noteId], {
    env: { ...env, DATA_ENCRYPTION_OLD_KEYS: '' },
  });
  assert.equal(out.stdout.trim(), 'contenido que debe sobrevivir');
});
