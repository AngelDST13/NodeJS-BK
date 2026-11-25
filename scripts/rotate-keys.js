// Rotación de la llave de cifrado sin perder datos.
// Procedimiento:
//   1. Generar una llave nueva (npm run gen-keys).
//   2. Mover la llave actual a DATA_ENCRYPTION_OLD_KEYS ("1:<llave_vieja>").
//   3. Poner la nueva en DATA_ENCRYPTION_KEY y subir DATA_ENCRYPTION_KEY_VERSION (p. ej. 2).
//   4. Desplegar: la app ya cifra con v2 y sigue leyendo v1.
//   5. Ejecutar este script: re-cifra todo lo que siga en versiones anteriores.
//   6. Cuando informe 0 pendientes, retirar la llave vieja de DATA_ENCRYPTION_OLD_KEYS.
import { pool, withTransaction } from '../src/db/pool.js';
import { encrypt, decrypt, aadFor, currentKeyVersion } from '../src/crypto/encryption.js';

const BATCH = 200;
const version = currentKeyVersion();

const rotateNotes = async () => {
  let total = 0;
  for (;;) {
    const count = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `SELECT id, title_enc, body_enc FROM notes WHERE enc_key_version <> $1
          ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED`,
        [version, BATCH],
      );
      for (const r of rows) {
        const title = decrypt(r.title_enc, aadFor('notes', 'title', r.id));
        const body = decrypt(r.body_enc, aadFor('notes', 'body', r.id));
        await client.query('UPDATE notes SET title_enc = $2, body_enc = $3, enc_key_version = $4 WHERE id = $1', [
          r.id,
          encrypt(title, aadFor('notes', 'title', r.id)),
          encrypt(body, aadFor('notes', 'body', r.id)),
          version,
        ]);
      }
      return rows.length;
    });
    total += count;
    if (count < BATCH) return total;
  }
};

const rotatePhones = async () => {
  let total = 0;
  for (;;) {
    const count = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `SELECT id, phone_enc FROM users WHERE phone_enc IS NOT NULL AND phone_key_version <> $1
          ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED`,
        [version, BATCH],
      );
      for (const r of rows) {
        const aad = aadFor('users', 'phone', r.id);
        await client.query('UPDATE users SET phone_enc = $2, phone_key_version = $3 WHERE id = $1', [
          r.id,
          encrypt(decrypt(r.phone_enc, aad), aad),
          version,
        ]);
      }
      return rows.length;
    });
    total += count;
    if (count < BATCH) return total;
  }
};

const notes = await rotateNotes();
const phones = await rotatePhones();
const { rows } = await pool.query(
  `SELECT (SELECT count(*) FROM notes WHERE enc_key_version <> $1)::int AS notes,
          (SELECT count(*) FROM users WHERE phone_enc IS NOT NULL AND phone_key_version <> $1)::int AS phones`,
  [version],
);
console.log(`Re-cifrados con la versión ${version}: ${notes} notas, ${phones} teléfonos.`);
console.log(`Pendientes: ${rows[0].notes} notas, ${rows[0].phones} teléfonos.`);
await pool.end();
