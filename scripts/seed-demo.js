// Crea (o restablece) las cuentas de prueba con notas de ejemplo.
// Uso: npm run seed      (se niega a correr con NODE_ENV=production)
import { config } from '../src/config.js';
import { pool, query } from '../src/db/pool.js';
import { migrate } from '../src/db/migrate.js';
import { hashPassword } from '../src/crypto/passwords.js';
import { createNote } from '../src/services/notes.js';
import { updateProfile } from '../src/services/users.js';
import { DEMO_ACCOUNTS } from '../src/demo.js';

if (config.isProduction) {
  console.error('seed-demo no se ejecuta en producción.');
  process.exit(1);
}

const SAMPLE_NOTES = [
  ['Claves del router de casa', 'Red: Casa-Gomez-5G\nCambiar la contraseña del panel cada tres meses.'],
  ['Ideas para la tesis', 'Comparar AES-GCM con ChaCha20-Poly1305 en teléfonos de gama baja.\n\nPreguntar al docente por el alcance del capítulo 3.'],
  ['Medicamentos de mamá', 'Losartán 50 mg en la mañana.\nControl con el cardiólogo el 12 de diciembre.'],
];

await migrate();

for (const account of DEMO_ACCOUNTS) {
  const passwordHash = await hashPassword(account.password);
  const { rows } = await query(
    `INSERT INTO users (email, name, password_hash, role) VALUES ($1, $2, $3, $4)
     ON CONFLICT (email) DO UPDATE
       SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, role = EXCLUDED.role,
           failed_login_count = 0, locked_until = NULL, updated_at = now()
     RETURNING id`,
    [account.email, account.name, passwordHash, account.role],
  );
  const userId = rows[0].id;

  if (account.role === 'user') {
    const { rows: existing } = await query('SELECT count(*)::int AS n FROM notes WHERE owner_id = $1', [userId]);
    if (existing[0].n === 0) {
      for (const [title, body] of SAMPLE_NOTES) await createNote(userId, { title, body });
    }
    await updateProfile(userId, { name: account.name, phone: '+57 300 555 1234' });
  }
  console.log(`${account.role === 'admin' ? 'Administrador' : 'Usuario'}: ${account.email} / ${account.password}`);
}

await pool.end();
