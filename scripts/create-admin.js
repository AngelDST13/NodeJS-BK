// Promueve a administrador una cuenta YA registrada desde la interfaz.
// Así la contraseña del admin nunca pasa por la línea de comandos ni por variables de entorno.
// Uso: npm run create-admin -- correo@dominio.com
import { query, pool } from '../src/db/pool.js';
import { recordEvent, AuditEvent } from '../src/services/audit.js';

const email = process.argv[2]?.trim().toLowerCase();
if (!email) {
  console.error('Uso: npm run create-admin -- correo@dominio.com');
  process.exit(1);
}

const { rows } = await query("UPDATE users SET role = 'admin', updated_at = now() WHERE email = $1 RETURNING id", [
  email,
]);
if (rows[0]) {
  await recordEvent({ eventType: AuditEvent.ROLE_CHANGED, targetId: rows[0].id, details: { newRole: 'admin', via: 'cli' } });
  console.log('Cuenta promovida a administrador.');
} else {
  console.error('No existe una cuenta con ese correo. Regístrala primero en /register.');
  process.exitCode = 1;
}
await pool.end();
