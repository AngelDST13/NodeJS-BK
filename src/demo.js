// Cuentas de prueba SOLO para desarrollo local (npm run seed).
// En producción el script se niega a ejecutarse y el login no las muestra:
// las credenciales reales del docente se entregan por canal privado.
export const DEMO_ACCOUNTS = Object.freeze([
  Object.freeze({ role: 'user', name: 'Laura Gómez', email: 'usuario@sigilo.test', password: 'Sello-Azul-2026!' }),
  Object.freeze({ role: 'admin', name: 'Admin Sigilo', email: 'admin@sigilo.test', password: 'Llave-Maestra-2026!' }),
]);
