// Hash de contraseñas con Argon2id (A04). La contraseña nunca se cifra ni se guarda.
// Parámetros mínimos recomendados por OWASP: m=19 MiB, t=2, p=1.
import argon2 from 'argon2';

const OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
});

export const hashPassword = (plain) => argon2.hash(plain, OPTIONS);

export const verifyPassword = async (hash, plain) => {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false; // hash corrupto: fallar cerrado
  }
};

// Hash ficticio para igualar el tiempo de respuesta cuando el correo no existe
// (evita enumerar usuarios midiendo tiempos).
let dummyHash;
export const burnPasswordCheck = async (plain) => {
  dummyHash ??= await hashPassword('dummy-password-for-timing');
  await verifyPassword(dummyHash, plain);
  return false;
};
