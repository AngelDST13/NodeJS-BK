// Validación de entrada con esquemas (A05). Todo lo que llega del cliente pasa por aquí;
// los esquemas son estrictos: campos no esperados se descartan (evita mass assignment).
import { z } from 'zod';
import { config } from '../config.js';

const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, 'Correo demasiado largo')
  .pipe(z.email('Correo inválido'));

export const passwordPolicy = z
  .string()
  .min(12, 'La contraseña debe tener al menos 12 caracteres')
  .max(128, 'La contraseña no puede superar 128 caracteres')
  .regex(/[a-z]/, 'Debe incluir una letra minúscula')
  .regex(/[A-Z]/, 'Debe incluir una letra mayúscula')
  .regex(/[0-9]/, 'Debe incluir un número')
  .regex(/[^A-Za-z0-9]/, 'Debe incluir un símbolo');

const name = z
  .string()
  .trim()
  .min(1, 'El nombre es obligatorio')
  .max(80, 'Nombre demasiado largo')
  .regex(/^[\p{L}\p{M}' .-]+$/u, 'El nombre solo puede contener letras, espacios, apóstrofos, puntos y guiones');

export const registerSchema = z
  .object({ email, name, password: passwordPolicy, confirmPassword: z.string() })
  .refine((d) => d.password === d.confirmPassword, { message: 'Las contraseñas no coinciden', path: ['confirmPassword'] })
  .refine((d) => !d.password.toLowerCase().includes(d.email.split('@')[0]), {
    message: 'La contraseña no debe contener tu correo',
    path: ['password'],
  });

export const loginSchema = z.object({
  email,
  password: z.string().min(1).max(128),
});

export const noteSchema = z.object({
  title: z.string().trim().min(1, 'El título es obligatorio').max(config.limits.maxNoteTitle, 'Título demasiado largo'),
  body: z
    .string()
    .max(config.limits.maxNoteBody, `La nota no puede superar ${config.limits.maxNoteBody} caracteres`)
    .default(''),
});

export const profileSchema = z.object({
  name,
  phone: z
    .string()
    .trim()
    .max(20)
    .refine((v) => v === '' || /^\+?[0-9 -]{7,20}$/.test(v), 'Teléfono inválido')
    .refine((v) => v === '' || v.replace(/\D/g, '').length >= 7, 'Teléfono inválido'),
});

export const forgotPasswordSchema = z.object({ email });

export const resetPasswordSchema = z
  .object({
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'Token inválido'),
    password: passwordPolicy,
    confirmPassword: z.string(),
  })
  .refine((d) => d.password === d.confirmPassword, { message: 'Las contraseñas no coinciden', path: ['confirmPassword'] });

export const uuidSchema = z.uuid();

export const roleChangeSchema = z.object({ role: z.enum(['user', 'admin']) });

// Devuelve { data } o { errors: [mensajes] } sin lanzar.
export const validate = (schema, input) => {
  const result = schema.safeParse(input);
  if (result.success) return { data: result.data };
  return { errors: [...new Set(result.error.issues.map((i) => i.message))] };
};
