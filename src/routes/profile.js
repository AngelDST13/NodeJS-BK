import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate, profileSchema } from '../validation/schemas.js';
import { getProfile, updateProfile } from '../services/users.js';

export const profileRouter = Router();
profileRouter.use(requireAuth);

profileRouter.get('/', async (req, res) => {
  const profile = await getProfile(req.user.id);
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('profile', { title: 'Mi perfil', profile, errors: [], flash });
});

profileRouter.post('/', async (req, res) => {
  const { data, errors } = validate(profileSchema, req.body);
  if (errors) {
    const profile = await getProfile(req.user.id);
    return res.status(400).render('profile', { title: 'Mi perfil', profile, errors, flash: null });
  }
  // El id siempre sale de la sesión, nunca del formulario (evita modificar a otros usuarios).
  await updateProfile(req.user.id, data);
  req.session.flash = 'Perfil actualizado.';
  return res.redirect(303, '/profile');
});
