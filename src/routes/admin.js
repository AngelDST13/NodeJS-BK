import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { validate, roleChangeSchema, uuidSchema } from '../validation/schemas.js';
import { listUsers, changeRole } from '../services/users.js';
import { listEvents } from '../services/audit.js';

export const adminRouter = Router();
// Denegar por defecto: todo /admin exige sesión y rol admin verificado en el servidor.
adminRouter.use(requireAuth, requireRole('admin'));

adminRouter.get('/', async (req, res) => {
  const [users, events] = await Promise.all([listUsers(), listEvents(100)]);
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('admin', { title: 'Administración', users, events, flash });
});

adminRouter.post('/users/:id/role', async (req, res) => {
  const { data, errors } = validate(roleChangeSchema, req.body);
  const idOk = uuidSchema.safeParse(req.params.id).success;
  if (errors || !idOk) {
    req.session.flash = 'Solicitud inválida.';
    return res.redirect(303, '/admin');
  }
  const result = await changeRole({ adminId: req.user.id, targetId: req.params.id, role: data.role }, req.ip);
  req.session.flash = result.error ?? 'Rol actualizado.';
  return res.redirect(303, '/admin');
});
