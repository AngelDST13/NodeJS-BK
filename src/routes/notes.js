import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { validate, noteSchema, uuidSchema } from '../validation/schemas.js';
import { listNotes, getNote, createNote, updateNote, deleteNote, noteExists } from '../services/notes.js';
import { recordEvent, AuditEvent } from '../services/audit.js';
import { config } from '../config.js';

export const notesRouter = Router();
notesRouter.use(requireAuth);

// 404 tanto si la nota no existe como si es de otro usuario: no se revela su existencia.
// Si existe y es ajena, se registra como intento de acceso indebido (IDOR).
const notFound = async (req, res) => {
  const { success } = uuidSchema.safeParse(req.params.id);
  if (success && (await noteExists(req.params.id))) {
    await recordEvent({
      eventType: AuditEvent.ACCESS_DENIED,
      actorId: req.user.id,
      targetId: req.params.id,
      ip: req.ip,
      details: { resource: 'note', method: req.method },
    });
  }
  return res.status(404).render('error', { title: 'No encontrado', message: 'La nota no existe.' });
};

const validId = (req) => uuidSchema.safeParse(req.params.id).success;

notesRouter.get('/', async (req, res) => {
  const notes = await listNotes(req.user.id);
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('notes/index', { title: 'Mis notas', notes, flash, limits: config.limits });
});

notesRouter.get('/new', (req, res) => {
  res.render('notes/form', { title: 'Nueva nota', note: { title: '', body: '' }, errors: [], limits: config.limits });
});

notesRouter.post('/', async (req, res) => {
  const { data, errors } = validate(noteSchema, req.body);
  if (errors) {
    return res
      .status(400)
      .render('notes/form', { title: 'Nueva nota', note: req.body, errors, limits: config.limits });
  }
  const id = await createNote(req.user.id, data);
  if (!id) {
    return res.status(409).render('notes/form', {
      title: 'Nueva nota',
      note: data,
      errors: [`Alcanzaste el máximo de ${config.limits.maxNotesPerUser} notas.`],
      limits: config.limits,
    });
  }
  return res.redirect(303, `/notes/${id}`);
});

notesRouter.get('/:id', async (req, res) => {
  const note = validId(req) ? await getNote(req.user.id, req.params.id) : null;
  if (!note) return notFound(req, res);
  return res.render('notes/show', { title: note.title, note });
});

notesRouter.get('/:id/edit', async (req, res) => {
  const note = validId(req) ? await getNote(req.user.id, req.params.id) : null;
  if (!note) return notFound(req, res);
  return res.render('notes/form', { title: 'Editar nota', note, errors: [], limits: config.limits });
});

notesRouter.post('/:id', async (req, res) => {
  if (!validId(req)) return notFound(req, res);
  const { data, errors } = validate(noteSchema, req.body);
  if (errors) {
    return res.status(400).render('notes/form', {
      title: 'Editar nota',
      note: { ...req.body, id: req.params.id },
      errors,
      limits: config.limits,
    });
  }
  if (!(await updateNote(req.user.id, req.params.id, data))) return notFound(req, res);
  return res.redirect(303, `/notes/${req.params.id}`);
});

notesRouter.post('/:id/delete', async (req, res) => {
  if (!validId(req) || !(await deleteNote(req.user.id, req.params.id))) return notFound(req, res);
  req.session.flash = 'Nota eliminada.';
  return res.redirect(303, '/notes');
});
