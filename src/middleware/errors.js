// Manejo global de errores (A10). El cliente recibe un mensaje genérico y un
// identificador; el detalle (stack) solo va al log interno.
import { randomUUID } from 'node:crypto';
import { logger } from '../logger.js';

export const notFound = (req, res) => {
  res.status(404).render('error', { title: 'No encontrado', message: 'La página que buscas no existe.' });
};

// eslint-disable-next-line no-unused-vars
export const errorHandler = (err, req, res, _next) => {
  const errorId = randomUUID();
  // Errores de cliente conocidos (JSON mal formado, cuerpo demasiado grande).
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;

  logger.error(
    {
      errorId,
      status,
      method: req.method,
      path: req.path,
      userId: req.session?.userId,
      err: { message: err.message, stack: err.stack, code: err.code },
    },
    'error al procesar la petición',
  );

  if (res.headersSent) return;
  const message =
    status === 500
      ? 'Ocurrió un error inesperado. Si el problema persiste, comparte este código con soporte.'
      : 'La solicitud no se pudo procesar.';
  if (req.accepts(['html', 'json']) === 'json') return res.status(status).json({ error: message, errorId });
  return res.status(status).render('error', { title: 'Error', message, errorId });
};
