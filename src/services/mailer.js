// Envío de correos (recuperación de contraseña).
// - Producción: SMTP_URL configurado en el gestor de secretos de la plataforma.
// - Desarrollo sin SMTP: el enlace se imprime SOLO en la consola local (nunca en el log JSON).
import nodemailer from 'nodemailer';
import { config } from '../config.js';
import { logger } from '../logger.js';

const transport = config.SMTP_URL ? nodemailer.createTransport(config.SMTP_URL) : null;

// Último correo "enviado" sin SMTP; las pruebas automáticas lo leen.
export const outbox = [];

export const sendPasswordResetEmail = async (to, resetUrl) => {
  const message = {
    from: config.MAIL_FROM,
    to,
    subject: 'Recupera tu contraseña de Sigilo',
    text: `Alguien solicitó restablecer tu contraseña.\n\nEnlace (válido 30 minutos, un solo uso):\n${resetUrl}\n\nSi no fuiste tú, ignora este correo.`,
  };

  if (transport) {
    try {
      await transport.sendMail(message);
    } catch (err) {
      // Falla el envío pero la respuesta al usuario no cambia (no revela si la cuenta existe).
      logger.error({ err: { message: err.message, code: err.code } }, 'no se pudo enviar el correo de recuperación');
    }
    return;
  }
  if (config.isProduction) {
    logger.error('SMTP_URL no configurado: no se puede enviar el correo de recuperación');
    return;
  }
  outbox.push(message);
  if (!config.isTest) console.log(`\n[DEV] Correo de recuperación para ${to}:\n${resetUrl}\n`);
};
