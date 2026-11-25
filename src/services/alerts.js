// Alertas de seguridad (A09) enviadas a un canal externo (Slack/Discord webhook).
// Petición saliente protegida contra SSRF (A01): solo HTTPS, solo hosts en lista blanca,
// sin seguir redirecciones y con timeout (A10).
import { config } from '../config.js';
import { logger } from '../logger.js';

export const isAllowedOutboundUrl = (rawUrl, allowedHosts = config.alertAllowedHosts) => {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  return url.protocol === 'https:' && !url.username && !url.password && allowedHosts.includes(url.hostname.toLowerCase());
};

export const sendSecurityAlert = async (message, context = {}) => {
  logger.warn({ alert: true, ...context }, `ALERTA DE SEGURIDAD: ${message}`);
  const target = config.ALERT_WEBHOOK_URL;
  if (!target) return;
  if (!isAllowedOutboundUrl(target)) {
    logger.error('ALERT_WEBHOOK_URL no está en la lista blanca; alerta externa no enviada');
    return;
  }
  try {
    const res = await fetch(target, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      // Slack usa "text"; Discord usa "content". Se envían ambos.
      body: JSON.stringify({ text: `[SecureVault] ${message}`, content: `[SecureVault] ${message}` }),
      redirect: 'error',
      signal: AbortSignal.timeout(3_000),
    });
    if (!res.ok) logger.error({ status: res.status }, 'el webhook de alertas respondió con error');
  } catch (err) {
    logger.error({ err: { message: err.message } }, 'no se pudo enviar la alerta externa');
  }
};
