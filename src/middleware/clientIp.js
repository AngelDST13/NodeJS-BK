// IP real del cliente detrás de una CDN (A07: el límite de intentos por IP depende de esto).
// Si CLIENT_IP_HEADER está configurado (p. ej. cf-connecting-ip en Render, que va detrás de
// Cloudflare), se usa esa cabecera: la pone la CDN y sobrescribe cualquier valor del cliente.
// Si falta o no es una IP válida, se usa req.ip calculado con TRUST_PROXY.
import { isIP } from 'node:net';

export const clientIp = (headerName) => (req, res, next) => {
  if (headerName) {
    const value = req.get(headerName)?.trim();
    if (value && isIP(value)) {
      Object.defineProperty(req, 'ip', { value, configurable: true, enumerable: true });
    }
  }
  next();
};
