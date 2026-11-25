import request from 'supertest';
import { createApp } from '../src/app.js';
import { migrate } from '../src/db/migrate.js';
import { pool, query } from '../src/db/pool.js';

export const STRONG_PASSWORD = 'Sup3r-Secreta!2026';

let ipCounter = 1;
// Cada agente simula un cliente con IP propia (vía X-Forwarded-For + trust proxy),
// para que los límites de tasa de una prueba no afecten a otra.
export const newIp = () => `10.0.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`;

let app;
export const setup = async () => {
  await migrate();
  await query('TRUNCATE audit_events, password_reset_tokens, notes, session, users RESTART IDENTITY CASCADE');
  app ??= createApp();
  return app;
};

export const teardown = () => pool.end();

export const newAgent = (ip = newIp()) => request.agent(app).set('X-Forwarded-For', ip);

export const csrfFrom = (html) => {
  const match = /name="_csrf" value="([^"]+)"/.exec(html);
  if (!match) throw new Error('No se encontró token CSRF en la página');
  return match[1];
};

export const getCsrf = async (agent, path = '/login') => csrfFrom((await agent.get(path)).text);

export const register = async (agent, { email, name = 'Usuario Prueba', password = STRONG_PASSWORD }) => {
  const _csrf = await getCsrf(agent, '/register');
  return agent.post('/register').type('form').send({ _csrf, email, name, password, confirmPassword: password });
};

export const login = async (agent, { email, password = STRONG_PASSWORD }) => {
  const _csrf = await getCsrf(agent, '/login');
  return agent.post('/login').type('form').send({ _csrf, email, password });
};

export const registerAndLogin = async (email, opts = {}) => {
  await register(newAgent(), { email, ...opts });
  const agent = newAgent();
  const res = await login(agent, { email, ...opts });
  if (res.status !== 303) throw new Error(`login falló (${res.status})`);
  return agent;
};

export const createNote = async (agent, title, body) => {
  const _csrf = await getCsrf(agent, '/notes/new');
  const res = await agent.post('/notes').type('form').send({ _csrf, title, body });
  return res.headers.location?.split('/').pop();
};
