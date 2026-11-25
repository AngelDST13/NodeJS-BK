// Comportamiento en modo producción (sección 6 del laboratorio), ejecutado en un proceso aparte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const prodEnv = (overrides = {}) => ({
  ...process.env,
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://sigilo.example.com',
  DATABASE_SSL: 'true',
  TRUST_PROXY: '1',
  ...overrides,
});

test('producción: la app no arranca sin TLS hacia la base de datos', async () => {
  await assert.rejects(
    run(process.execPath, ['-e', "await import('./src/config.js')", '--input-type=module'], {
      env: prodEnv({ DATABASE_SSL: 'false' }),
    }),
    (err) => err.code === 1 && /DATABASE_SSL debe ser true/.test(err.stderr),
  );
});

test('producción: la app no arranca si APP_ORIGIN no es https', async () => {
  await assert.rejects(
    run(process.execPath, ['-e', "await import('./src/config.js')", '--input-type=module'], {
      env: prodEnv({ APP_ORIGIN: 'http://sigilo.example.com' }),
    }),
    (err) => err.code === 1 && /APP_ORIGIN debe usar https/.test(err.stderr),
  );
});

test('producción: HTTP redirige a HTTPS y se envía HSTS', async () => {
  const script = `
    const { default: request } = await import('supertest');
    const { createApp } = await import('./src/app.js');
    const app = createApp();
    const http = await request(app).get('/login?x=1').set('X-Forwarded-Proto', 'http').set('Host', 'sigilo.example.com');
    const https = await request(app).get('/static/css/app.css').set('X-Forwarded-Proto', 'https');
    console.log(JSON.stringify({ status: http.status, location: http.headers.location, hsts: https.headers['strict-transport-security'], csp: https.headers['content-security-policy'] }));
    process.exit(0);`;
  const { stdout } = await run(process.execPath, ['--input-type=module', '-e', script], { env: prodEnv() });
  const r = JSON.parse(stdout.trim().split('\n').pop());
  assert.equal(r.status, 308);
  assert.equal(r.location, 'https://sigilo.example.com/login?x=1');
  assert.match(r.hsts, /max-age=31536000; includeSubDomains/);
  assert.match(r.csp, /upgrade-insecure-requests/);
});
