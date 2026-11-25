# Sigilo

**Sigilo** es nuestra implementación de *SecureVault*, el sistema del laboratorio.

Es una aplicación web para guardar notas privadas y un dato sensible de perfil (teléfono), construida con Node.js aplicando el **OWASP Top 10:2025**, hash de contraseñas con **Argon2id**, cifrado autenticado **AES-256-GCM** y despliegue en producción con HTTPS.

| Documento | Contenido |
|---|---|
| [docs/deep-research.md](docs/deep-research.md) | Fase 0: investigación sobre despliegue de Node.js en producción |
| [docs/threat-model.md](docs/threat-model.md) | Fase 1: modelo de datos, flujo de autenticación y modelo de amenazas STRIDE (A06) |
| [docs/security-report.md](docs/security-report.md) | Fase 4: mapa OWASP Top 10:2025 → mitigación → evidencia, decisiones criptográficas y riesgos residuales |

## Funcionalidad

| ID | Requisito | Dónde |
|---|---|---|
| RF-01 | Registro con política de contraseñas; solo se guarda el hash Argon2id | `src/routes/auth.js`, `src/validation/schemas.js` |
| RF-02 | Sesión en cookie `HttpOnly` + `Secure` + `SameSite=Strict`, ID regenerado al entrar, logout que destruye la sesión en el servidor | `src/app.js`, `src/routes/auth.js` |
| RF-03 | Roles `user` / `admin`, leídos de la BD en cada petición | `src/middleware/auth.js` |
| RF-04 | CRUD de notas propias; título y contenido cifrados | `src/routes/notes.js`, `src/services/notes.js` |
| RF-05 | Teléfono cifrado y mostrado como `***-***-1234` | `src/services/users.js` |
| RF-06 | Recuperación con token aleatorio de un solo uso (30 min); en BD solo su SHA-256 | `src/services/users.js` |
| RF-07 | Panel admin: usuarios, cambio de rol y bitácora con verificación HMAC | `src/routes/admin.js`, `src/services/audit.js` |
| RF-08 | `GET /health` → `{"status":"ok"}` sin versiones | `src/routes/health.js` |

## Stack

Node.js 24 LTS · Express 5 · PostgreSQL (`pg`, consultas parametrizadas) · EJS (escape automático) · helmet · express-rate-limit · express-session + connect-pg-simple · zod · argon2 · `node:crypto` · pino (logs JSON) · nodemailer.

## Instalación local

Requisitos: Node.js 24+, Docker (para PostgreSQL).

```bash
npm ci
cp .env.example .env
npm run gen-keys            # copia la salida dentro de .env
npm run db:up               # PostgreSQL 17 en 127.0.0.1:5432 (crea también securevault_test)
npm run dev                 # aplica migraciones y arranca en http://localhost:3000
```

**Cuentas de prueba (solo desarrollo):** `npm run seed` crea un usuario con notas de ejemplo y un administrador; sus credenciales aparecen en la pantalla de login mientras `NODE_ENV=development`. El script se niega a correr en producción y el login no las muestra fuera de desarrollo.

Para promover otra cuenta a administrador: regístrala en `/register` y luego `npm run create-admin -- tu@correo.com`.

Sin `SMTP_URL`, el enlace de recuperación de contraseña se imprime en la consola local (solo en desarrollo).

### Pruebas

```bash
# .env.test: igual que .env pero con NODE_ENV=test, TRUST_PROXY=1,
# DATABASE_URL=postgres://securevault:securevault@localhost:5432/securevault_test y llaves propias
npm test
```

43 pruebas cubren los requisitos funcionales y las evidencias OWASP (IDOR, XSS, inyección SQL, fuerza bruta → 429, CSRF, cabeceras, cifrado en BD, rotación de llaves, etc.).

## Variables de entorno

Solo nombres; los valores van en `.env` (local, excluido de Git) o en el panel de secretos de la plataforma.

| Variable | Obligatoria | Descripción |
|---|---|---|
| `NODE_ENV` | sí | `production` en el servidor |
| `PORT` | no | Puerto HTTP (la plataforma lo inyecta) |
| `APP_ORIGIN` | sí | URL pública, p. ej. `https://securevault.onrender.com`. Se usa para CSRF/Origin y enlaces de correo |
| `TRUST_PROXY` | sí en prod | Número de proxies delante de la app (`1` en Render) |
| `DATABASE_URL` | sí | Cadena de conexión PostgreSQL |
| `DATABASE_SSL` | sí en prod | `true` exige TLS con verificación de certificado |
| `SESSION_SECRET` | sí | ≥ 32 caracteres aleatorios |
| `DATA_ENCRYPTION_KEY` | sí | 32 bytes en base64 (AES-256-GCM) |
| `DATA_ENCRYPTION_KEY_VERSION` | no | Versión de la llave actual (por defecto `1`) |
| `DATA_ENCRYPTION_OLD_KEYS` | no | Llaves anteriores durante una rotación: `1:<base64>,2:<base64>` |
| `AUDIT_HMAC_KEY` | sí | 32 bytes en base64 para firmar la bitácora |
| `SMTP_URL`, `MAIL_FROM` | recomendado | Envío del correo de recuperación |
| `ALERT_WEBHOOK_URL`, `ALERT_ALLOWED_HOSTS` | no | Alertas a Slack/Discord; el host debe estar en la lista blanca |
| `LOGIN_ALERT_THRESHOLD` | no | Fallos consecutivos que bloquean la cuenta y disparan alerta (por defecto 5) |
| `LOG_LEVEL` | no | Nivel de pino |

La app **no arranca** si falta un secreto, si una llave no mide 32 bytes, o si en producción `DATABASE_SSL` no es `true` o `APP_ORIGIN` no es `https://`.

## Despliegue (Render + Neon)

Arquitectura: navegador → HTTPS (certificado gestionado por Render) → proxy de Render → contenedor Docker (usuario no root) → PostgreSQL en Neon con TLS obligatorio.

1. **Base de datos (Neon):** crear proyecto → copiar la cadena de conexión con `sslmode=require`. Crear un rol propio para la app (no usar el rol dueño en producción si es posible).
2. **Repositorio:** subir a GitHub. Activar Dependabot alerts y *secret scanning* en *Settings → Security*.
3. **Render:** *New → Blueprint* → elegir el repositorio. Render lee `render.yaml` y pide los valores marcados `sync: false`:
   - `DATABASE_URL` (de Neon), `APP_ORIGIN` (`https://<servicio>.onrender.com`)
   - `SESSION_SECRET`, `DATA_ENCRYPTION_KEY`, `AUDIT_HMAC_KEY` → generarlos con `npm run gen-keys` **en una máquina de confianza** y pegarlos solo en Render. Guardar copia de `DATA_ENCRYPTION_KEY` en un gestor de contraseñas: si se pierde, las notas son irrecuperables.
4. Render construye el `Dockerfile`, la app aplica migraciones al arrancar y el health check usa `/health`. HTTPS es automático y la app redirige HTTP→HTTPS (308) y envía HSTS.
5. `autoDeployTrigger: checksPass`: cada push a `main` se despliega **solo si** GitHub Actions (gitleaks, `npm audit`, pruebas, build Docker) pasó.
6. Crear el administrador: registrarse en la URL pública y ejecutar `npm run create-admin -- correo` desde la *Shell* del servicio en Render (o local con `DATABASE_URL` de producción).
7. Verificar: `securityheaders.com`, `ssllabs.com/ssltest`, OWASP ZAP baseline (ver `docs/security-report.md`).

Reinicio automático: Render reinicia el contenedor si el proceso termina (la app sale a propósito ante `unhandledRejection`/`uncaughtException`) o si `/health` falla.

### Rotación de la llave de cifrado

1. `npm run gen-keys` → nueva llave.
2. En Render: `DATA_ENCRYPTION_OLD_KEYS=1:<llave_actual>`, `DATA_ENCRYPTION_KEY=<nueva>`, `DATA_ENCRYPTION_KEY_VERSION=2` → redeploy (lee v1 y v2, cifra con v2).
3. `npm run rotate-keys` → re-cifra todo; debe terminar con `Pendientes: 0`.
4. Quitar la llave vieja de `DATA_ENCRYPTION_OLD_KEYS`.

## Estructura

```
src/
  app.js, server.js, config.js, logger.js
  crypto/       encryption.js (AES-256-GCM), passwords.js (Argon2id), tokens.js (random/SHA-256/HMAC)
  db/           pool.js (timeouts), migrate.js, migrations/*.sql
  middleware/   auth.js, csrf.js, rateLimit.js, errors.js
  routes/       auth, notes, profile, admin, health
  services/     users, notes, audit (HMAC), alerts (SSRF allowlist), mailer
  validation/   schemas.js (zod)
  views/        plantillas EJS
scripts/        gen-keys, create-admin, rotate-keys
test/           pruebas node:test + supertest
```

Las credenciales de prueba (usuario y administrador) se entregan al docente por canal privado, no en este repositorio.
