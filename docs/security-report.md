# Informe de seguridad — SecureVault

> Las evidencias marcadas **[LOCAL]** se obtuvieron en desarrollo y en CI. La verificación sobre la URL de producción está en la sección 4.

## 1. Mapa OWASP Top 10:2025 → mitigación → evidencia

| Categoría | Mitigación implementada | Código | Evidencia |
|---|---|---|---|
| **A01 Broken Access Control (incl. SSRF)** | Todas las consultas de notas filtran `WHERE id = $1 AND owner_id = $2`; 404 sin revelar existencia; intento registrado como `authz.access_denied`. `/admin` con `requireRole('admin')` y el rol leído de la BD en cada petición. Esquemas zod descartan campos extra (`role`). CSRF: token sincronizador + `Origin` + `SameSite=Strict`. SSRF: webhook de alertas solo HTTPS, lista blanca de hosts, sin redirecciones. | `src/services/notes.js`, `src/middleware/auth.js`, `src/middleware/csrf.js`, `src/services/alerts.js` | [LOCAL] `test/notes.test.js` «A01 (IDOR): Alice no puede leer, editar ni borrar la nota de Bob» → 404 ×4 y 4 eventos en bitácora. `test/security.test.js` «usuario normal recibe 403 en /admin». `test/crypto.test.js` «SSRF». Producción: 404 al leer y borrar (sección 4). |
| **A02 Security Misconfiguration** | helmet con CSP estricta (`script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`), HSTS 1 año, `X-Powered-By` desactivado, sin cabeceras CORS (ningún origen externo puede leer respuestas), `NODE_ENV=production`, errores genéricos, sin rutas de depuración, `Cache-Control: no-store`, `Permissions-Policy`. La app no arranca con configuración insegura (`src/config.js`). | `src/app.js`, `src/config.js` | [LOCAL] `test/security.test.js` «cabeceras de seguridad». Producción: **A+** en securityheaders.com y Mozilla Observatory (sección 4). |
| **A03 Software Supply Chain Failures** | `package-lock.json` versionado, `npm ci` en CI y Docker, `npm audit --audit-level=high` bloquea el pipeline, Dependabot (npm, Actions, Docker), 11 dependencias directas, gitleaks en CI. | `.github/workflows/ci.yml`, `.github/dependabot.yml` | [LOCAL] `npm audit` → `found 0 vulnerabilities` (25/11/2026). Dependabot ya abrió PRs reales (actions/checkout 5→7, setup-node 5→7, gitleaks-action 2→3, imagen node 24→26), todos con CI en verde. Producción: pipeline en verde en https://github.com/AngelDST13/NodeJS-BK/actions (gitleaks, `npm audit`, pruebas, build Docker). |
| **A04 Cryptographic Failures** | Argon2id (m=19456 KiB, t=2, p=1); AES-256-GCM con IV aleatorio de 12 B por registro, tag de 16 B y AAD; SHA-256 para tokens de alta entropía; HMAC-SHA256 para la bitácora; llaves en variables de entorno (panel de Render), nunca en el repo; TLS obligatorio (redirección 308 + HSTS); cookie `Secure` en producción; conexión a BD con TLS y verificación de certificado. | `src/crypto/*`, `src/db/pool.js` | [LOCAL] captura de la BD (abajo). `test/crypto.test.js`. Producción: **A+** en SSL Labs (sección 4). |
| **A05 Injection (incl. XSS)** | Solo consultas parametrizadas (`$1…`); validación de entrada con zod; `:id` validado como UUID; EJS escapa con `<%= %>`; CSP bloquea scripts inline. | `src/db/pool.js`, `src/validation/schemas.js`, `src/views/*` | [LOCAL] `test/auth.test.js` «inyección SQL en el login no autentica» (`' OR 1=1 --` → 401); `test/notes.test.js` «XSS: un `<script>` se muestra escapado». Captura del navegador mostrando `<script>alert(1)</script>` como texto. |
| **A06 Insecure Design** | Modelo STRIDE con 19 amenazas, límites de negocio (100 notas, 5000 caracteres, 64 KB por petición), casos de abuso documentados. | `docs/threat-model.md` | Diagramas + tabla STRIDE en `docs/threat-model.md`; `test/notes.test.js` «A06: límite de tamaño / cantidad». |
| **A07 Authentication Failures** | Rate limit (5 fallos/IP/15 min → 429), bloqueo progresivo por cuenta (1→60 min), mensajes genéricos, hash ficticio contra enumeración por tiempo, `session.regenerate()` al autenticar, expiración 30 min inactividad / 8 h absoluta, logout que destruye la sesión, invalidación de sesiones al restablecer contraseña. | `src/middleware/rateLimit.js`, `src/services/users.js`, `src/routes/auth.js` | [LOCAL] `test/home.test.js` «Reto: fuerza bruta frenada con HTTP 429 al sexto intento» y «tras 5 fallos seguidos la cuenta se bloquea aunque se acierte». En la portada, el reto del sello permite demostrarlo en vivo. `test/auth.test.js` «fuerza bruta en login devuelve HTTP 429», «bloqueo progresivo», «cierre de sesión invalida la sesión». Producción: ver sección 4 (corrección de `TRUST_PROXY`). |
| **A08 Software or Data Integrity Failures** | No se deserializa nada no confiable (solo `urlencoded` con `extended:false`); sin JWT (sesiones de servidor); SRI (`integrity="sha384-…"`) en las hojas de tipografías del CDN (versión fija); HMAC por fila de la bitácora; pipeline CI (gitleaks → audit → pruebas → build) y Render despliega solo con checks en verde (`autoDeployTrigger: checksPass`). | `src/app.js`, `src/views/partials/header.ejs`, `.github/workflows/ci.yml`, `render.yaml` | [LOCAL] `test/security.test.js` «SRI» y «panel detecta registros alterados»; `test/production.test.js` (HTTPS obligatorio, HSTS, arranque rechazado sin TLS a la BD). Archivo `ci.yml`. |
| **A09 Security Logging and Alerting Failures** | Bitácora en BD + logs JSON (pino) de: registro, login ok/fallido, bloqueo, logout, recuperación, accesos denegados, cambio de rol, rate limit, CSRF. Redacción de `password`, `token`, `cookie`, `body`, `phone`. Alerta al 5.º fallo consecutivo (log `warn` + webhook opcional). | `src/services/audit.js`, `src/logger.js`, `src/services/alerts.js` | [LOCAL] `test/auth.test.js` «la bitácora registra eventos sin contraseñas ni tokens». Muestra de log abajo. Captura del panel con la bitácora y la columna de firma HMAC: `evidencias/panel-admin-bitacora.png` (entorno local). |
| **A10 Mishandling of Exceptional Conditions** | Manejador global: mensaje genérico + `errorId`, detalle solo en log; `unhandledRejection`/`uncaughtException` → log fatal y salida (la plataforma reinicia); fail closed en configuración, descifrado y verificación de hash; timeouts en BD (5 s), webhook (3 s) y servidor HTTP. | `src/middleware/errors.js`, `src/server.js`, `src/db/pool.js` | [LOCAL] `test/security.test.js` «errores no controlados devuelven respuesta genérica sin stack», «cuerpos gigantes → 413». |

## 2. Evidencias locales

### Base de datos: hashes y datos cifrados

```
 email                | hash                                     | phone
----------------------+------------------------------------------+------------------------------------------
 qa1795618779200@exam | $argon2id$v=19$m=19456,t=2,p=1$kfh3ZCY0R | v1.kFMmH1csS0lLXHD5.I6IaNIBr+Bel5EFUSXCF…

 title_enc                                          | body_enc
----------------------------------------------------+----------------------------------------------------
 v1.tUlnVE8RXcuP2McY.p4S0X5gJvt4oLYuCuz409w==.Ij3y/… | v1.sIDZaAy2nsdo9d6s.ateDgAoC9tWnMhKveicnug==.ves4b…
```

Formato `v<versión de llave>.<IV 12 B>.<tag 16 B>.<datos>` en base64.

### npm audit

```
$ npm audit --audit-level=high
found 0 vulnerabilities
```

### Muestra de log JSON (intento CSRF rechazado)

```json
{"level":30,"time":"2026-11-25T14:58:48.959Z","service":"securevault","audit":{"eventType":"security.csrf_rejected","actorId":null,"targetId":null,"ip":"::1","details":{"path":"/register","reason":"origin"}},"msg":"security.csrf_rejected"}
```

### Pruebas automáticas

`npm test` → 55 pruebas, 55 correctas (node:test + supertest contra PostgreSQL 17), en Node 24 local y Node 26 (imagen `node:26-alpine` y CI).

## 3. Decisiones criptográficas

| Dato | Técnica | Parámetros | Justificación |
|---|---|---|---|
| Contraseña | Argon2id | m=19 MiB, t=2, p=1, sal aleatoria | Mínimo recomendado por OWASP Password Storage Cheat Sheet; resistente a GPU por el coste de memoria. Nunca se necesita el valor original. |
| Notas (título y contenido) | AES-256-GCM | IV 12 B aleatorio por cifrado, tag 16 B, AAD `securevault:notes:<campo>:<id>` | El dueño debe volver a leerlas; GCM detecta manipulación. El AAD impide mover un cifrado válido a otra fila/usuario. |
| Teléfono | AES-256-GCM | ídem, AAD `securevault:users:phone:<id>` | Se muestra enmascarado; se descifra solo en el servidor. |
| Token de recuperación | `randomBytes(32)` + SHA-256 | 256 bits de entropía | No necesita hash lento por su entropía; si roban la BD los hashes no sirven. |
| Bitácora | HMAC-SHA256 | llave `AUDIT_HMAC_KEY` de 32 B | Detecta modificaciones directas en la BD. |
| Token CSRF | `randomBytes(32)` | comparación en tiempo constante | |
| Tránsito | TLS 1.2/1.3 | certificado gestionado por Render; TLS a Neon con verificación | Protege credenciales y cookies. |

No se usa: MD5, SHA-1, hash simple para contraseñas, ECB, `createCipher()`, IV fijo, `Math.random()` ni llaves en el código.

### Pregunta de análisis: ¿qué pasa si se pierde la llave? ¿cómo rotarla?

- **Pérdida de la llave:** las notas y teléfonos cifrados con ella son **irrecuperables**; GCM no tiene puerta trasera. Las cuentas siguen funcionando (las contraseñas son hashes, no dependen de la llave). Mitigación: copia de la llave en un gestor de contraseñas/bóveda separada del entorno de producción, con acceso restringido.
- **Filtración de la llave:** rotar de inmediato (abajo); los datos ya robados de la BD siguen expuestos con la llave vieja, así que se trata como incidente.
- **Rotación sin pérdida (implementada):** cada valor cifrado lleva su versión (`v1.`, columna `enc_key_version` / `phone_key_version`). La app acepta varias llaves (`DATA_ENCRYPTION_OLD_KEYS`) para leer y cifra siempre con la actual. `npm run rotate-keys` re-cifra en lotes con `FOR UPDATE SKIP LOCKED` y reporta pendientes; al llegar a 0 se retira la llave vieja. Probado en `test/rotation.test.js`.

## 4. Verificación en producción

URL: https://securevault-s20f.onrender.com · fecha: 26/11/2026. Las capturas y el informe de ZAP están en [`docs/evidencias/`](evidencias/).

| Herramienta / prueba | Resultado esperado | Resultado obtenido | Evidencia |
|---|---|---|---|
| securityheaders.com | A o A+ | **A+** (CSP, Permissions-Policy, Referrer-Policy, HSTS, X-Content-Type-Options, X-Frame-Options) | `evidencias/securityheaders.jpg` |
| Mozilla Observatory | — | **A+**, 140 puntos, 12/12 pruebas | `evidencias/mozilla-observatory.png` |
| Qualys SSL Labs | A | **A+** en los dos servidores de Render | `evidencias/ssllabs.jpg` |
| OWASP ZAP baseline | Sin alertas High | **0 FAIL, 0 High, 0 Medium**; 1 Low (COEP ausente, ya corregido: `Cross-Origin-Embedder-Policy: require-corp`) y avisos informativos propios de una app con login | `evidencias/zap-baseline.html` |
| HTTP → HTTPS | 301/308 a https | **301** a `https://…` | `curl -I http://…/login` |
| Cookie de sesión | HttpOnly, Secure, SameSite | `HttpOnly; Secure; SameSite=Strict` | cabecera `Set-Cookie` |
| `/health` | `{"status":"ok"}` | `{"status":"ok"}`, sin versiones | `curl …/health` |
| IDOR | 404 | La cuenta A recibe **404** al leer y al borrar la nota de B; la nota de B sigue intacta | prueba manual con dos cuentas de verificación |
| XSS almacenado | Escapado | `<script>` guardado en una nota se muestra como `&lt;script&gt;` | prueba manual |
| Inyección SQL `' OR 1=1 --` | Rechazada | **403 del WAF de Cloudflare** que Render tiene delante (defensa en profundidad). La protección propia de la app (consultas parametrizadas → 401) está en `test/auth.test.js` | prueba manual + prueba automática |
| CSRF sin token | 403 | **403** | prueba manual |
| Errores | Mensaje genérico | `/debug` → 404 genérico, sin stack | prueba manual |
| Fuerza bruta (6 intentos) | 429 en el 6.º | Con `TRUST_PROXY=1` **no** se alcanzaba el 429: Render tiene dos proxies delante y la app veía la IP de Cloudflare, distinta en cada petición. Corregido a `TRUST_PROXY=2` (ver abajo). El bloqueo progresivo por cuenta, que se guarda en la BD, sí funcionaba | prueba manual |

**Hallazgo corregido durante la verificación (A07):** el límite de intentos por IP depende de que `req.ip` sea la IP real del cliente. En Render la cadena es cliente → Cloudflare → balanceador de Render → app, así que hacen falta dos saltos de confianza. Se cambió `TRUST_PROXY` a `2` en `render.yaml` y se volvió a verificar en producción (sección siguiente).

## 5. Riesgos residuales

| Riesgo | Por qué queda | Mitigación futura |
|---|---|---|
| Rate limit en memoria | Se reinicia si el contenedor se reinicia o duerme (plan gratuito) y no se comparte entre réplicas. El bloqueo por cuenta sí persiste en la BD. | Almacén compartido (Redis / tabla en PostgreSQL). |
| Número de proxies de Render | Si Render cambia su topología, `TRUST_PROXY=2` podría dejar de ser correcto y el límite por IP fallaría o aceptaría IP falsificadas. | Revisar el contador del reto tras cada cambio de plataforma; a futuro, verificar la IP con la cabecera propia del proveedor. |
| Llave de cifrado en variable de entorno | Quien tenga acceso al panel de Render o a la memoria del proceso la obtiene. | KMS (AWS KMS, GCP KMS) con cifrado por sobre (*envelope encryption*). |
| Sin MFA | Una contraseña filtrada basta para entrar. | TOTP (RFC 6238) como segundo factor. |
| Sin verificación de correo | Se puede registrar un correo ajeno (no da acceso a nada del dueño real). | Correo de verificación con token de un solo uso. |
| Bloqueo de cuenta abusable | Un atacante puede bloquear temporalmente a una víctima (máx. 60 min). | CAPTCHA tras N fallos en vez de bloqueo duro. |
| Límite de 100 notas no es estrictamente atómico | Dos inserciones simultáneas al borde del límite podrían dejar 101. | Restricción con trigger o bloqueo por usuario. |
| Plan gratuito duerme | Primera petición tras inactividad tarda ~1 min. | Plan pagado o instancia siempre activa. |
| Tipografías desde un CDN | Dependencia externa (mitigada con versión fija + SRI: si cambian, no se cargan). | Servirlas localmente. |
