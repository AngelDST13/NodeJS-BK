# Fase 0 — Deep Research: despliegue de aplicaciones Node.js en producción

> Investigación preparada el 25/11/2026. Los planes gratuitos cambian con frecuencia (Fly.io cambió el suyo esta misma semana): antes de entregar, el equipo debe abrir cada fuente oficial, confirmar los datos y anotar la fecha de consulta. Los números entre corchetes remiten a la lista de referencias.

## Resumen ejecutivo

Una app Node.js se puede publicar en tres modelos: **PaaS** (la plataforma gestiona servidor, TLS y reinicios), **contenedores** (empaquetamos app + runtime en una imagen reproducible que corre en cualquier orquestador o PaaS) y **VPS/IaaS** (alquilamos una máquina y administramos todo). Para un proyecto académico de dos semanas, con poco presupuesto y foco en seguridad de la aplicación, conviene un PaaS que acepte una imagen Docker: obtenemos HTTPS automático, gestor de secretos y reinicio automático sin administrar un sistema operativo, y el `Dockerfile` hace el despliegue portable.

**Decisión para SecureVault:** web service Docker en **Render** (plan gratuito) + **PostgreSQL gestionado en Neon** (plan gratuito, TLS obligatorio), con **GitHub Actions** como CI y despliegue automático solo cuando el pipeline pasa. Render tiene HTTPS automático y panel de secretos; su base de datos gratuita expira a los 30 días [1][2], por eso la BD va en Neon, cuyo plan gratuito no caduca [5].

## Respuestas

### 1. PaaS vs. contenedores vs. VPS/IaaS

| | PaaS (Render, Railway, Fly.io, Heroku) | Contenedores (Docker) | VPS / IaaS (EC2, DigitalOcean, Azure VM) |
|---|---|---|---|
| Qué gestionas | Solo código y variables | Imagen (SO base, runtime, app) | Todo: SO, parches, firewall, proxy, TLS, procesos |
| Ventajas | Rápido, TLS y reinicios incluidos, poco mantenimiento | Reproducible ("funciona igual en todas partes"), portable entre proveedores | Control total, precio predecible a escala |
| Desventajas | Menos control, límites del plan, *vendor lock-in*, planes gratis que duermen | Hay que mantener la imagen y escanearla; necesita dónde correr (PaaS, Kubernetes, VPS) | Toda la seguridad del servidor es tuya; más tiempo de operación |
| Costo | Gratis–bajo al inicio, sube con el uso | Depende de dónde se ejecute | Desde unos USD 4–6/mes por VM pequeña |
| Control | Bajo | Medio | Alto |

Los contenedores no excluyen a los otros dos: Render, Railway y Fly.io ejecutan imágenes Docker. Por eso SecureVault entrega un `Dockerfile` (usuario no root, `npm ci`, `HEALTHCHECK`) [10].

### 2. Comparación de plataformas con plan gratuito

| | **Render** | **Railway** | **Fly.io** |
|---|---|---|---|
| Plan gratuito | Web services gratis; 750 h de instancia/mes por workspace [1][2] | Trial de 30 días con USD 5 de crédito; la página oficial también lista un plan Free de USD 1/mes de uso (1 vCPU / 0,5 GB). Hobby: USD 5/mes [3] | Hasta nov. 2026: sin plan gratuito para organizaciones nuevas (trial corto). El 23/11/2026 se reportó un nuevo plan Free (USD 5 de uso mensual al registrar tarjeta); **confirmar en la documentación oficial** [4] |
| ¿Duerme? | Sí, tras 15 min sin tráfico; tarda ~1 min en despertar [1][2] | No duerme mientras haya crédito | Máquinas pueden auto-detenerse/arrancar (configurable) |
| Base de datos | Postgres gratis que **expira a los 30 días** (+14 de gracia) [1][2] | Postgres como servicio, consume crédito | Postgres gestionado de pago; o externo |
| HTTPS automático | Sí (certificados gestionados, también dominios propios) | Sí | Sí |
| Docker | Sí | Sí | Sí (modelo nativo) |
| Regiones | Oregón, Ohio, Virginia, Frankfurt, Singapur | Varias (EE. UU., Europa, Asia) | Más de 30 regiones |
| Secretos | Panel de variables de entorno / *environment groups* | Variables por servicio | `fly secrets set` |

**Elección:** Render. Es el único de los tres con servicio web gratuito sin crédito que se agote, tiene HTTPS automático, *health checks*, reinicio automático, Blueprint (`render.yaml`) como infraestructura en código, y `autoDeployTrigger: checksPass` para desplegar solo cuando el CI pasa. Su principal desventaja (duerme y la BD caduca) se resuelve con Neon y se documenta como riesgo residual.

### 3. Variables de entorno y secretos

La configuración que cambia entre entornos se lee de variables de entorno (factor III de *The Twelve-Factor App*) [13]. Un **gestor de secretos** (panel de Render, AWS Secrets Manager, HashiCorp Vault, GitHub Secrets) guarda los valores cifrados, controla quién los ve, registra accesos y permite rotarlos sin tocar el código [8]. Un `.env` no basta en producción: es un archivo en texto plano en el disco del servidor, se copia por error a imágenes o repositorios, no tiene control de acceso ni auditoría, y rotarlo exige entrar al servidor. En SecureVault, `.env` existe solo en desarrollo (en `.gitignore` y `.dockerignore`), los secretos de producción viven en Render (`sync: false` en `render.yaml`) y la app valida al arrancar que existan y tengan el formato correcto.

### 4. TLS, Let's Encrypt y HSTS

**TLS** cifra y autentica la conexión: el servidor presenta un certificado X.509 firmado por una autoridad (CA) que el navegador valida para el dominio; luego negocian llaves de sesión. **Let's Encrypt** es una CA gratuita y automatizada que emite certificados de 90 días mediante el protocolo ACME: el cliente (Certbot, Caddy o la propia plataforma) demuestra control del dominio con un reto HTTP-01 (archivo en `/.well-known/acme-challenge/`) o DNS-01 (registro TXT), y renueva automáticamente [6]. **HSTS** (`Strict-Transport-Security`) indica al navegador que durante `max-age` solo use HTTPS para ese dominio, lo que evita ataques de *downgrade*/SSL stripping tras la primera visita [7]. SecureVault envía `max-age=31536000; includeSubDomains` y redirige HTTP→HTTPS.

### 5. Proxy inverso y `trust proxy`

Un proxy inverso (Nginx, Caddy) recibe las conexiones públicas y las reenvía a Node.js: termina TLS, sirve estáticos, comprime, limita tamaño de peticiones y tasas, y oculta el puerto interno. En un PaaS, el balanceador de la plataforma cumple ese papel. Como Node ve la conexión del proxy y no la del cliente, el proxy envía `X-Forwarded-For` y `X-Forwarded-Proto`. `app.set('trust proxy', 1)` le dice a Express que confíe en **un** salto: así `req.ip` es la IP real (necesaria para el rate limiting) y `req.secure` es verdadero cuando el cliente usó HTTPS (necesario para emitir cookies `Secure`). Configurarlo en `true` sin más permitiría a un atacante falsificar `X-Forwarded-For` y evadir el rate limit [9].

### 6. Gestores de procesos

PM2 o systemd mantienen vivo el proceso en un VPS: lo reinician si se cae, lo arrancan al iniciar la máquina, gestionan logs y (PM2) modo clúster [12]. Dejan de ser necesarios cuando la plataforma ya supervisa el proceso: en contenedores (Docker `restart: always`, Kubernetes) y en PaaS, que reinician el contenedor si el proceso termina o el *health check* falla. Usar PM2 dentro de un contenedor duplica la supervisión y oculta caídas a la plataforma. SecureVault ejecuta `node src/server.js` como PID 1, sale ante errores no controlados y deja que Render lo reinicie.

### 7. CI/CD con GitHub Actions

**CI** (integración continua) ejecuta automáticamente pruebas y controles en cada push/PR; **CD** (despliegue continuo) publica a producción cuando esos controles pasan [11]. Pipeline mínimo de SecureVault (`.github/workflows/ci.yml`):

1. `gitleaks` sobre todo el historial (secretos filtrados).
2. `npm ci` (instala exactamente el `package-lock.json`).
3. `npm audit --audit-level=high` (falla con vulnerabilidades altas/críticas).
4. `npm test` contra un PostgreSQL de servicio.
5. `docker build`.
6. Despliegue: Render despliega `main` solo si los checks están en verde (`autoDeployTrigger: checksPass`). Alternativa: un paso final que llame al *deploy hook* de Render guardado en GitHub Secrets.

### 8. Bases de datos gestionadas y conexión segura

| | Neon (Postgres) | Supabase (Postgres) | MongoDB Atlas |
|---|---|---|---|
| Plan gratuito | 100 CU-h/mes y 1 GB por proyecto, escala a cero tras 5 min [5] | 2 proyectos, se pausan tras inactividad | Cluster M0 de 512 MB |
| TLS | Obligatorio | Disponible | Obligatorio |
| Restricción por IP | Planes de pago | Sí | Lista de acceso IP obligatoria |

Buenas prácticas: TLS con verificación del certificado (`sslmode=verify-full` o `rejectUnauthorized: true`), lista de IPs permitidas cuando el proveedor lo ofrece, un usuario de BD propio para la app con **mínimo privilegio** (solo DML sobre sus tablas, no superusuario), contraseñas largas generadas y guardadas en el gestor de secretos, y copias de seguridad/PITR activadas [8].

### 9. Desarrollo vs. producción

| Aspecto | Desarrollo | Producción |
|---|---|---|
| `NODE_ENV` | `development` | `production` (Express cachea vistas y oculta detalles de error) [9] |
| Logs | Legibles, nivel `debug` | JSON estructurado, nivel `info`, sin datos sensibles, enviados a la plataforma |
| Errores | Stack trace útil | Mensaje genérico + ID de correlación; stack solo en el log |
| CORS | Puede abrirse a `localhost` | Restringido al dominio propio (o sin CORS si es mismo origen) |
| Cookies | `Secure` desactivado (HTTP local) | `Secure`, `HttpOnly`, `SameSite`, `trust proxy` configurado |
| Secretos | `.env` local | Gestor de secretos |
| BD | Local sin TLS | Gestionada con TLS |

### 10. Verificaciones después del despliegue

- Cabeceras: **securityheaders.com** y **Mozilla Observatory**.
- TLS: **Qualys SSL Labs** (versión de TLS, cifrados, cadena de certificados, HSTS).
- Escaneo dinámico: **OWASP ZAP baseline** (`zap-baseline.py`) contra la URL propia [14].
- Dependencias: `npm audit`, Dependabot, escaneo de la imagen (`docker scout` / Trivy).
- Pruebas manuales: IDOR con dos cuentas, `' OR 1=1 --`, `<script>`, fuerza bruta (429), redirección HTTP→HTTPS, banderas de cookies, `/health` sin versiones.
- Revisar que los logs no contengan contraseñas/tokens y que las alertas lleguen.

## Plan de despliegue de SecureVault

```
Usuario ──HTTPS──▶ Render (TLS + balanceador, X-Forwarded-*)
                      │
                      ▼
              Contenedor Docker (node:26-alpine, usuario "node")
              trust proxy=1 + IP real desde CF-Connecting-IP · helmet · rate limit · sesiones
                      │ TLS verificado
                      ▼
              Neon PostgreSQL (usuario de la app con mínimo privilegio)

GitHub ──push main──▶ Actions: gitleaks → npm ci → npm audit → tests → docker build
                                        │ checks en verde
                                        ▼
                                Render despliega (autoDeployTrigger: checksPass)
```

- **Plataforma:** Render, web service Docker, región Oregón (o Frankfurt), *health check* `/health`.
- **Secretos:** `SESSION_SECRET`, `DATA_ENCRYPTION_KEY`, `AUDIT_HMAC_KEY`, `DATABASE_URL`, `SMTP_URL` en el panel de Render; generados con `npm run gen-keys`; copia de la llave de cifrado en un gestor de contraseñas del equipo.
- **Base de datos:** Neon, cadena con `sslmode=require` y `DATABASE_SSL=true` (verificación de certificado en el cliente).
- **Pipeline:** `.github/workflows/ci.yml` + Dependabot + `render.yaml`.
- **Reinicio:** Render reinicia el contenedor si el proceso termina o `/health` falla.

## Referencias

1. Render — *Deploy for Free* (límites del plan gratuito). https://render.com/docs/free — complementado con: J. McKelvey, *Is Render Free? Free Tier Limits, Sleep, and the 30-Day DB (2026)*. https://justinmckelvey.com/blog/is-render-free
2. Kuberns — *Render Pricing Guide: Free Tier, Compute and Database Costs* (2026). https://kuberns.com/blogs/render-pricing/
3. Railway — *Pricing Plans* (documentación oficial). https://docs.railway.com/pricing/plans y https://railway.com/pricing
4. Fly.io — *Resource Pricing* (documentación oficial). https://fly.io/docs/about/pricing/ — estado del nuevo plan gratuito reportado en: https://agentdeals.dev/vendor/fly-io y https://convika.com/compare/fly-io-free-tier/
5. Neon — *What are the limits and quotas for Neon's Free plan?* (actualizado 03/11/2026). https://neon.com/faqs/free-plan-limits-and-quotas
6. Let's Encrypt — *How It Works*. https://letsencrypt.org/how-it-works/
7. MDN Web Docs — *Strict-Transport-Security*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
8. OWASP Cheat Sheet Series — *Secrets Management* y *Database Security*. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
9. Express — *Production Best Practices: Security* y *Express behind proxies*. https://expressjs.com/en/advanced/best-practice-security.html · https://expressjs.com/en/guide/behind-proxies.html
10. OWASP Cheat Sheet Series — *NodeJS Docker* y *Node.js Security*. https://cheatsheetseries.owasp.org/cheatsheets/NodeJS_Docker_Cheat_Sheet.html
11. GitHub Docs — *Building and testing Node.js*. https://docs.github.com/en/actions/use-cases-and-examples/building-and-testing/building-and-testing-nodejs
12. PM2 — *Quick Start*. https://pm2.keymetrics.io/docs/usage/quick-start/
13. *The Twelve-Factor App — III. Config*. https://12factor.net/config
14. OWASP ZAP — *ZAP Baseline Scan*. https://www.zaproxy.org/docs/docker/baseline-scan/
15. OWASP — *OWASP Top 10:2025*. https://owasp.org/Top10/2025/
