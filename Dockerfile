# syntax=docker/dockerfile:1
# Imagen de producción: dependencias reproducibles (npm ci), sin herramientas de build
# en la imagen final y ejecución como usuario sin privilegios (bonificación).

FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts=false && npm cache clean --force

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
COPY --chown=node:node scripts ./scripts
# Usuario no root incluido en la imagen oficial de Node.
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-3000}/health || exit 1
# node directamente como PID 1 (no "npm start") para recibir SIGTERM y apagar limpio.
CMD ["node", "src/server.js"]
