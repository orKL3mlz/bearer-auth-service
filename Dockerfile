FROM node:25-alpine AS builder
WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm install

COPY src ./src
RUN npm run build


FROM node:25-alpine AS runner
WORKDIR /app

COPY package.json ./
COPY --from=builder /app/package-lock.json ./package-lock.json
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

HEALTHCHECK --interval=1m --timeout=30s --retries=3 --start-period=20s CMD curl --silent --fail http://localhost/health || exit 1
EXPOSE 80
CMD ["node", "dist/app.js"]