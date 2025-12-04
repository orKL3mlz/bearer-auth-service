# Bearer Auth Service (multi-tokens)

Minimalist **HTTP service in Node.js + Express** to **validate Bearer tokens**.  
It supports **multiple tokens** (allowlist), **constant-time comparison** (timing‑safe), **security headers** (Helmet), and **logging** (Morgan).

## ✨ Features

- ✅ **Multi-tokens** via the `BEARER_TOKENS` variable (comma-separated list)
- ✅ **Timing-safe comparison** (`crypto.timingSafeEqual`) and robust parsing of the `Authorization` header
- ✅ **Security**: headers via `helmet`, disable `x-powered-by`
- ✅ **HTTP logs** via `morgan`
- ✅ **Public/protected routes** (`/health`, `/auth-check`, `/v1/secure-data`)
- ✅ **Fail to start** if no token is provided (fail‑closed)

## 🧰 Requirements

- **Node.js 18+**
- **npm**

## 🚀 Installation

```bash
npm install
```

## ⚙️ Configuration

Environment variables:

- `BEARER_TOKENS` (**required**): list of allowed tokens, comma-separated.
- `PORT` (optional, default `80`): listening port.

> ⚠️ The service will refuse to start if `BEARER_TOKENS` is empty.

## 🛠️ Development

```bash
# Linux/macOS
export BEARER_TOKENS=tokA,tokB
npm run dev

# Windows PowerShell
$env:BEARER_TOKENS="tokA,tokB"
npm run dev
```

## Build & Prod

```bash
export BEARER_TOKENS=tokA,tokB
npm run build
npm start
```

## 📡 Endpoints

### `GET /health` (public)
- **200 OK**

### `GET /auth-check` (protected)
- **200 OK** if `Authorization: Bearer <token>` is valid
- **401 Unauthorized** otherwise

## 🔐 Authentication

Expected header: `Authorization: Bearer <token>`
- `Bearer` is case-insensitive
- Extra spaces are tolerated
- **Constant-time comparison**

## 🧪 Tests (cURL)

```bash
curl -i http://localhost:80/auth-check
curl -i -H "Authorization: Bearer wrong" http://localhost:80/auth-check
curl -i -H "Authorization: Bearer tokA" http://localhost:80/auth-check
```

## 🐳 Docker

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 80
CMD ["node", "dist/server.ts"]
```

### docker-compose.yml

```yaml
services:
  auth-service:
    build: .
    environment:
      - PORT=80
      - BEARER_TOKENS=tokA,tokB,tokC
    ports:
      - "80:80"
```

## Security

- Use **HTTPS** in production.
- No default values for secrets.
- Token rotation possible by deploying [old + new] then removing old ones.
