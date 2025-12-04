FROM node:25-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:25-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm install
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 80
CMD ["node", "dist/server.ts"]