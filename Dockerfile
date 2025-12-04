FROM node:25-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
# COPY tsconfig.json ./
RUN npm install
RUN npm ci --omit=dev
# COPY --from=build /app/dist ./dist
EXPOSE 80
CMD ["node", "src/server.ts"]