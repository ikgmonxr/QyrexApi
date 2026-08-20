FROM node:20-alpine

WORKDIR /app

# Install deps first (better cache)
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# App source
COPY server.js ./
COPY public ./public/

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

# Important for Fly: bind 0.0.0.0 (handled in server.js)
CMD ["node", "server.js"]
