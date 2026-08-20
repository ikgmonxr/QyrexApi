FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public/
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
USER root
CMD ["node", "server.js"]
