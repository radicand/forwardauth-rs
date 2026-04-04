FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

EXPOSE 4444

HEALTHCHECK --interval=2s --timeout=5s --start-period=10s --retries=30 \
  CMD wget -q -O /dev/null http://localhost:4444/.well-known/openid-configuration || exit 1

CMD ["node", "server.js"]
