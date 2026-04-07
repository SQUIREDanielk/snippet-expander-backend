FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# Railway provides a volume mount at /data for persistence
ENV DB_PATH=/data/snippet-expander.db
ENV NODE_ENV=production

# Railway sets PORT dynamically — the server reads process.env.PORT
EXPOSE ${PORT:-3456}

CMD ["node", "server.js"]
