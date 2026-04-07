FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --production

COPY . .

# Railway provides a volume mount at /data for persistence
ENV DB_PATH=/data/snippet-expander.db
ENV NODE_ENV=production

EXPOSE 3456

CMD ["node", "server.js"]
