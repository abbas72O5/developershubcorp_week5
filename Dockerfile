# syntax=docker/dockerfile:1.7

FROM node:20-bookworm-slim AS base

ENV NODE_ENV=production
WORKDIR /app

# Install only production dependencies first for better layer caching.
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy application source after dependencies.
COPY server.js ./
COPY logger.js ./
COPY models ./models
COPY routes ./routes
COPY middleware ./middleware

# Drop privileges: run as the non-root node user.
USER node

EXPOSE 3000

CMD ["node", "server.js"]
