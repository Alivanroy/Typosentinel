# Multi-stage build for ACME Security Dashboard
FROM node:18-alpine AS base

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata && \
    rm -rf /var/cache/apk/*

# Create app directory and user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S dashboard -u 1001 -G nodejs

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Development stage
FROM base AS development

# Install all dependencies including dev dependencies
RUN npm ci && npm cache clean --force

# Copy source code
COPY --chown=nodejs:nodejs . .

# Expose port
EXPOSE 4000

# Switch to non-root user
USER nodejs

# Start development server
CMD ["dumb-init", "npm", "run", "dev"]

# Production build stage
FROM base AS builder

# Install all dependencies for building
RUN npm ci && npm cache clean --force

# Copy source code
COPY --chown=nodejs:nodejs . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata && \
    rm -rf /var/cache/apk/*

# Create app directory and user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S dashboard -u 1001 -G nodejs

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && \
    npm cache clean --force && \
    rm package*.json

# Copy built application from builder stage
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/public ./public
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
COPY --from=builder --chown=nodejs:nodejs /app/server.js ./
COPY --from=builder --chown=nodejs:nodejs /app/config ./config

# Create logs directory
RUN mkdir -p logs && chown nodejs:nodejs logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

# Security: Remove unnecessary packages and files
RUN apk del curl && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Set environment variables
ENV NODE_ENV=production
ENV PORT=4000
ENV TZ=UTC

# Expose port
EXPOSE 4000

# Switch to non-root user
USER nodejs

# Start the application
CMD ["dumb-init", "node", "server.js"]

# Labels for metadata
LABEL maintainer="ACME Enterprise Security Team <security@acme.com>"
LABEL version="1.0.0"
LABEL description="ACME Security Dashboard for Typosentinel Monitoring"
LABEL org.opencontainers.image.title="ACME Security Dashboard"
LABEL org.opencontainers.image.description="Enterprise security dashboard for monitoring Typosentinel"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="ACME Enterprise"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/acme-enterprise/security-dashboard"
LABEL org.opencontainers.image.documentation="https://docs.acme.com/security-dashboard"