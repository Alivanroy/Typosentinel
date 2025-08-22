# Multi-stage build for Ruby on Rails application
FROM ruby:3.2.0-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    postgresql-dev \
    nodejs \
    npm \
    yarn \
    git \
    imagemagick-dev \
    libxml2-dev \
    libxslt-dev \
    tzdata

# Set working directory
WORKDIR /app

# Copy Gemfile and Gemfile.lock
COPY Gemfile Gemfile.lock ./

# Install gems
RUN bundle config set --local deployment 'true' && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4 --retry 3

# Copy package.json and yarn.lock if they exist
COPY package*.json yarn.lock* ./

# Install Node.js dependencies
RUN if [ -f "package.json" ]; then yarn install --frozen-lockfile --production; fi

# Copy application code
COPY . .

# Precompile assets
RUN RAILS_ENV=production \
    SECRET_KEY_BASE=dummy \
    bundle exec rails assets:precompile

# Production stage
FROM ruby:3.2.0-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache \
    postgresql-client \
    nodejs \
    imagemagick \
    libxml2 \
    libxslt \
    tzdata \
    curl \
    dumb-init && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy gems from builder
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Copy application code and precompiled assets
COPY --from=builder /app .

# Create necessary directories and set permissions
RUN mkdir -p /app/log /app/tmp/pids /app/tmp/cache /app/tmp/sockets /app/public/uploads && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Set environment variables
ENV RAILS_ENV=production \
    RAILS_SERVE_STATIC_FILES=true \
    RAILS_LOG_TO_STDOUT=true \
    BUNDLE_DEPLOYMENT=1 \
    BUNDLE_WITHOUT="development:test"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the Rails server
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "3000"]

# Labels for metadata
LABEL maintainer="ACME Enterprise <dev@acme.local>" \
      version="1.0.0" \
      description="ACME Enterprise Ruby on Rails Application" \
      org.opencontainers.image.title="ACME Ruby Rails App" \
      org.opencontainers.image.description="A vulnerable Ruby on Rails application for testing Typosentinel" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="ACME Enterprise" \
      org.opencontainers.image.licenses="MIT"