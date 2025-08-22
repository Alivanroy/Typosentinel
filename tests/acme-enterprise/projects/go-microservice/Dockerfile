# Multi-stage build for Go microservice
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main .

# Production stage
FROM scratch AS production

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder
COPY --from=builder /app/main /main

# Create a non-root user (using numeric IDs for scratch image)
USER 65534:65534

# Expose port
EXPOSE 8080

# Health check (using wget alternative for scratch)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["./main", "--health-check"]

# Set environment variables
ENV GIN_MODE=release \
    PORT=8080

# Run the application
ENTRYPOINT ["/main"]

# Alternative production stage with minimal Alpine base
FROM alpine:3.18 AS production-alpine

# Install runtime dependencies and create user
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/main .

# Create necessary directories
RUN mkdir -p /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV GIN_MODE=release \
    PORT=8080

# Run the application
CMD ["./main"]

# Labels for metadata
LABEL maintainer="ACME Enterprise <dev@acme.local>" \
      version="1.0.0" \
      description="ACME Enterprise Go Microservice" \
      org.opencontainers.image.title="ACME Go Microservice" \
      org.opencontainers.image.description="A vulnerable Go microservice for testing Typosentinel" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="ACME Enterprise" \
      org.opencontainers.image.licenses="MIT"