# Multi-stage build for PlanFinale Production

# Stage 1: Build the Go application
FROM golang:1.23-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata curl

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations for production
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o planfinale .

# Stage 2: Final runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    && update-ca-certificates

# Create app user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy Go binary from builder
COPY --from=go-builder /app/planfinale ./

# Copy configuration files
COPY config/ ./config/
COPY dictionaries/ ./dictionaries/

# Create necessary directories
RUN mkdir -p /app/data /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command - start the server
CMD ["./planfinale", "server", "--port", "8080"]