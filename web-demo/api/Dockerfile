# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY server.go .

# Copy TypoSentinel source from parent directory
COPY ../../ /typosentinel-src

# Build TypoSentinel binary
WORKDIR /typosentinel-src
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/typosentinel .

# Build the API server
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o api-server server.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1001 -S apiuser && \
    adduser -u 1001 -S apiuser -G apiuser

# Set working directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/api-server .
COPY --from=builder /app/typosentinel .

# Copy TypoSentinel configuration files if they exist
COPY --from=builder /typosentinel-src/config* /app/

# TypoSentinel binary is now available for production scanning

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/config && \
    chown -R apiuser:apiuser /app

# Switch to non-root user
USER apiuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/health || exit 1

# Run the application
CMD ["./api-server"]