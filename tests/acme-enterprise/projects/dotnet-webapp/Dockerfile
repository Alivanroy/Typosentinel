# Multi-stage build for .NET application
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS builder

# Set working directory
WORKDIR /app

# Copy project files
COPY *.csproj ./
COPY packages.config ./

# Restore dependencies
RUN dotnet restore

# Copy source code
COPY . .

# Build the application
RUN dotnet publish -c Release -o out --no-restore

# Production stage
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS production

# Install security updates and create app user
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        curl \
        dumb-init && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r appgroup && \
    useradd -r -g appgroup appuser

# Set working directory
WORKDIR /app

# Copy the built application from builder stage
COPY --from=builder /app/out .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://+:5000 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_USE_POLLING_FILE_WATCHER=true

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Run the application
CMD ["dotnet", "AcmeDotNetWebApp.dll"]

# Labels for metadata
LABEL maintainer="ACME Enterprise <dev@acme.local>" \
      version="1.0.0" \
      description="ACME Enterprise .NET Web Application" \
      org.opencontainers.image.title="ACME .NET Web App" \
      org.opencontainers.image.description="A vulnerable .NET application for testing Typosentinel" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="ACME Enterprise" \
      org.opencontainers.image.licenses="MIT"