package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// DockerSetup handles one-click Docker setup for TypoSentinel
type DockerSetup struct {
	projectPath string
	verbose     bool
	output      io.Writer
}

// SetupOptions configures the Docker setup process
type SetupOptions struct {
	ProjectPath string
	Verbose     bool
	Output      io.Writer
}

// SetupResult contains the result of the Docker setup
type SetupResult struct {
	Success       bool
	ContainerID   string
	ImageName     string
	Port          int
	WebURL        string
	ConfigPath    string
	LogsPath      string
	ErrorMessage  string
	SetupDuration time.Duration
}

// NewDockerSetup creates a new Docker setup instance
func NewDockerSetup(opts SetupOptions) *DockerSetup {
	if opts.Output == nil {
		opts.Output = os.Stdout
	}
	if opts.ProjectPath == "" {
		opts.ProjectPath = "."
	}

	return &DockerSetup{
		projectPath: opts.ProjectPath,
		verbose:     opts.Verbose,
		output:      opts.Output,
	}
}

// QuickSetup performs a one-click Docker setup
func (d *DockerSetup) QuickSetup(ctx context.Context) (*SetupResult, error) {
	startTime := time.Now()
	result := &SetupResult{
		Port: 8080,
	}

	d.printStep("🐳 Starting TypoSentinel Docker Quick Setup...")

	// Check Docker availability
	if err := d.checkDockerAvailable(); err != nil {
		result.ErrorMessage = fmt.Sprintf("Docker not available: %v", err)
		return result, err
	}
	d.printSuccess("✅ Docker is available")

	// Generate Dockerfile if not exists
	if err := d.generateDockerfile(); err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to generate Dockerfile: %v", err)
		return result, err
	}
	d.printSuccess("✅ Dockerfile generated")

	// Generate docker-compose.yml
	if err := d.generateDockerCompose(); err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to generate docker-compose.yml: %v", err)
		return result, err
	}
	d.printSuccess("✅ Docker Compose configuration generated")

	// Build Docker image
	imageName := "typosentinel:latest"
	if err := d.buildImage(ctx, imageName); err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to build Docker image: %v", err)
		return result, err
	}
	result.ImageName = imageName
	d.printSuccess("✅ Docker image built successfully")

	// Start container
	containerID, err := d.startContainer(ctx, imageName)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to start container: %v", err)
		return result, err
	}
	result.ContainerID = containerID
	d.printSuccess("✅ Container started successfully")

	// Wait for service to be ready
	if err := d.waitForService(ctx, result.Port); err != nil {
		result.ErrorMessage = fmt.Sprintf("Service failed to start: %v", err)
		return result, err
	}

	result.Success = true
	result.WebURL = fmt.Sprintf("http://localhost:%d", result.Port)
	result.ConfigPath = filepath.Join(d.projectPath, "config")
	result.LogsPath = filepath.Join(d.projectPath, "logs")
	result.SetupDuration = time.Since(startTime)

	d.printSetupComplete(result)
	return result, nil
}

// checkDockerAvailable checks if Docker is installed and running
func (d *DockerSetup) checkDockerAvailable() error {
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Docker is not installed or not running. Please install Docker Desktop")
	}
	return nil
}

// generateDockerfile creates an optimized Dockerfile for TypoSentinel
func (d *DockerSetup) generateDockerfile() error {
	dockerfilePath := filepath.Join(d.projectPath, "Dockerfile")
	
	// Check if Dockerfile already exists
	if _, err := os.Stat(dockerfilePath); err == nil {
		d.printInfo("ℹ️  Dockerfile already exists, skipping generation")
		return nil
	}

	dockerfile := `# TypoSentinel Docker Image
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
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o typosentinel ./cmd/typosentinel

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates git

# Create non-root user
RUN addgroup -g 1001 -S typosentinel && \
    adduser -u 1001 -S typosentinel -G typosentinel

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/typosentinel .

# Copy configuration templates
COPY --from=builder /app/configs ./configs

# Create directories for data and logs
RUN mkdir -p /app/data /app/logs /app/config && \
    chown -R typosentinel:typosentinel /app

# Switch to non-root user
USER typosentinel

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ./typosentinel health || exit 1

# Default command
CMD ["./typosentinel", "serve", "--config", "/app/config/config.yaml"]
`

	return os.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
}

// generateDockerCompose creates a docker-compose.yml for easy setup
func (d *DockerSetup) generateDockerCompose() error {
	composePath := filepath.Join(d.projectPath, "docker-compose.yml")
	
	// Check if docker-compose.yml already exists
	if _, err := os.Stat(composePath); err == nil {
		d.printInfo("ℹ️  docker-compose.yml already exists, skipping generation")
		return nil
	}

	compose := `version: '3.8'

services:
  typosentinel:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - TYPOSENTINEL_ENV=production
      - TYPOSENTINEL_LOG_LEVEL=info
      - TYPOSENTINEL_WEB_ENABLED=true
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "./typosentinel", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Redis for caching (uncomment if needed)
  # redis:
  #   image: redis:7-alpine
  #   ports:
  #     - "6379:6379"
  #   volumes:
  #     - redis_data:/data
  #   restart: unless-stopped

  # Optional: PostgreSQL for advanced features (uncomment if needed)
  # postgres:
  #   image: postgres:15-alpine
  #   environment:
  #     POSTGRES_DB: typosentinel
  #     POSTGRES_USER: typosentinel
  #     POSTGRES_PASSWORD: changeme
  #   ports:
  #     - "5432:5432"
  #   volumes:
  #     - postgres_data:/var/lib/postgresql/data
  #   restart: unless-stopped

volumes:
  # redis_data:
  # postgres_data:
  config_data:
  app_data:
  logs_data:
`

	return os.WriteFile(composePath, []byte(compose), 0644)
}

// buildImage builds the Docker image
func (d *DockerSetup) buildImage(ctx context.Context, imageName string) error {
	d.printStep("🔨 Building Docker image...")
	
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, d.projectPath)
	
	if d.verbose {
		cmd.Stdout = d.output
		cmd.Stderr = d.output
		return cmd.Run()
	}

	// Show progress for non-verbose mode
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Step") || strings.Contains(line, "Successfully") {
			d.printInfo(fmt.Sprintf("   %s", line))
		}
	}

	return cmd.Wait()
}

// startContainer starts the Docker container
func (d *DockerSetup) startContainer(ctx context.Context, imageName string) (string, error) {
	d.printStep("🚀 Starting container...")

	// Create necessary directories
	dirs := []string{"config", "data", "logs"}
	for _, dir := range dirs {
		dirPath := filepath.Join(d.projectPath, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"-p", "8080:8080",
		"-v", fmt.Sprintf("%s:/app/config", filepath.Join(d.projectPath, "config")),
		"-v", fmt.Sprintf("%s:/app/data", filepath.Join(d.projectPath, "data")),
		"-v", fmt.Sprintf("%s:/app/logs", filepath.Join(d.projectPath, "logs")),
		"--name", "typosentinel-quick",
		imageName)

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// waitForService waits for the service to be ready
func (d *DockerSetup) waitForService(ctx context.Context, port int) error {
	d.printStep("⏳ Waiting for service to be ready...")
	
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("service failed to start within 60 seconds")
		case <-ticker.C:
			cmd := exec.CommandContext(ctx, "docker", "logs", "typosentinel-quick")
			output, err := cmd.Output()
			if err == nil && strings.Contains(string(output), "Server started") {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Cleanup removes Docker resources
func (d *DockerSetup) Cleanup() error {
	d.printStep("🧹 Cleaning up Docker resources...")

	// Stop and remove container
	exec.Command("docker", "stop", "typosentinel-quick").Run()
	exec.Command("docker", "rm", "typosentinel-quick").Run()

	d.printSuccess("✅ Cleanup completed")
	return nil
}

// Helper methods for formatted output
func (d *DockerSetup) printStep(message string) {
	fmt.Fprintf(d.output, "%s %s\n", color.BlueString("▶"), message)
}

func (d *DockerSetup) printSuccess(message string) {
	fmt.Fprintf(d.output, "%s %s\n", color.GreenString("✓"), message)
}

func (d *DockerSetup) printInfo(message string) {
	fmt.Fprintf(d.output, "%s %s\n", color.CyanString("ℹ"), message)
}

func (d *DockerSetup) printError(message string) {
	fmt.Fprintf(d.output, "%s %s\n", color.RedString("✗"), message)
}

func (d *DockerSetup) printSetupComplete(result *SetupResult) {
	fmt.Fprintf(d.output, "\n%s\n", color.GreenString("🎉 TypoSentinel Docker Setup Complete!"))
	fmt.Fprintf(d.output, "\n%s\n", color.YellowString("📋 Setup Summary:"))
	fmt.Fprintf(d.output, "   🐳 Container ID: %s\n", result.ContainerID[:12])
	fmt.Fprintf(d.output, "   🖼️  Image: %s\n", result.ImageName)
	fmt.Fprintf(d.output, "   🌐 Web Interface: %s\n", color.CyanString(result.WebURL))
	fmt.Fprintf(d.output, "   📁 Config Directory: %s\n", result.ConfigPath)
	fmt.Fprintf(d.output, "   📝 Logs Directory: %s\n", result.LogsPath)
	fmt.Fprintf(d.output, "   ⏱️  Setup Duration: %v\n", result.SetupDuration.Round(time.Second))
	
	fmt.Fprintf(d.output, "\n%s\n", color.YellowString("🚀 Quick Commands:"))
	fmt.Fprintf(d.output, "   View logs:    docker logs typosentinel-quick\n")
	fmt.Fprintf(d.output, "   Stop service: docker stop typosentinel-quick\n")
	fmt.Fprintf(d.output, "   Start service: docker start typosentinel-quick\n")
	fmt.Fprintf(d.output, "   Remove setup: docker rm -f typosentinel-quick\n")
	
	fmt.Fprintf(d.output, "\n%s %s\n", 
		color.GreenString("✨"), 
		"Open your browser and navigate to the Web Interface URL above!")
}