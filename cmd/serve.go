package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

var (
	servePort     int
	serveHost     string
	serveWorkers  int
	serveTimeout  int
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Typosentinel API server",
	Long: `Start a REST API server for Typosentinel scanning services.

The serve command starts an HTTP server that provides REST API endpoints
for package scanning, batch operations, and system monitoring. This enables
programmatic access to Typosentinel functionality for integration with
other tools and services.

Example usage:
  typosentinel serve
  typosentinel serve --port 8080 --host 0.0.0.0
  typosentinel serve --workers 20 --timeout 60`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Server configuration flags
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&serveHost, "host", "localhost", "Host to bind to")
	serveCmd.Flags().IntVar(&serveWorkers, "workers", 10, "Number of worker goroutines")
	serveCmd.Flags().IntVar(&serveTimeout, "timeout", 30, "Request timeout in seconds")
}

func runServe(cmd *cobra.Command, args []string) error {
	logger.Info("Starting Typosentinel API server", map[string]interface{}{
		"host":    serveHost,
		"port":    servePort,
		"workers": serveWorkers,
		"timeout": serveTimeout,
	})

	// Load configuration
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Note: API config would need to be added to Config struct
	// Using command line flags for now
	apiHost := serveHost
	apiPort := servePort

	// Initialize ML pipeline
	mlPipeline := ml.NewMLPipeline(cfg)
	ctx := context.Background()
	if err := mlPipeline.Initialize(ctx); err != nil {
		logger.Error("Failed to initialize ML pipeline", map[string]interface{}{
			"error": err.Error(),
		})
		// Continue without ML pipeline for now
	}

	// Initialize analyzer
	analyzer, err := analyzer.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer: %w", err)
	}

	// Initialize REST API server
	// Create a default REST API config since regular Config doesn't have Integrations
	restConfig := &config.RESTAPIConfig{
		Enabled:  true,
		Host:     apiHost,
		Port:     apiPort,
		BasePath: "/api",
		Versioning: config.APIVersioning{
			Enabled:           true,
			Strategy:          "path",
			DefaultVersion:    "1",
			SupportedVersions: []string{"1"},
		},
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"*"},
		},
		RateLimiting: &config.APIRateLimiting{
			Enabled: false,
		},
		Authentication: &config.APIAuthentication{
			Enabled: false,
		},
		Documentation: config.APIDocumentation{
			Enabled: false,
		},
	}
	server := rest.NewServer(*restConfig, mlPipeline, analyzer)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", map[string]interface{}{
				"error": err.Error(),
			})
			cancel()
		}
	}()

	logger.Info("API server started successfully", map[string]interface{}{
		"address": fmt.Sprintf("http://%s:%d", apiHost, apiPort),
	})

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", map[string]interface{}{
			"signal": sig.String(),
		})
	case <-ctx.Done():
		logger.Info("Server context cancelled")
	}

	// Graceful shutdown
	logger.Info("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Stop(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	logger.Info("Server shutdown completed")
	return nil
}