package rest

import (
	"fmt"
	"github.com/Alivanroy/Typosentinel/internal/api/rest/handlers"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/gin-gonic/gin"
)

// SupplyChainAPI handles supply chain security endpoints
type SupplyChainAPI struct {
	handlers *handlers.SupplyChainHandlers
}

// NewSupplyChainAPI creates a new supply chain API handler
func NewSupplyChainAPI(scanner *scanner.Scanner, cfg *config.Config, logger *logger.Logger) *SupplyChainAPI {
	if scanner == nil {
		logger.Error("Scanner is nil in NewSupplyChainAPI")
		return nil
	}
	if cfg == nil {
		logger.Error("Config is nil in NewSupplyChainAPI")
		return nil
	}
	if logger == nil {
		fmt.Println("Logger is nil in NewSupplyChainAPI")
		return nil
	}

	handlers := handlers.NewSupplyChainHandlers(scanner, cfg, logger)
	if handlers == nil {
		logger.Error("Failed to create supply chain handlers")
		return nil
	}

	logger.Info("Supply chain API created successfully")
	return &SupplyChainAPI{
		handlers: handlers,
	}
}

// RegisterRoutes registers supply chain API routes
func (sc *SupplyChainAPI) RegisterRoutes(router *gin.RouterGroup) {
	v1 := router.Group("/supply-chain")

	// Enhanced supply chain scanning
	v1.POST("/scan", sc.handlers.HandleScan)

	// Get supply chain analysis results
	v1.GET("/analysis/:id", sc.handlers.HandleGetAnalysis)

	// Dependency graph analysis
	v1.POST("/graph/analyze", sc.handlers.HandleGraphAnalyze)

	// Dependency graph generation
	v1.POST("/graph/generate", sc.handlers.HandleGraphGenerate)

	// Dependency graph export
	v1.POST("/graph/export", sc.handlers.HandleGraphExport)

	// Dependency graph statistics
	v1.GET("/graph/stats", sc.handlers.HandleGraphStats)

	// Threat intelligence queries
	v1.GET("/threats/intel", sc.handlers.HandleThreatIntel)
}
