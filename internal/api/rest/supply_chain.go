package rest

import (
	"github.com/gin-gonic/gin"
	"github.com/Alivanroy/Typosentinel/internal/api/rest/handlers"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SupplyChainAPI handles supply chain security endpoints
type SupplyChainAPI struct {
	handlers *handlers.SupplyChainHandlers
}

// NewSupplyChainAPI creates a new supply chain API handler
func NewSupplyChainAPI(scanner *scanner.Scanner, cfg *config.Config, logger *logger.Logger) *SupplyChainAPI {
	return &SupplyChainAPI{
		handlers: handlers.NewSupplyChainHandlers(scanner, cfg, logger),
	}
}

// RegisterRoutes registers supply chain API routes
func (sc *SupplyChainAPI) RegisterRoutes(router *gin.RouterGroup) {
	v1 := router.Group("/v1/supply-chain")
	
	// Enhanced supply chain scanning
	v1.POST("/scan", sc.handlers.HandleScan)
	
	// Get supply chain analysis results
	v1.GET("/analysis/:id", sc.handlers.HandleGetAnalysis)
	
	// Dependency graph analysis
	v1.POST("/graph/analyze", sc.handlers.HandleGraphAnalyze)
	
	// Threat intelligence queries
	v1.GET("/threats/intel", sc.handlers.HandleThreatIntel)
}