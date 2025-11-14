package rest

import (
    "github.com/Alivanroy/Typosentinel/internal/threat_intelligence"
    "github.com/gin-gonic/gin"
)

type ThreatIntelAPI struct {
    manager *threat_intelligence.ThreatIntelligenceManager
}

func NewThreatIntelAPI(m *threat_intelligence.ThreatIntelligenceManager) *ThreatIntelAPI {
    return &ThreatIntelAPI{manager: m}
}

func (s *Server) setupThreatIntelRoutes(v1 *gin.RouterGroup, api *ThreatIntelAPI) {
    g := v1.Group("/threat-intel")
    g.GET("/status", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
    g.GET("/feeds", func(c *gin.Context) { c.JSON(200, gin.H{"feeds": []string{"osv", "github_advisory", "nvd"}}) })
}

