package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	// Suspicious imports that should be detected
	_ "github.com/gin-gonic/ginn"   // typosquatting
	_ "github.com/gorila/mux"       // typosquatting
	_ "github.com/sirupsenn/logrus" // typosquatting
)

func main() {
	fmt.Println("Test Go Project for TypoSentinel Analysis")

	// Initialize Gin router
	r := gin.Default()

	// Initialize Gorilla mux router
	muxRouter := mux.NewRouter()

	// Initialize logrus logger
	logger := logrus.New()
	logger.Info("Application started")

	// Simple test assertion
	assert.True(nil, true, "This should pass")

	// Setup routes
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from test Go project",
			"status":  "running",
		})
	})

	muxRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Health check passed")
	})

	fmt.Println("Server would start on :8080")
	fmt.Println("This is a test project - not actually starting server")
}
