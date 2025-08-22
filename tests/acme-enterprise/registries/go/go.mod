// ACME Enterprise Go modules registry test project for Typosentinel validation
module github.com/acme-enterprise/go-test-project

go 1.21

require (
	// Web framework
	github.com/gin-gonic/gin v1.9.1
	github.com/gorilla/mux v1.8.1
	github.com/labstack/echo/v4 v4.11.3
	
	// Database
	gorm.io/gorm v1.25.5
	gorm.io/driver/postgres v1.5.4
	github.com/go-redis/redis/v8 v8.11.5
	github.com/jmoiron/sqlx v1.3.5
	
	// HTTP client
	github.com/go-resty/resty/v2 v2.10.0
	github.com/valyala/fasthttp v1.51.0
	
	// JSON and serialization
	github.com/json-iterator/go v1.1.12
	github.com/goccy/go-json v0.10.2
	
	// Authentication and security
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	golang.org/x/crypto v0.16.0
	github.com/casbin/casbin/v2 v2.81.0
	
	// Configuration
	github.com/spf13/viper v1.17.0
	github.com/joho/godotenv v1.4.0
	
	// Logging
	github.com/sirupsen/logrus v1.9.3
	go.uber.org/zap v1.26.0
	github.com/rs/zerolog v1.31.0
	
	// Monitoring and metrics
	github.com/prometheus/client_golang v1.17.0
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
	go.opentelemetry.io/otel/metric v1.21.0
	
	// Utilities
	github.com/google/uuid v1.4.0
	github.com/shopspring/decimal v1.3.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
	
	// Validation
	github.com/go-playground/validator/v10 v10.16.0
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	
	// CLI
	github.com/spf13/cobra v1.8.0
	github.com/urfave/cli/v2 v2.25.7
	
	// Concurrency
	golang.org/x/sync v0.5.0
	github.com/panjf2000/ants/v2 v2.8.2
	
	// File handling
	github.com/spf13/afero v1.11.0
	gopkg.in/yaml.v3 v3.0.1
	
	// Time handling
	github.com/jinzhu/now v1.1.5
	
	// Caching
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/allegro/bigcache/v3 v3.1.0
	
	// Message queue
	github.com/streadway/amqp v1.1.0
	github.com/nats-io/nats.go v1.31.0
	
	// Template engine
	github.com/flosch/pongo2/v6 v6.0.0
	
	// Rate limiting
	golang.org/x/time v0.5.0
	github.com/ulule/limiter/v3 v3.11.2
	
	// Compression
	github.com/klauspost/compress v1.17.4
	
	// Email
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	
	// Image processing
	github.com/disintegration/imaging v1.6.2
	
	// PDF generation
	github.com/jung-kurt/gofpdf v1.16.2
	
	// Excel handling
	github.com/xuri/excelize/v2 v2.8.0
	
	// Encryption
	github.com/gtank/cryptopasta v0.0.0-20170601214702-1f550f6f2f69
)

require (
	// Testing
	github.com/golang/mock v1.6.0
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/testcontainers/testcontainers-go v0.26.0
	
	// Development tools
	github.com/air-verse/air v1.49.0
	github.com/cosmtrek/air v1.49.0
	
	// Code generation
	github.com/99designs/gqlgen v0.17.42
	github.com/swaggo/swag v1.16.2
	
	// Linting and formatting
	github.com/golangci/golangci-lint v1.55.2
	
	// Security scanning
	github.com/securecodewarrior/gosec/v2 v2.18.2
)

// Replace directives for local development
// replace github.com/acme-enterprise/internal-lib => ../internal-lib

// Exclude known vulnerable versions
exclude (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
)

// Retract vulnerable versions
retract (
	v1.0.0 // Contains security vulnerability
	v1.0.1 // Contains security vulnerability
)