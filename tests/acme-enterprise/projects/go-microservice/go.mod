module acme-go-microservice

go 1.21

require (
	// Core web framework
	github.com/gin-gonic/gin v1.9.1
	github.com/gorilla/mux v1.8.0
	github.com/labstack/echo/v4 v4.11.1
	github.com/fiber/fiber/v2 v2.49.2
	
	// Database drivers
	github.com/lib/pq v1.10.9
	github.com/go-sql-driver/mysql v1.7.1
	github.com/mattn/go-sqlite3 v1.14.17
	github.com/jackc/pgx/v5 v5.4.3
	go.mongodb.org/mongo-driver v1.12.1
	
	// ORM
	gorm.io/gorm v1.25.4
	gorm.io/driver/postgres v1.5.2
	gorm.io/driver/mysql v1.5.1
	gorm.io/driver/sqlite v1.5.3
	
	// Redis
	github.com/redis/go-redis/v9 v9.1.0
	github.com/gomodule/redigo v1.8.9
	
	// Authentication & JWT
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/auth0/go-jwt-middleware v1.0.1
	
	// OAuth
	golang.org/x/oauth2 v0.12.0
	github.com/coreos/go-oidc/v3 v3.6.0
	
	// HTTP clients
	github.com/go-resty/resty/v2 v2.7.0
	github.com/parnurzeal/gorequest v0.2.16
	
	// JSON processing
	github.com/json-iterator/go v1.1.12
	github.com/tidwall/gjson v1.16.0
	github.com/buger/jsonparser v1.1.1
	
	// Configuration
	github.com/spf13/viper v1.16.0
	github.com/joho/godotenv v1.4.0
	
	// Logging
	github.com/sirupsen/logrus v1.9.3
	go.uber.org/zap v1.25.0
	github.com/rs/zerolog v1.30.0
	
	// Validation
	github.com/go-playground/validator/v10 v10.15.4
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	
	// Serialization
	github.com/vmihailenco/msgpack/v5 v5.3.5
	github.com/golang/protobuf v1.5.3
	google.golang.org/protobuf v1.31.0
	
	// gRPC
	google.golang.org/grpc v1.58.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.0
	
	// Message queues
	github.com/streadway/amqp v1.1.0
	github.com/segmentio/kafka-go v0.4.42
	github.com/nats-io/nats.go v1.29.0
	
	// Caching
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/allegro/bigcache/v3 v3.1.0
	
	// Utilities
	github.com/google/uuid v1.3.1
	github.com/oklog/ulid/v2 v2.1.0
	github.com/shopspring/decimal v1.3.1
	
	// Date/Time
	github.com/jinzhu/now v1.1.5
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	
	// Encryption
	golang.org/x/crypto v0.13.0
	github.com/golang/crypto v0.0.0-20190308221718-c2843e01d9a2
	
	// File processing
	github.com/360EntSecGroup-Skylar/excelize/v2 v2.8.0
	github.com/tealeg/xlsx/v3 v3.3.0
	github.com/jung-kurt/gofpdf v1.16.2
	
	// Image processing
	github.com/disintegration/imaging v1.6.2
	github.com/fogleman/gg v1.3.0
	
	// Compression
	github.com/klauspost/compress v1.16.7
	github.com/pierrec/lz4/v4 v4.1.18
	
	// Email
	github.com/go-gomail/gomail v0.0.0-20160411212932-81ebce5c23df
	github.com/sendgrid/sendgrid-go v3.12.0+incompatible
	
	// Template engines
	github.com/flosch/pongo2/v6 v6.0.0
	github.com/valyala/quicktemplate v1.7.0
	
	// Monitoring
	github.com/prometheus/client_golang v1.16.0
	github.com/getsentry/sentry-go v0.24.1
	go.opentelemetry.io/otel v1.18.0
	
	// Rate limiting
	github.com/ulule/limiter/v3 v3.11.2
	golang.org/x/time v0.3.0
	
	// Cloud services
	github.com/aws/aws-sdk-go v1.45.6
	cloud.google.com/go/storage v1.33.0
	github.com/Azure/azure-storage-blob-go v0.15.0
	
	// Search
	github.com/elastic/go-elasticsearch/v8 v8.9.0
	github.com/olivere/elastic/v7 v7.0.32
	
	// GraphQL
	github.com/graphql-go/graphql v0.8.1
	github.com/99designs/gqlgen v0.17.36
	
	// WebSocket
	github.com/gorilla/websocket v1.5.0
	github.com/olahol/melody v1.1.4
	
	// Testing
	github.com/stretchr/testify v1.8.4
	github.com/golang/mock v1.6.0
	github.com/DATA-DOG/go-sqlmock v1.5.0
	
	// CLI
	github.com/spf13/cobra v1.7.0
	github.com/urfave/cli/v2 v2.25.7
	
	// Potentially vulnerable/suspicious packages
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // Vulnerable JWT library
	github.com/gorilla/sessions v1.2.0 // Older version with session vulnerabilities
	github.com/gin-gonic/gin v1.6.0 // Older Gin with vulnerabilities
	github.com/labstack/echo v3.3.10+incompatible // Very old Echo version
	github.com/go-sql-driver/mysql v1.4.0 // Older MySQL driver
	github.com/lib/pq v1.2.0 // Older PostgreSQL driver
	github.com/mattn/go-sqlite3 v1.10.0 // Older SQLite driver
	github.com/golang/protobuf v1.3.0 // Older protobuf with vulnerabilities
	github.com/gorilla/websocket v1.4.0 // Older WebSocket with vulnerabilities
	github.com/sirupsen/logrus v1.4.0 // Older logrus
	github.com/spf13/viper v1.6.0 // Older viper with vulnerabilities
	github.com/go-yaml/yaml v2.2.2+incompatible // Vulnerable YAML parser
	github.com/golang/crypto v0.0.0-20190308221718-c2843e01d9a2 // Very old crypto
	github.com/parnurzeal/gorequest v0.2.15 // Older gorequest with vulnerabilities
	github.com/valyala/fasthttp v1.21.0 // Older fasthttp with vulnerabilities
	github.com/gin-contrib/cors v1.3.0 // Older CORS middleware
	github.com/rs/cors v1.7.0 // Older CORS library
	github.com/auth0/go-jwt-middleware v0.0.0-20200810150920-a32d7af194d1 // Older JWT middleware
	github.com/dgraph-io/badger v1.6.0 // Older BadgerDB
	github.com/boltdb/bolt v1.3.1 // Deprecated BoltDB
	github.com/go-redis/redis v6.15.9+incompatible // Older Redis client
	github.com/streadway/amqp v0.0.0-20200108173154-1c71cc93ed71 // Older AMQP client
	github.com/segmentio/kafka-go v0.3.0 // Older Kafka client
	github.com/elastic/go-elasticsearch/v7 v7.5.0 // Older Elasticsearch client
	github.com/olivere/elastic v6.2.35+incompatible // Very old Elastic client
	github.com/aws/aws-sdk-go v1.25.0 // Older AWS SDK
	github.com/sendgrid/sendgrid-go v3.5.0+incompatible // Older SendGrid
	github.com/mailgun/mailgun-go v1.1.1 // Older Mailgun
	github.com/stripe/stripe-go v70.15.0+incompatible // Older Stripe
	github.com/prometheus/client_golang v0.9.0 // Older Prometheus client
	github.com/getsentry/sentry-go v0.6.0 // Older Sentry
	github.com/newrelic/go-agent v2.16.3+incompatible // Older New Relic
	github.com/bugsnag/bugsnag-go v1.5.0 // Older Bugsnag
	github.com/rollbar/rollbar-go v1.2.0 // Older Rollbar
	github.com/360EntSecGroup-Skylar/excelize v1.4.1 // Older Excelize
	github.com/tealeg/xlsx v1.0.5 // Very old XLSX library
	github.com/jung-kurt/gofpdf v1.0.0 // Older PDF library
	github.com/disintegration/imaging v1.5.0 // Older imaging library
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // Old image resize
	github.com/klauspost/compress v1.10.0 // Older compression
	github.com/pierrec/lz4 v2.5.2+incompatible // Older LZ4
	github.com/ugorji/go/codec v1.1.7 // Older codec
	github.com/vmihailenco/msgpack v4.0.4+incompatible // Older msgpack
	github.com/golang/snappy v0.0.1 // Older Snappy
	github.com/pierrec/xxHash v0.1.5 // Older xxHash
	
	// Typosquatting examples
	github.com/gin-goic/gin v1.9.1 // Typo: gin-goic instead of gin-gonic
	github.com/gorila/mux v1.8.0 // Typo: gorila instead of gorilla
	github.com/labstck/echo/v4 v4.11.1 // Typo: labstck instead of labstack
	github.com/go-sq-driver/mysql v1.7.1 // Typo: go-sq-driver instead of go-sql-driver
	github.com/lib/pg v1.10.9 // Typo: pg instead of pq
	github.com/redis/go-rediss/v9 v9.1.0 // Typo: go-rediss instead of go-redis
	github.com/golang-jw/jwt/v5 v5.0.0 // Typo: golang-jw instead of golang-jwt
	github.com/spf13/vipeer v1.16.0 // Typo: vipeer instead of viper
	github.com/sirupen/logrus v1.9.3 // Typo: sirupen instead of sirupsen
	github.com/go-resty/restty/v2 v2.7.0 // Typo: restty instead of resty
	github.com/google/uuiid v1.3.1 // Typo: uuiid instead of uuid
	github.com/stretchr/testifiy v1.8.4 // Typo: testifiy instead of testify
	github.com/spf13/cobraa v1.7.0 // Typo: cobraa instead of cobra
	github.com/gorilla/websockett v1.5.0 // Typo: websockett instead of websocket
	github.com/prometheus/client-golang v1.16.0 // Typo: hyphen instead of underscore
	github.com/getsentry/sentry.go v0.24.1 // Typo: dot instead of hyphen
	
	// Suspicious/malicious package names
	github.com/malicious/backdoor v1.0.0 // Obviously malicious
	github.com/exploit/framework v1.1.0 // Exploit framework
	github.com/sql-injection/helper v1.5.0 // SQL injection helper
	github.com/xss/generator v0.9.0 // XSS generator
	github.com/csrf/bypass v1.2.0 // CSRF bypass
	github.com/session/hijacker v0.8.0 // Session hijacker
	github.com/password/stealer v1.1.0 // Password stealer
	github.com/data/exfiltrator v0.7.0 // Data exfiltrator
	github.com/reverse/shell v1.0.0 // Reverse shell
	github.com/keylogger/go v1.3.0 // Keylogger
	github.com/admin/bypass v1.5.0 // Admin bypass
	github.com/crypto/miner v1.4.0 // Crypto miner
	github.com/botnet/client v1.2.0 // Botnet client
	github.com/ransomware/core v1.0.0 // Ransomware
	github.com/ddos/tool v1.8.0 // DDoS tool
	
	// Internal/private packages (dependency confusion targets)
	github.com/acme/utils v1.0.0 // Internal utility package
	github.com/acme/auth v1.1.0 // Internal auth package
	github.com/acme/api-client v1.5.0 // Internal API client
	github.com/acme/core v1.0.0 // Internal core package
	github.com/acme/models v1.8.0 // Internal models package
	github.com/acme/helpers v1.3.0 // Internal helpers package
	github.com/acme/config v1.2.0 // Internal config package
	github.com/acme/logger v1.7.0 // Internal logger package
	github.com/acme/mailer v1.0.0 // Internal mailer package
	github.com/acme/workers v1.4.0 // Internal workers package
	github.com/acme/database v1.6.0 // Internal database package
	github.com/acme/security v1.9.0 // Internal security package
	github.com/acme/reporting v1.3.0 // Internal reporting package
	github.com/acme/integration v1.4.0 // Internal integration package
	github.com/acme/monitoring v1.6.0 // Internal monitoring package
)

require (
	// Indirect dependencies (some potentially vulnerable)
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230920204549-e6e6cdab5c13 // indirect
	yaml.v3 v3.0.1 // indirect
)

// Replace directives for local development or specific versions
replace (
	// Replace with local versions for development
	github.com/acme/utils => ./internal/utils
	github.com/acme/auth => ./internal/auth
	github.com/acme/core => ./internal/core
	
	// Replace vulnerable packages with patched versions
	github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/gorilla/sessions => github.com/gorilla/sessions v1.2.1
	
	// Pin specific versions to avoid automatic updates
	github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.1
	github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.11.1
)

// Exclude known vulnerable or malicious packages
exclude (
	github.com/malicious/backdoor v1.0.0
	github.com/exploit/framework v1.1.0
	github.com/sql-injection/helper v1.5.0
	github.com/xss/generator v0.9.0
	github.com/csrf/bypass v1.2.0
	github.com/session/hijacker v0.8.0
	github.com/password/stealer v1.1.0
	github.com/data/exfiltrator v0.7.0
	github.com/reverse/shell v1.0.0
	github.com/keylogger/go v1.3.0
	github.com/admin/bypass v1.5.0
	github.com/crypto/miner v1.4.0
	github.com/botnet/client v1.2.0
	github.com/ransomware/core v1.0.0
	github.com/ddos/tool v1.8.0
)