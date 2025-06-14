package main

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/typosentinel/typosentinel/internal/analyzer"
	"github.com/typosentinel/typosentinel/internal/auth"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/pkg/api"
	"github.com/typosentinel/typosentinel/pkg/ml"
)

// Build information
var (
	version    = "dev"
	buildTime  = "unknown"
	commitHash = "unknown"
	configFile string
	debugMode  bool
	host       string
	port       int
	dbHost     string
	dbPort     int
	dbUser     string
	dbPassword string
	dbName     string
	mlURL      string
	mlAPIKey   string
	jwtSecret  string
)

var rootCmd = &cobra.Command{
	Use:   "typosentinel-server",
	Short: "TypoSentinel API Server",
	Long:  `TypoSentinel API Server provides REST API endpoints for package security analysis.`,
	Run:   runServer,
}

func main() {
	// Initialize configuration
	initConfig()

	// Add subcommands
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Initialize database
	dbConfig := database.Config{
		Host:     viper.GetString("database.host"),
		Port:     viper.GetInt("database.port"),
		User:     viper.GetString("database.user"),
		Password: viper.GetString("database.password"),
		DBName:   viper.GetString("database.name"),
		SSLMode:  viper.GetString("database.ssl_mode"),
	}
	db, err := database.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize services
	authConfig := auth.Config{
		JWTSecret:   viper.GetString("auth.jwt_secret"),
		AccessTTL:   time.Hour * 24,
		RefreshTTL:  time.Hour * 24 * 7,
		Issuer:      "typosentinel",
	}

	authService := auth.NewAuthService(authConfig)
	userService := auth.NewUserService(db.GetDB(), authService)
	orgService := auth.NewOrganizationService(db.GetDB())

	// Initialize analyzer with config
	analyzerConfig := &config.Config{
		Debug:   viper.GetBool("debug"),
		Verbose: viper.GetBool("verbose"),
	}
	analyzer := analyzer.New(analyzerConfig)

	// Initialize ML client
	mlClient := ml.NewClient(viper.GetString("ml.url"), viper.GetString("ml.api_key"))

	// Create API server
	server := api.NewServer(analyzer, db, mlClient, authService, userService, orgService)

	// Start server
	addr := fmt.Sprintf("%s:%d", viper.GetString("server.host"), viper.GetInt("server.port"))
	log.Printf("Starting server on %s", addr)
	if err := server.Start(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func initConfig() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.typosentinel.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "enable debug mode")

	// Server flags
	rootCmd.PersistentFlags().StringVar(&host, "host", "localhost", "server host")
	rootCmd.PersistentFlags().IntVar(&port, "port", 8080, "server port")

	// Database flags
	rootCmd.PersistentFlags().StringVar(&dbHost, "db-host", "localhost", "database host")
	rootCmd.PersistentFlags().IntVar(&dbPort, "db-port", 5432, "database port")
	rootCmd.PersistentFlags().StringVar(&dbUser, "db-user", "typosentinel", "database user")
	rootCmd.PersistentFlags().StringVar(&dbPassword, "db-password", "", "database password")
	rootCmd.PersistentFlags().StringVar(&dbName, "db-name", "typosentinel", "database name")

	// ML service flags
	rootCmd.PersistentFlags().StringVar(&mlURL, "ml-url", "http://localhost:8000", "ML service URL")
	rootCmd.PersistentFlags().StringVar(&mlAPIKey, "ml-api-key", "", "ML service API key")

	// JWT flags
	rootCmd.PersistentFlags().StringVar(&jwtSecret, "jwt-secret", "", "JWT secret key")

	// Bind flags to viper
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("server.host", rootCmd.PersistentFlags().Lookup("host"))
	viper.BindPFlag("server.port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("database.host", rootCmd.PersistentFlags().Lookup("db-host"))
	viper.BindPFlag("database.port", rootCmd.PersistentFlags().Lookup("db-port"))
	viper.BindPFlag("database.user", rootCmd.PersistentFlags().Lookup("db-user"))
	viper.BindPFlag("database.password", rootCmd.PersistentFlags().Lookup("db-password"))
	viper.BindPFlag("database.name", rootCmd.PersistentFlags().Lookup("db-name"))
	viper.BindPFlag("ml.url", rootCmd.PersistentFlags().Lookup("ml-url"))
	viper.BindPFlag("ml.api_key", rootCmd.PersistentFlags().Lookup("ml-api-key"))
	viper.BindPFlag("auth.jwt_secret", rootCmd.PersistentFlags().Lookup("jwt-secret"))

	// Set config file
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/typosentinel")
	}

	// Read environment variables
	viper.SetEnvPrefix("TYPOSENTINEL")
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
			log.Println("No config file found, using defaults and environment variables")
		} else {
			log.Printf("Error reading config file: %v", err)
		}
	} else {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("TypoSentinel Server %s\n", version)
			fmt.Printf("Build Time: %s\n", buildTime)
			fmt.Printf("Commit Hash: %s\n", commitHash)
		},
	}
}