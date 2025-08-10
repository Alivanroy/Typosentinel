package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Alivanroy/Typosentinel/internal/security"
)

func main() {
	fmt.Println("Typosentinel Security Configuration Checker")
	fmt.Println("==========================================")

	validator := security.NewSecureConfigValidator()

	// Check if this is a production environment
	environment := os.Getenv("TYPOSENTINEL_ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	fmt.Printf("Environment: %s\n\n", environment)

	// Validate production configuration
	if environment == "production" {
		fmt.Println("🔒 Validating production security configuration...")
		if err := validator.ValidateProductionConfig(); err != nil {
			fmt.Printf("❌ Security validation failed:\n%v\n\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Production security configuration is valid!\n")
	} else {
		fmt.Println("⚠️  Development environment detected - running basic checks...\n")
		
		// Basic checks for development
		jwtSecret := os.Getenv("TYPOSENTINEL_JWT_SECRET")
		if jwtSecret != "" {
			if err := validator.ValidateJWTSecret(jwtSecret); err != nil {
				fmt.Printf("⚠️  JWT Secret issue: %v\n", err)
			} else {
				fmt.Println("✅ JWT Secret is properly configured")
			}
		} else {
			fmt.Println("⚠️  JWT Secret not configured (will use development default)")
		}

		adminPassword := os.Getenv("TYPOSENTINEL_ADMIN_PASSWORD")
		if adminPassword != "" {
			if err := validator.ValidateAdminPassword(adminPassword); err != nil {
				fmt.Printf("⚠️  Admin Password issue: %v\n", err)
			} else {
				fmt.Println("✅ Admin Password is properly configured")
			}
		} else {
			fmt.Println("⚠️  Admin Password not configured")
		}
	}

	// Show security recommendations
	fmt.Println("📋 Security Recommendations:")
	fmt.Println("============================")
	recommendations := validator.GetSecurityRecommendations()
	for i, rec := range recommendations {
		fmt.Printf("%d. %s\n", i+1, rec)
	}

	// Generate sample secure configuration
	fmt.Println("\n🔧 Sample Secure Configuration:")
	fmt.Println("===============================")
	
	jwtSecret, err := validator.GenerateSecureSecret(32)
	if err != nil {
		log.Printf("Failed to generate JWT secret: %v", err)
	} else {
		fmt.Printf("export TYPOSENTINEL_JWT_SECRET=\"%s\"\n", jwtSecret)
	}

	encryptionKey, err := validator.GenerateSecureSecret(16) // 32 hex chars = 16 bytes
	if err != nil {
		log.Printf("Failed to generate encryption key: %v", err)
	} else {
		fmt.Printf("export TYPOSENTINEL_ENCRYPTION_KEY=\"%s\"\n", encryptionKey)
	}

	apiKey, err := validator.GenerateSecureSecret(16) // 32 hex chars
	if err != nil {
		log.Printf("Failed to generate API key: %v", err)
	} else {
		fmt.Printf("export TYPOSENTINEL_API_KEYS=\"%s\"\n", apiKey)
	}

	fmt.Println("export TYPOSENTINEL_ADMIN_PASSWORD=\"YourSecurePassword123!\"")
	fmt.Println("export TYPOSENTINEL_ENVIRONMENT=\"production\"")
	fmt.Println("export TYPOSENTINEL_ENABLE_TEST_TOKENS=\"false\"")
	fmt.Println("export TYPOSENTINEL_DISABLE_AUTH=\"false\"")

	fmt.Println("\n✅ Security check completed!")
}