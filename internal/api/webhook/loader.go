package webhook

import (
	"github.com/spf13/viper"
	"os"
)

func LoadProviderConfigStatus() map[string]bool {
	providers := []string{"github", "gitlab", "bitbucket", "azure"}
	status := make(map[string]bool)
	for _, p := range providers {
		var secret string
		// Try config
		secret = viper.GetString("webhooks.providers." + p + ".secret")
		if secret == "" {
			// Some providers use token naming
			secret = viper.GetString("webhooks.providers." + p + ".token")
		}
		if secret == "" {
			// Fallback to env
			switch p {
			case "github":
				secret = os.Getenv("GITHUB_WEBHOOK_SECRET")
			case "gitlab":
				secret = os.Getenv("GITLAB_WEBHOOK_TOKEN")
			case "bitbucket":
				secret = os.Getenv("BITBUCKET_WEBHOOK_SECRET")
			case "azure":
				secret = os.Getenv("AZURE_WEBHOOK_SECRET")
			}
		}
		status[p] = secret != ""
	}
	return status
}
