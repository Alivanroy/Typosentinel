package connectors

import (
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestSlackConnector(t *testing.T) {
	config := map[string]interface{}{
		"webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
		"channel":     "#test",
		"username":    "Typosentinel",
	}

	log := logger.NewTestLogger()
	slack, err := NewSlackConnector("test-slack", config, *log)
	assert.NoError(t, err)
	assert.NotNil(t, slack)
	assert.Equal(t, "test-slack", slack.GetName())
	assert.Equal(t, "slack", slack.GetType())
}

func TestSplunkConnector(t *testing.T) {
	config := map[string]interface{}{
		"hec_url": "https://splunk.example.com:8088",
		"token":   "00000000-0000-0000-0000-000000000000",
		"index":   "main",
	}

	log := logger.NewTestLogger()
	splunk, err := NewSplunkConnector("test-splunk", config, *log)
	assert.NoError(t, err)
	assert.NotNil(t, splunk)
	assert.Equal(t, "test-splunk", splunk.GetName())
	assert.Equal(t, "splunk", splunk.GetType())
}

func TestWebhookConnector(t *testing.T) {
	config := map[string]interface{}{
		"url":    "https://webhook.example.com",
		"method": "POST",
	}

	log := logger.NewTestLogger()
	webhook, err := NewWebhookConnector("test-webhook", config, *log)
	assert.NoError(t, err)
	assert.NotNil(t, webhook)
	assert.Equal(t, "test-webhook", webhook.GetName())
	assert.Equal(t, "webhook", webhook.GetType())
}
