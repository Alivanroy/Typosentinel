package webhook

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/Alivanroy/Typosentinel/pkg/logger"
    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// MockScanTrigger is a mock implementation of ScanTrigger
type MockScanTrigger struct {
	mock.Mock
}

func (m *MockScanTrigger) TriggerScan(ctx context.Context, request *ScanRequest) (*ScanResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ScanResponse), args.Error(1)
}

func (m *MockScanTrigger) GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	args := m.Called(ctx, scanID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ScanStatus), args.Error(1)
}

func TestNewWebhookHandler(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{
		Enabled:         true,
		Secret:          "test-secret",
		SignatureHeader: "X-Hub-Signature-256",
		Providers:       make(map[string]ProviderConfig),
		Timeout:         30 * time.Second,
		RateLimit: RateLimitConfig{
			Enabled:     true,
			MaxRequests: 100,
			Window:      time.Hour,
		},
	}

	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	assert.NotNil(t, handler)
	assert.Equal(t, testLogger, handler.logger)
	assert.Equal(t, mockScanTrigger, handler.scanTrigger)
	assert.Equal(t, config, handler.config)
}

func TestNewWebhookHandler_DefaultConfig(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	handler := NewWebhookHandler(testLogger, mockScanTrigger, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.config)
	assert.True(t, handler.config.Enabled)
	assert.Equal(t, "X-Hub-Signature-256", handler.config.SignatureHeader)
	assert.Equal(t, 30*time.Second, handler.config.Timeout)
}

func TestHandleGenericWebhook_DisabledService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/api/v1/webhooks/scan", bytes.NewBufferString("{}"))
	c.Request.Header.Set("Content-Type", "application/json")

	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{
		Enabled: false,
	}

	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleGenericWebhook(c)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Webhook service is disabled")
}

func TestHandleGenericWebhook_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/api/v1/webhooks/scan", bytes.NewBufferString("invalid json"))
	c.Request.Header.Set("Content-Type", "application/json")

	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{
		Enabled: true,
	}

	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleGenericWebhook(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Invalid payload")
}

func TestHandleGitHubWebhook_EventIgnored(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create mock GitHub payload
	payload := GitHubWebhookPayload{
		Ref: "refs/heads/main",
		Repository: struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
		}{
			Name:     "test-repo",
			FullName: "user/test-repo",
			CloneURL: "https://github.com/user/test-repo.git",
			HTMLURL:  "https://github.com/user/test-repo",
		},
	}

	body, _ := json.Marshal(payload)
	c.Request = httptest.NewRequest("POST", "/api/v1/webhooks/github", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("X-GitHub-Event", "issues") // Not in allowed events

	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{
		Enabled: true,
		Providers: map[string]ProviderConfig{
			"github": {
				Enabled: true,
				Events:  []string{"push"}, // Only allow push events
			},
		},
	}

	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleGitHubWebhook(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Event ignored", response["message"])
}

func TestShouldProcessEvent_AllEvents(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	// Should process all events when no allowed events specified
	result := handler.shouldProcessEvent("push", []string{})
	assert.True(t, result)

	result = handler.shouldProcessEvent("pull_request", []string{})
	assert.True(t, result)
}

func TestShouldProcessEvent_SpecificEvents(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	allowedEvents := []string{"push", "pull_request"}

	// Should process allowed events
	result := handler.shouldProcessEvent("push", allowedEvents)
	assert.True(t, result)

	result = handler.shouldProcessEvent("pull_request", allowedEvents)
	assert.True(t, result)

	// Should not process non-allowed events
	result = handler.shouldProcessEvent("issues", allowedEvents)
	assert.False(t, result)
}

func TestShouldProcessBranch_AllBranches(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	// Should process all branches when no allowed branches specified
	result := handler.shouldProcessBranch("main", []string{})
	assert.True(t, result)

	result = handler.shouldProcessBranch("develop", []string{})
	assert.True(t, result)
}

func TestShouldProcessBranch_SpecificBranches(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	allowedBranches := []string{"main", "master"}

	// Should process allowed branches
	result := handler.shouldProcessBranch("main", allowedBranches)
	assert.True(t, result)

	result = handler.shouldProcessBranch("master", allowedBranches)
	assert.True(t, result)

	// Should not process non-allowed branches
	result = handler.shouldProcessBranch("develop", allowedBranches)
	assert.False(t, result)
}

func TestShouldProcessPaths_AllPaths(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	changedPaths := []string{"src/main.js", "package.json", "README.md"}

	// Should process all paths when no watched paths specified
	result := handler.shouldProcessPaths(changedPaths, []string{})
	assert.True(t, result)
}

func TestShouldProcessPaths_SpecificPaths(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	changedPaths := []string{"src/main.js", "package.json", "README.md"}
	watchedPaths := []string{"package.json", "package-lock.json"}

	// Should process when matching paths exist
	result := handler.shouldProcessPaths(changedPaths, watchedPaths)
	assert.True(t, result)

	// Should not process when no matching paths
	changedPaths = []string{"src/main.js", "README.md"}
	result = handler.shouldProcessPaths(changedPaths, watchedPaths)
	assert.False(t, result)
}

func TestShouldProcessPaths_Wildcard(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	changedPaths := []string{"src/main.js", "package.json"}
	watchedPaths := []string{"*"}

	// Should process all paths with wildcard
	result := handler.shouldProcessPaths(changedPaths, watchedPaths)
	assert.True(t, result)
}

func TestExtractChangedPaths(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	commits := []struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	}{
		{
			ID:       "abc123",
			Message:  "Add new feature",
			Added:    []string{"src/new.js", "test/new.test.js"},
			Modified: []string{"package.json"},
			Removed:  []string{},
		},
		{
			ID:       "def456",
			Message:  "Fix bug",
			Added:    []string{},
			Modified: []string{"src/main.js"},
			Removed:  []string{"old.js"},
		},
	}

	paths := handler.extractChangedPaths(commits)

	// Should contain all unique paths
	assert.Contains(t, paths, "src/new.js")
	assert.Contains(t, paths, "test/new.test.js")
	assert.Contains(t, paths, "package.json")
	assert.Contains(t, paths, "src/main.js")
	assert.Contains(t, paths, "old.js")

	// Should not contain duplicates
	assert.Equal(t, 5, len(paths))
}

func TestHandleScanStatus_MissingScanID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// No scan ID parameter
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleScanStatus(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Scan ID is required")
}

func TestHandleCancelScan(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Set scan ID parameter
	c.Params = []gin.Param{{Key: "id", Value: "scan-123"}}

	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleCancelScan(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "scan-123", response["scan_id"])
	assert.Equal(t, "cancelled", response["status"])
}

func TestHandleHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("GET", "/api/v1/webhooks/health", nil)

	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{
		Enabled: true,
		Providers: map[string]ProviderConfig{
			"github": {
				Enabled: true,
				Events:  []string{"push"},
			},
			"gitlab": {
				Enabled: false,
			},
		},
	}

	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)
	handler.handleHealth(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	assert.True(t, response["enabled"].(bool))

	providers := response["providers"].(map[string]interface{})
	assert.NotNil(t, providers)

	githubProvider := providers["github"].(map[string]interface{})
	assert.True(t, githubProvider["enabled"].(bool))
	assert.NotNil(t, githubProvider["events"])

	gitlabProvider := providers["gitlab"].(map[string]interface{})
	assert.False(t, gitlabProvider["enabled"].(bool))
}

func TestGenerateScanID(t *testing.T) {
	testLogger := logger.NewTestLogger()
	mockScanTrigger := new(MockScanTrigger)

	config := &WebhookConfig{}
	handler := NewWebhookHandler(testLogger, mockScanTrigger, config)

	scanID1 := handler.generateScanID()
	scanID2 := handler.generateScanID()

    // Should start with webhook_
    assert.True(t, len(scanID1) > 8)
    assert.Contains(t, scanID1, "webhook_")
    assert.Contains(t, scanID2, "webhook_")
}
