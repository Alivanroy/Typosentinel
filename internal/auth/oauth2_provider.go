package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// OAuth2Provider implements SSO authentication using OAuth2/OIDC
type OAuth2Provider struct {
	name         string
	clientID     string
	clientSecret string
	authorizeURL string
	tokenURL     string
	userInfoURL  string
	redirectURL  string
	scopes       []string
	client       *http.Client
	logger       *logrus.Logger
}

// OAuth2Config contains OAuth2 provider configuration
type OAuth2Config struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	AuthorizeURL string   `json:"authorize_url" yaml:"authorize_url"`
	TokenURL     string   `json:"token_url" yaml:"token_url"`
	UserInfoURL  string   `json:"user_info_url" yaml:"user_info_url"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

// OAuth2TokenResponse represents the OAuth2 token response
type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// OAuth2UserInfo represents user information from OAuth2 provider
type OAuth2UserInfo struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Picture           string   `json:"picture"`
	Locale            string   `json:"locale"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

// NewOAuth2Provider creates a new OAuth2 provider
func NewOAuth2Provider(name string, config OAuth2Config, logger *logrus.Logger) *OAuth2Provider {
	if logger == nil {
		logger = logrus.New()
	}

	return &OAuth2Provider{
		name:         name,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		authorizeURL: config.AuthorizeURL,
		tokenURL:     config.TokenURL,
		userInfoURL:  config.UserInfoURL,
		redirectURL:  config.RedirectURL,
		scopes:       config.Scopes,
		client:       &http.Client{Timeout: 30 * time.Second},
		logger:       logger,
	}
}

// GetProviderName returns the provider name
func (p *OAuth2Provider) GetProviderName() string {
	return p.name
}

// GetAuthURL generates the OAuth2 authorization URL
func (p *OAuth2Provider) GetAuthURL(state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"response_type": {"code"},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
	}

	// Add OIDC specific parameters
	if p.isOIDC() {
		params.Set("response_mode", "query")
		params.Set("nonce", state) // Use state as nonce for simplicity
	}

	authURL := fmt.Sprintf("%s?%s", p.authorizeURL, params.Encode())
	return authURL, nil
}

// ExchangeCode exchanges authorization code for access token
func (p *OAuth2Provider) ExchangeCode(code, state string) (*SSOToken, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	req, err := http.NewRequest("POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &SSOToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// GetUserInfo retrieves user information using the access token
func (p *OAuth2Provider) GetUserInfo(token *SSOToken) (*SSOUser, error) {
	req, err := http.NewRequest("GET", p.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo OAuth2UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &SSOUser{
		ID:          userInfo.Sub,
		Email:       userInfo.Email,
		Name:        userInfo.Name,
		FirstName:   userInfo.GivenName,
		LastName:    userInfo.FamilyName,
		Username:    userInfo.PreferredUsername,
		Picture:     userInfo.Picture,
		Provider:    p.name,
		Roles:       userInfo.Roles,
		Groups:      userInfo.Groups,
		Verified:    userInfo.EmailVerified,
		LastLoginAt: time.Now(),
		Attributes: map[string]string{
			"locale": userInfo.Locale,
			"sub":    userInfo.Sub,
		},
	}, nil
}

// ValidateToken validates an access token
func (p *OAuth2Provider) ValidateToken(tokenString string) (*SSOUser, error) {
	token := &SSOToken{
		AccessToken: tokenString,
		TokenType:   "Bearer",
	}

	return p.GetUserInfo(token)
}

// RefreshToken refreshes an access token using the refresh token
func (p *OAuth2Provider) RefreshToken(refreshToken string) (*SSOToken, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	req, err := http.NewRequest("POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &SSOToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// Logout performs logout (revokes token if supported)
func (p *OAuth2Provider) Logout(token string) error {
	// OAuth2 doesn't have a standard logout endpoint
	// This would be provider-specific implementation
	p.logger.Infof("Logout called for OAuth2 provider %s", p.name)
	return nil
}

// isOIDC checks if this is an OpenID Connect provider
func (p *OAuth2Provider) isOIDC() bool {
	for _, scope := range p.scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

// SetHTTPClient allows setting a custom HTTP client
func (p *OAuth2Provider) SetHTTPClient(client *http.Client) {
	p.client = client
}

// GetTokenInfo returns information about a token without making external calls
func (p *OAuth2Provider) GetTokenInfo(token *SSOToken) map[string]interface{} {
	return map[string]interface{}{
		"provider":     p.name,
		"token_type":   token.TokenType,
		"expires_at":   token.ExpiresAt,
		"scope":        token.Scope,
		"has_refresh":  token.RefreshToken != "",
		"has_id_token": token.IDToken != "",
		"is_expired":   time.Now().After(token.ExpiresAt),
	}
}

// ValidateConfig validates the OAuth2 provider configuration
func ValidateOAuth2Config(config OAuth2Config) error {
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if config.AuthorizeURL == "" {
		return fmt.Errorf("authorize_url is required")
	}
	if config.TokenURL == "" {
		return fmt.Errorf("token_url is required")
	}
	if config.UserInfoURL == "" {
		return fmt.Errorf("user_info_url is required")
	}
	if config.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}
	if len(config.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	return nil
}

// CreateOAuth2ProviderFromConfig creates an OAuth2 provider from configuration
func CreateOAuth2ProviderFromConfig(name string, providerConfig ProviderConfig, logger *logrus.Logger) (*OAuth2Provider, error) {
	settings := providerConfig.Settings

	getString := func(key string) string {
		if val, ok := settings[key].(string); ok {
			return val
		}
		return ""
	}

	getStringSlice := func(key string) []string {
		if val, ok := settings[key].([]interface{}); ok {
			result := make([]string, len(val))
			for i, v := range val {
				if str, ok := v.(string); ok {
					result[i] = str
				}
			}
			return result
		}
		if val, ok := settings[key].([]string); ok {
			return val
		}
		return []string{}
	}

	oauth2Config := OAuth2Config{
		ClientID:     getString("client_id"),
		ClientSecret: getString("client_secret"),
		AuthorizeURL: getString("authorize_url"),
		TokenURL:     getString("token_url"),
		UserInfoURL:  getString("user_info_url"),
		RedirectURL:  getString("redirect_url"),
		Scopes:       getStringSlice("scopes"),
	}

	if err := ValidateOAuth2Config(oauth2Config); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 config for provider %s: %w", name, err)
	}

	return NewOAuth2Provider(name, oauth2Config, logger), nil
}
