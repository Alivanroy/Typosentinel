package auth

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SAMLProvider implements SAML 2.0 authentication
type SAMLProvider struct {
	config *SAMLConfig
}

// SAMLConfig holds SAML provider configuration
type SAMLConfig struct {
	EntityID                string `json:"entity_id"`
	SSOURL                  string `json:"sso_url"`
	SLOURL                  string `json:"slo_url"`
	Certificate             string `json:"certificate"`
	PrivateKey              string `json:"private_key"`
	IDPMetadataURL          string `json:"idp_metadata_url"`
	IDPEntityID             string `json:"idp_entity_id"`
	IDPSSOURL               string `json:"idp_sso_url"`
	IDPSLOURL               string `json:"idp_slo_url"`
	IDPCertificate          string `json:"idp_certificate"`
	NameIDFormat            string `json:"name_id_format"`
	SignRequests            bool   `json:"sign_requests"`
	WantAssertionsSigned    bool   `json:"want_assertions_signed"`
	WantResponseSigned      bool   `json:"want_response_signed"`
	AllowUnencryptedAssertion bool `json:"allow_unencrypted_assertion"`
	AttributeMapping        map[string]string `json:"attribute_mapping"`
}

// SAMLResponse represents a SAML response
type SAMLResponse struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	Issuer       SAMLIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       SAMLStatus `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    SAMLAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// SAMLIssuer represents the SAML issuer
type SAMLIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// SAMLStatus represents the SAML status
type SAMLStatus struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode SAMLStatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// SAMLStatusCode represents the SAML status code
type SAMLStatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// SAMLAssertion represents a SAML assertion
type SAMLAssertion struct {
	XMLName            xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string   `xml:"ID,attr"`
	Version            string   `xml:"Version,attr"`
	IssueInstant       string   `xml:"IssueInstant,attr"`
	Issuer             SAMLIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            SAMLSubject `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         SAMLConditions `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement SAMLAttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// SAMLSubject represents the SAML subject
type SAMLSubject struct {
	XMLName             xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              SAMLNameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SAMLSubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// SAMLNameID represents the SAML NameID
type SAMLNameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

// SAMLSubjectConfirmation represents SAML subject confirmation
type SAMLSubjectConfirmation struct {
	XMLName                      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                       string   `xml:"Method,attr"`
	SubjectConfirmationData      SAMLSubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// SAMLSubjectConfirmationData represents SAML subject confirmation data
type SAMLSubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
}

// SAMLConditions represents SAML conditions
type SAMLConditions struct {
	XMLName                xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore              string   `xml:"NotBefore,attr"`
	NotOnOrAfter           string   `xml:"NotOnOrAfter,attr"`
	AudienceRestriction    SAMLAudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// SAMLAudienceRestriction represents SAML audience restriction
type SAMLAudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience SAMLAudience `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// SAMLAudience represents SAML audience
type SAMLAudience struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	Value   string   `xml:",chardata"`
}

// SAMLAttributeStatement represents SAML attribute statement
type SAMLAttributeStatement struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []SAMLAttribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// SAMLAttribute represents a SAML attribute
type SAMLAttribute struct {
	XMLName        xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name           string   `xml:"Name,attr"`
	NameFormat     string   `xml:"NameFormat,attr"`
	AttributeValue SAMLAttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// SAMLAttributeValue represents a SAML attribute value
type SAMLAttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value   string   `xml:",chardata"`
}

// NewSAMLProvider creates a new SAML provider
func NewSAMLProvider(config *SAMLConfig) *SAMLProvider {
	return &SAMLProvider{
		config: config,
	}
}

// CreateSAMLProviderFromConfig creates a SAML provider from ProviderConfig
func CreateSAMLProviderFromConfig(providerConfig *ProviderConfig) (*SAMLProvider, error) {
	if !providerConfig.Enabled {
		return nil, fmt.Errorf("SAML provider is disabled")
	}

	settings := providerConfig.Settings
	config := &SAMLConfig{
		EntityID:                  getString(settings, "entity_id"),
		SSOURL:                    getString(settings, "sso_url"),
		SLOURL:                    getString(settings, "slo_url"),
		Certificate:               getString(settings, "certificate"),
		PrivateKey:                getString(settings, "private_key"),
		IDPMetadataURL:            getString(settings, "idp_metadata_url"),
		IDPEntityID:               getString(settings, "idp_entity_id"),
		IDPSSOURL:                 getString(settings, "idp_sso_url"),
		IDPSLOURL:                 getString(settings, "idp_slo_url"),
		IDPCertificate:            getString(settings, "idp_certificate"),
		NameIDFormat:              getString(settings, "name_id_format"),
		SignRequests:              getBool(settings, "sign_requests"),
		WantAssertionsSigned:      getBool(settings, "want_assertions_signed"),
		WantResponseSigned:        getBool(settings, "want_response_signed"),
		AllowUnencryptedAssertion: getBool(settings, "allow_unencrypted_assertion"),
		AttributeMapping:          getStringMap(settings, "attribute_mapping"),
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration: %w", err)
	}

	return NewSAMLProvider(config), nil
}

// Authenticate implements the SSOProvider interface
func (sp *SAMLProvider) Authenticate(ctx context.Context, request *http.Request) (*SSOToken, error) {
	// Parse SAML response from POST data
	if err := request.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse form data: %w", err)
	}

	samlResponse := request.FormValue("SAMLResponse")
	if samlResponse == "" {
		return nil, fmt.Errorf("missing SAMLResponse parameter")
	}

	// Decode base64 SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Parse XML response
	var response SAMLResponse
	if err := xml.Unmarshal(decodedResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Validate response
	if err := sp.validateResponse(&response); err != nil {
		return nil, fmt.Errorf("SAML response validation failed: %w", err)
	}

	// Extract user information
	_, err = sp.extractUserInfo(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user info: %w", err)
	}

	// Create SSO token
	token := &SSOToken{
		AccessToken:  response.ID, // Use response ID as token
		TokenType:    "SAML",
		ExpiresIn:    3600, // 1 hour default
		RefreshToken: "",   // SAML doesn't use refresh tokens
		Scope:        "openid profile email",
		IDToken:      samlResponse,
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	return token, nil
}

// GetUser implements the SSOProvider interface
func (sp *SAMLProvider) GetUser(ctx context.Context, token *SSOToken) (*SSOUser, error) {
	// For SAML, user info is embedded in the token's IDToken field
	if token.IDToken == "" {
		return nil, fmt.Errorf("missing SAML response in token")
	}

	// Decode and parse SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(token.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	var response SAMLResponse
	if err := xml.Unmarshal(decodedResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	return sp.extractUserInfo(&response)
}

// ValidateToken implements the SSOProvider interface
func (sp *SAMLProvider) ValidateToken(ctx context.Context, token *SSOToken) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	if token.TokenType != "SAML" {
		return fmt.Errorf("invalid token type: %s", token.TokenType)
	}

	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("token has expired")
	}

	return nil
}

// RefreshToken implements the SSOProvider interface
func (sp *SAMLProvider) RefreshToken(ctx context.Context, refreshToken string) (*SSOToken, error) {
	// SAML doesn't support token refresh - user must re-authenticate
	return nil, fmt.Errorf("SAML does not support token refresh")
}

// GetAuthorizationURL generates a SAML authentication request URL
func (sp *SAMLProvider) GetAuthorizationURL(state string, redirectURI string) (string, error) {
	// Create SAML AuthnRequest
	authnRequest := sp.createAuthnRequest(redirectURI)

	// Encode the request
	encodedRequest, err := sp.encodeAuthnRequest(authnRequest)
	if err != nil {
		return "", fmt.Errorf("failed to encode AuthnRequest: %w", err)
	}

	// Build the redirect URL
	params := url.Values{}
	params.Set("SAMLRequest", encodedRequest)
	if state != "" {
		params.Set("RelayState", state)
	}

	redirectURL := fmt.Sprintf("%s?%s", sp.config.IDPSSOURL, params.Encode())
	return redirectURL, nil
}

// Validate validates the SAML configuration
func (c *SAMLConfig) Validate() error {
	if c.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}
	if c.IDPSSOURL == "" {
		return fmt.Errorf("idp_sso_url is required")
	}
	if c.IDPEntityID == "" {
		return fmt.Errorf("idp_entity_id is required")
	}
	if c.IDPCertificate == "" {
		return fmt.Errorf("idp_certificate is required")
	}
	return nil
}

// validateResponse validates a SAML response
func (sp *SAMLProvider) validateResponse(response *SAMLResponse) error {
	// Check status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("SAML authentication failed: %s", response.Status.StatusCode.Value)
	}

	// Validate issuer
	if response.Issuer.Value != sp.config.IDPEntityID {
		return fmt.Errorf("invalid issuer: expected %s, got %s", sp.config.IDPEntityID, response.Issuer.Value)
	}

	// Validate assertion issuer
	if response.Assertion.Issuer.Value != sp.config.IDPEntityID {
		return fmt.Errorf("invalid assertion issuer: expected %s, got %s", sp.config.IDPEntityID, response.Assertion.Issuer.Value)
	}

	// Validate audience
	if response.Assertion.Conditions.AudienceRestriction.Audience.Value != sp.config.EntityID {
		return fmt.Errorf("invalid audience: expected %s, got %s", sp.config.EntityID, response.Assertion.Conditions.AudienceRestriction.Audience.Value)
	}

	// Validate time conditions
	now := time.Now()
	notBefore, err := time.Parse(time.RFC3339, response.Assertion.Conditions.NotBefore)
	if err == nil && now.Before(notBefore) {
		return fmt.Errorf("assertion not yet valid")
	}

	notOnOrAfter, err := time.Parse(time.RFC3339, response.Assertion.Conditions.NotOnOrAfter)
	if err == nil && now.After(notOnOrAfter) {
		return fmt.Errorf("assertion has expired")
	}

	return nil
}

// extractUserInfo extracts user information from SAML response
func (sp *SAMLProvider) extractUserInfo(response *SAMLResponse) (*SSOUser, error) {
	user := &SSOUser{
		ID:         response.Assertion.Subject.NameID.Value,
		Username:   response.Assertion.Subject.NameID.Value,
		Provider:   "saml",
		Attributes: make(map[string]string),
		Verified:   true,
	}

	// Extract attributes
	for _, attr := range response.Assertion.AttributeStatement.Attributes {
		value := attr.AttributeValue.Value
		user.Attributes[attr.Name] = value

		// Map standard attributes
		switch attr.Name {
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
			user.Email = value
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":
			user.FirstName = value
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":
			user.LastName = value
		case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
			user.Name = value
		}

		// Apply custom attribute mapping
		if mappedField, exists := sp.config.AttributeMapping[attr.Name]; exists {
			switch mappedField {
			case "email":
				user.Email = value
			case "first_name":
				user.FirstName = value
			case "last_name":
				user.LastName = value
			case "name":
				user.Name = value
			case "username":
				user.Username = value
			}
		}
	}

	// Set display name if not already set
	if user.Name == "" {
		if user.FirstName != "" && user.LastName != "" {
			user.Name = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
		} else if user.Username != "" {
			user.Name = user.Username
		}
	}

	return user, nil
}

// createAuthnRequest creates a SAML AuthnRequest
func (sp *SAMLProvider) createAuthnRequest(redirectURI string) string {
	// This is a simplified AuthnRequest - in production, you'd want to use a proper SAML library
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_%s"
                    Version="2.0"
                    IssueInstant="%s"
                    Destination="%s"
                    AssertionConsumerServiceURL="%s"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>%s</saml:Issuer>
    <samlp:NameIDPolicy Format="%s" AllowCreate="true"/>
</samlp:AuthnRequest>`,
		generateID(),
		time.Now().UTC().Format(time.RFC3339),
		sp.config.IDPSSOURL,
		redirectURI,
		sp.config.EntityID,
		sp.config.NameIDFormat,
	)
}

// encodeAuthnRequest encodes an AuthnRequest for transmission
func (sp *SAMLProvider) encodeAuthnRequest(authnRequest string) (string, error) {
	// Base64 encode the request
	return base64.StdEncoding.EncodeToString([]byte(authnRequest)), nil
}

// generateID generates a unique ID for SAML requests
func generateID() string {
	return fmt.Sprintf("id%d", time.Now().UnixNano())
}

// Helper functions for extracting values from settings map
func getString(settings map[string]interface{}, key string) string {
	if val, ok := settings[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

func getBool(settings map[string]interface{}, key string) bool {
	if val, ok := settings[key]; ok {
		if boolVal, ok := val.(bool); ok {
			return boolVal
		}
	}
	return false
}

func getStringMap(settings map[string]interface{}, key string) map[string]string {
	if val, ok := settings[key]; ok {
		if mapVal, ok := val.(map[string]interface{}); ok {
			result := make(map[string]string)
			for k, v := range mapVal {
				if strVal, ok := v.(string); ok {
					result[k] = strVal
				}
			}
			return result
		}
	}
	return make(map[string]string)
}