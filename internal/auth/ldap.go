package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPProvider implements LDAP authentication
type LDAPProvider struct {
	config LDAPConfig
}

// LDAPConfig holds LDAP configuration
type LDAPConfig struct {
	Host                 string            `yaml:"host" json:"host"`
	Port                 int               `yaml:"port" json:"port"`
	UseTLS               bool              `yaml:"use_tls" json:"use_tls"`
	SkipTLSVerify        bool              `yaml:"skip_tls_verify" json:"skip_tls_verify"`
	BindDN               string            `yaml:"bind_dn" json:"bind_dn"`
	BindPassword         string            `yaml:"bind_password" json:"bind_password"`
	BaseDN               string            `yaml:"base_dn" json:"base_dn"`
	UserFilter           string            `yaml:"user_filter" json:"user_filter"`
	UserSearchBase       string            `yaml:"user_search_base" json:"user_search_base"`
	GroupFilter          string            `yaml:"group_filter" json:"group_filter"`
	GroupSearchBase      string            `yaml:"group_search_base" json:"group_search_base"`
	UsernameAttribute    string            `yaml:"username_attribute" json:"username_attribute"`
	EmailAttribute       string            `yaml:"email_attribute" json:"email_attribute"`
	DisplayNameAttribute string            `yaml:"display_name_attribute" json:"display_name_attribute"`
	GroupMemberAttribute string            `yaml:"group_member_attribute" json:"group_member_attribute"`
	RoleMapping          map[string]string `yaml:"role_mapping" json:"role_mapping"`
	ConnectionTimeout    time.Duration     `yaml:"connection_timeout" json:"connection_timeout"`
	RequestTimeout       time.Duration     `yaml:"request_timeout" json:"request_timeout"`
}

// NewLDAPProvider creates a new LDAP authentication provider
func NewLDAPProvider(config LDAPConfig) *LDAPProvider {
	// Set defaults
	if config.Port == 0 {
		if config.UseTLS {
			config.Port = 636
		} else {
			config.Port = 389
		}
	}
	if config.UserFilter == "" {
		config.UserFilter = "(uid=%s)"
	}
	if config.GroupFilter == "" {
		config.GroupFilter = "(member=%s)"
	}
	if config.UsernameAttribute == "" {
		config.UsernameAttribute = "uid"
	}
	if config.EmailAttribute == "" {
		config.EmailAttribute = "mail"
	}
	if config.DisplayNameAttribute == "" {
		config.DisplayNameAttribute = "cn"
	}
	if config.GroupMemberAttribute == "" {
		config.GroupMemberAttribute = "member"
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}

	return &LDAPProvider{config: config}
}

// Authenticate authenticates a user against LDAP
func (p *LDAPProvider) Authenticate(ctx context.Context, username, password string) (*User, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	// Bind with service account if configured
	if p.config.BindDN != "" {
		err = conn.Bind(p.config.BindDN, p.config.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for user
	userDN, userEntry, err := p.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	// Authenticate user
	err = conn.Bind(userDN, password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Get user groups
	groups, err := p.getUserGroups(conn, userDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Map groups to roles
	roles := p.mapGroupsToRoles(groups)

	// Create user object
	user := &User{
		ID:          userEntry.GetAttributeValue(p.config.UsernameAttribute),
		Username:    username,
		Email:       userEntry.GetAttributeValue(p.config.EmailAttribute),
		DisplayName: userEntry.GetAttributeValue(p.config.DisplayNameAttribute),
		Roles:       roles,
		Groups:      groups,
		Attributes:  make(map[string]string),
		CreatedAt:   time.Now(),
		LastLoginAt: &[]time.Time{time.Now()}[0],
		IsActive:    true,
	}

	// Extract additional attributes
	for _, attr := range userEntry.Attributes {
		if len(attr.Values) > 0 {
			user.Attributes[attr.Name] = attr.Values[0]
		}
	}

	return user, nil
}

// ValidateToken validates a token (not implemented for LDAP)
func (p *LDAPProvider) ValidateToken(ctx context.Context, token string) (*User, error) {
	return nil, fmt.Errorf("token validation not supported by LDAP provider")
}

// GetUser retrieves user information by ID
func (p *LDAPProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	// Bind with service account
	if p.config.BindDN != "" {
		err = conn.Bind(p.config.BindDN, p.config.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for user
	userDN, userEntry, err := p.searchUser(conn, userID)
	if err != nil {
		return nil, err
	}

	// Get user groups
	groups, err := p.getUserGroups(conn, userDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Map groups to roles
	roles := p.mapGroupsToRoles(groups)

	// Create user object
	user := &User{
		ID:          userEntry.GetAttributeValue(p.config.UsernameAttribute),
		Username:    userID,
		Email:       userEntry.GetAttributeValue(p.config.EmailAttribute),
		DisplayName: userEntry.GetAttributeValue(p.config.DisplayNameAttribute),
		Roles:       roles,
		Groups:      groups,
		Attributes:  make(map[string]string),
		IsActive:    true,
	}

	// Extract additional attributes
	for _, attr := range userEntry.Attributes {
		if len(attr.Values) > 0 {
			user.Attributes[attr.Name] = attr.Values[0]
		}
	}

	return user, nil
}

// GetUserByUsername retrieves user information by username
func (p *LDAPProvider) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return p.GetUser(ctx, username)
}

// RefreshToken refreshes a token (not implemented for LDAP)
func (p *LDAPProvider) RefreshToken(ctx context.Context, token string) (string, error) {
	return "", fmt.Errorf("token refresh not supported by LDAP provider")
}

// Logout logs out a user (no-op for LDAP)
func (p *LDAPProvider) Logout(ctx context.Context, token string) error {
	return nil
}

// GetProviderType returns the provider type
func (p *LDAPProvider) GetProviderType() string {
	return "ldap"
}

// connect establishes a connection to the LDAP server
func (p *LDAPProvider) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	var conn *ldap.Conn
	var err error

	if p.config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.config.SkipTLSVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, err
	}

	// Set timeouts
	conn.SetTimeout(p.config.RequestTimeout)

	return conn, nil
}

// searchUser searches for a user in LDAP
func (p *LDAPProvider) searchUser(conn *ldap.Conn, username string) (string, *ldap.Entry, error) {
	searchBase := p.config.UserSearchBase
	if searchBase == "" {
		searchBase = p.config.BaseDN
	}

	filter := fmt.Sprintf(p.config.UserFilter, ldap.EscapeFilter(username))

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit
		int(p.config.RequestTimeout.Seconds()),
		false,
		filter,
		[]string{"dn", p.config.UsernameAttribute, p.config.EmailAttribute, p.config.DisplayNameAttribute},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return "", nil, ErrUserNotFound
	}

	entry := searchResult.Entries[0]
	return entry.DN, entry, nil
}

// getUserGroups retrieves groups for a user
func (p *LDAPProvider) getUserGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	searchBase := p.config.GroupSearchBase
	if searchBase == "" {
		searchBase = p.config.BaseDN
	}

	filter := fmt.Sprintf(p.config.GroupFilter, ldap.EscapeFilter(userDN))

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		int(p.config.RequestTimeout.Seconds()),
		false,
		filter,
		[]string{"cn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	var groups []string
	for _, entry := range searchResult.Entries {
		groupName := entry.GetAttributeValue("cn")
		if groupName != "" {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

// mapGroupsToRoles maps LDAP groups to application roles
func (p *LDAPProvider) mapGroupsToRoles(groups []string) []string {
	var roles []string
	roleSet := make(map[string]bool)

	for _, group := range groups {
		if role, exists := p.config.RoleMapping[group]; exists {
			if !roleSet[role] {
				roles = append(roles, role)
				roleSet[role] = true
			}
		}
	}

	// Add default role if no roles mapped
	if len(roles) == 0 {
		roles = append(roles, "user")
	}

	return roles
}

// TestConnection tests the LDAP connection
func (p *LDAPProvider) TestConnection() error {
	conn, err := p.connect()
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	// Test bind if credentials provided
	if p.config.BindDN != "" {
		err = conn.Bind(p.config.BindDN, p.config.BindPassword)
		if err != nil {
			return fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	return nil
}
