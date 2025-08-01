package orchestrator

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// AdvancedFilter implements sophisticated repository filtering
type AdvancedFilter struct {
	config FilterConfig
}

// FilterConfig holds configuration for advanced filtering
type FilterConfig struct {
	Languages        []string          `json:"languages"`
	MinStars         int               `json:"min_stars"`
	MaxStars         int               `json:"max_stars"`
	MinSize          int64             `json:"min_size"`          // in bytes
	MaxSize          int64             `json:"max_size"`          // in bytes
	NamePatterns     []string          `json:"name_patterns"`     // regex patterns
	ExcludePatterns  []string          `json:"exclude_patterns"`  // regex patterns
	MinAge           *time.Duration    `json:"min_age"`           // minimum repository age
	MaxAge           *time.Duration    `json:"max_age"`           // maximum repository age
	RequiredTopics   []string          `json:"required_topics"`
	ExcludedTopics   []string          `json:"excluded_topics"`
	IsPrivate        *bool             `json:"is_private"`        // nil means both, true means private only, false means public only
	IsFork           *bool             `json:"is_fork"`           // nil means both, true means forks only, false means non-forks only
	IsArchived       *bool             `json:"is_archived"`       // nil means both, true means archived only, false means active only
	HasIssues        *bool             `json:"has_issues"`
	HasWiki          *bool             `json:"has_wiki"`
	HasPages         *bool             `json:"has_pages"`
	CustomFilters    map[string]string `json:"custom_filters"`    // custom key-value filters
	OwnerTypes       []string          `json:"owner_types"`       // "user", "organization"
	LicenseTypes     []string          `json:"license_types"`
	MinCommits       int               `json:"min_commits"`
	MaxCommits       int               `json:"max_commits"`
	MinContributors  int               `json:"min_contributors"`
	MaxContributors  int               `json:"max_contributors"`
	LastActivityDays int               `json:"last_activity_days"` // repositories with activity in last N days
}

// NewAdvancedFilter creates a new advanced filter
func NewAdvancedFilter(config FilterConfig) *AdvancedFilter {
	return &AdvancedFilter{
		config: config,
	}
}

// FilterRepositories filters a list of repositories based on the configured criteria
func (af *AdvancedFilter) FilterRepositories(repos []*repository.Repository) ([]*repository.Repository, error) {
	var filtered []*repository.Repository

	for _, repo := range repos {
		matches, err := af.MatchesRepository(repo)
		if err != nil {
			return nil, fmt.Errorf("error filtering repository %s: %w", repo.FullName, err)
		}
		if matches {
			filtered = append(filtered, repo)
		}
	}

	return filtered, nil
}

// MatchesRepository checks if a single repository matches the filter criteria
func (af *AdvancedFilter) MatchesRepository(repo *repository.Repository) (bool, error) {
	// Language filter
	if len(af.config.Languages) > 0 {
		if !af.matchesLanguages(repo) {
			return false, nil
		}
	}

	// Stars filter
	if af.config.MinStars > 0 && repo.StarCount < af.config.MinStars {
		return false, nil
	}
	if af.config.MaxStars > 0 && repo.StarCount > af.config.MaxStars {
		return false, nil
	}

	// Size filter
	if af.config.MinSize > 0 && repo.Size < af.config.MinSize {
		return false, nil
	}
	if af.config.MaxSize > 0 && repo.Size > af.config.MaxSize {
		return false, nil
	}

	// Name pattern filters
	if len(af.config.NamePatterns) > 0 {
		matches, err := af.matchesNamePatterns(repo.Name)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}

	// Exclude pattern filters
	if len(af.config.ExcludePatterns) > 0 {
		excluded, err := af.matchesExcludePatterns(repo.Name)
		if err != nil {
			return false, err
		}
		if excluded {
			return false, nil
		}
	}

	// Age filters
	if af.config.MinAge != nil || af.config.MaxAge != nil {
		if !af.matchesAge(repo) {
			return false, nil
		}
	}

	// Topics filters
	if len(af.config.RequiredTopics) > 0 {
		if !af.hasRequiredTopics(repo) {
			return false, nil
		}
	}
	if len(af.config.ExcludedTopics) > 0 {
		if af.hasExcludedTopics(repo) {
			return false, nil
		}
	}

	// Boolean property filters
	if af.config.IsPrivate != nil && repo.Private != *af.config.IsPrivate {
		return false, nil
	}
	if af.config.IsFork != nil && repo.Fork != *af.config.IsFork {
		return false, nil
	}
	if af.config.IsArchived != nil && repo.Archived != *af.config.IsArchived {
		return false, nil
	}
	// Note: HasIssues, HasWiki, HasPages not available in Repository struct

	// Owner type filter
	if len(af.config.OwnerTypes) > 0 {
		if !af.matchesOwnerType(repo) {
			return false, nil
		}
	}

	// Note: License information not available in Repository struct
	// This would need to be fetched separately via connector methods

	// Note: CommitCount and ContributorCount not available in Repository struct
	// These would need to be fetched separately via connector methods

	// Last activity filter
	if af.config.LastActivityDays > 0 {
		if !af.matchesLastActivity(repo) {
			return false, nil
		}
	}

	// Custom filters
	if len(af.config.CustomFilters) > 0 {
		if !af.matchesCustomFilters(repo) {
			return false, nil
		}
	}

	return true, nil
}

// matchesLanguages checks if repository matches language criteria
func (af *AdvancedFilter) matchesLanguages(repo *repository.Repository) bool {
	if repo.Language == "" {
		return false
	}

	for _, lang := range af.config.Languages {
		if strings.EqualFold(repo.Language, lang) {
			return true
		}
	}
	return false
}

// matchesNamePatterns checks if repository name matches any of the name patterns
func (af *AdvancedFilter) matchesNamePatterns(name string) (bool, error) {
	for _, pattern := range af.config.NamePatterns {
		matched, err := regexp.MatchString(pattern, name)
		if err != nil {
			return false, fmt.Errorf("invalid name pattern %s: %w", pattern, err)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// matchesExcludePatterns checks if repository name matches any exclude patterns
func (af *AdvancedFilter) matchesExcludePatterns(name string) (bool, error) {
	for _, pattern := range af.config.ExcludePatterns {
		matched, err := regexp.MatchString(pattern, name)
		if err != nil {
			return false, fmt.Errorf("invalid exclude pattern %s: %w", pattern, err)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// matchesAge checks if repository age matches criteria
func (af *AdvancedFilter) matchesAge(repo *repository.Repository) bool {
	age := time.Since(repo.CreatedAt)

	if af.config.MinAge != nil && age < *af.config.MinAge {
		return false
	}
	if af.config.MaxAge != nil && age > *af.config.MaxAge {
		return false
	}

	return true
}

// hasRequiredTopics checks if repository has all required topics
func (af *AdvancedFilter) hasRequiredTopics(repo *repository.Repository) bool {
	for _, required := range af.config.RequiredTopics {
		found := false
		for _, topic := range repo.Topics {
			if strings.EqualFold(topic, required) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// hasExcludedTopics checks if repository has any excluded topics
func (af *AdvancedFilter) hasExcludedTopics(repo *repository.Repository) bool {
	for _, excluded := range af.config.ExcludedTopics {
		for _, topic := range repo.Topics {
			if strings.EqualFold(topic, excluded) {
				return true
			}
		}
	}
	return false
}

// matchesOwnerType checks if repository owner type matches criteria
func (af *AdvancedFilter) matchesOwnerType(repo *repository.Repository) bool {
	for _, ownerType := range af.config.OwnerTypes {
		if strings.EqualFold(repo.Owner.Type, ownerType) {
			return true
		}
	}
	return false
}

// matchesLicense checks if repository license matches criteria
// Note: License information not available in Repository struct
func (af *AdvancedFilter) matchesLicense(repo *repository.Repository) bool {
	// This would need to be implemented by fetching license info via connector
	return true // Skip license filtering for now
}

// matchesLastActivity checks if repository has recent activity
func (af *AdvancedFilter) matchesLastActivity(repo *repository.Repository) bool {
	lastActivity := repo.UpdatedAt
	if repo.PushedAt.After(lastActivity) {
		lastActivity = repo.PushedAt
	}

	daysSinceActivity := int(time.Since(lastActivity).Hours() / 24)
	return daysSinceActivity <= af.config.LastActivityDays
}

// matchesCustomFilters checks custom filter criteria
func (af *AdvancedFilter) matchesCustomFilters(repo *repository.Repository) bool {
	for key, value := range af.config.CustomFilters {
		switch key {
		case "default_branch":
			if !strings.EqualFold(repo.DefaultBranch, value) {
				return false
			}
		case "visibility":
			expectedPrivate := strings.EqualFold(value, "private")
			if repo.Private != expectedPrivate {
				return false
			}
		case "has_downloads":
			// Note: HasDownloads not available in Repository struct
			// Skip this custom filter
		default:
			// For unknown custom filters, we skip them
			continue
		}
	}
	return true
}

// GetFilterSummary returns a summary of the current filter configuration
func (af *AdvancedFilter) GetFilterSummary() map[string]interface{} {
	summary := make(map[string]interface{})

	if len(af.config.Languages) > 0 {
		summary["languages"] = af.config.Languages
	}
	if af.config.MinStars > 0 || af.config.MaxStars > 0 {
		summary["stars_range"] = fmt.Sprintf("%d-%d", af.config.MinStars, af.config.MaxStars)
	}
	if af.config.MinSize > 0 || af.config.MaxSize > 0 {
		summary["size_range"] = fmt.Sprintf("%d-%d bytes", af.config.MinSize, af.config.MaxSize)
	}
	if len(af.config.NamePatterns) > 0 {
		summary["name_patterns"] = af.config.NamePatterns
	}
	if len(af.config.ExcludePatterns) > 0 {
		summary["exclude_patterns"] = af.config.ExcludePatterns
	}
	if af.config.IsPrivate != nil {
		summary["private_only"] = *af.config.IsPrivate
	}
	if af.config.IsFork != nil {
		summary["forks_only"] = *af.config.IsFork
	}
	if af.config.IsArchived != nil {
		summary["archived_only"] = *af.config.IsArchived
	}
	if len(af.config.RequiredTopics) > 0 {
		summary["required_topics"] = af.config.RequiredTopics
	}
	if len(af.config.ExcludedTopics) > 0 {
		summary["excluded_topics"] = af.config.ExcludedTopics
	}
	if len(af.config.OwnerTypes) > 0 {
		summary["owner_types"] = af.config.OwnerTypes
	}
	if len(af.config.LicenseTypes) > 0 {
		summary["license_types"] = af.config.LicenseTypes
	}
	if af.config.LastActivityDays > 0 {
		summary["last_activity_days"] = af.config.LastActivityDays
	}
	if len(af.config.CustomFilters) > 0 {
		summary["custom_filters"] = af.config.CustomFilters
	}

	return summary
}

// ValidateConfig validates the filter configuration
func (af *AdvancedFilter) ValidateConfig() error {
	// Validate regex patterns
	for _, pattern := range af.config.NamePatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid name pattern %s: %w", pattern, err)
		}
	}

	for _, pattern := range af.config.ExcludePatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid exclude pattern %s: %w", pattern, err)
		}
	}

	// Validate ranges
	if af.config.MinStars > af.config.MaxStars && af.config.MaxStars > 0 {
		return fmt.Errorf("min_stars (%d) cannot be greater than max_stars (%d)", af.config.MinStars, af.config.MaxStars)
	}

	if af.config.MinSize > af.config.MaxSize && af.config.MaxSize > 0 {
		return fmt.Errorf("min_size (%d) cannot be greater than max_size (%d)", af.config.MinSize, af.config.MaxSize)
	}

	if af.config.MinCommits > af.config.MaxCommits && af.config.MaxCommits > 0 {
		return fmt.Errorf("min_commits (%d) cannot be greater than max_commits (%d)", af.config.MinCommits, af.config.MaxCommits)
	}

	if af.config.MinContributors > af.config.MaxContributors && af.config.MaxContributors > 0 {
		return fmt.Errorf("min_contributors (%d) cannot be greater than max_contributors (%d)", af.config.MinContributors, af.config.MaxContributors)
	}

	// Validate age ranges
	if af.config.MinAge != nil && af.config.MaxAge != nil && *af.config.MinAge > *af.config.MaxAge {
		return fmt.Errorf("min_age (%v) cannot be greater than max_age (%v)", *af.config.MinAge, *af.config.MaxAge)
	}

	return nil
}