package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DefaultPullRequestGenerator implements automated pull request generation
type DefaultPullRequestGenerator struct {
	gitProvider   GitProvider
	templateStore TemplateStore
	config        *PRGeneratorConfig
}

// GitProvider interface for Git operations
type GitProvider interface {
	CreateBranch(ctx context.Context, repo *Repository, branchName string, baseBranch string) error
	CommitFiles(ctx context.Context, repo *Repository, branch string, changes []FileChange, message string) error
	CreatePullRequest(ctx context.Context, repo *Repository, pr *PullRequestSpec) (*PRResult, error)
	GetRepository(ctx context.Context, repoURL string) (*Repository, error)
}

// TemplateStore interface for PR templates
type TemplateStore interface {
	GetTemplate(threatType types.ThreatType) (*PRTemplate, error)
	GetCustomTemplate(templateID string) (*PRTemplate, error)
}

// PRGeneratorConfig configuration for PR generation
type PRGeneratorConfig struct {
	DefaultReviewers    []string            `json:"default_reviewers"`
	DefaultAssignees    []string            `json:"default_assignees"`
	BranchPrefix        string              `json:"branch_prefix"`
	AutoMergeEnabled    bool                `json:"auto_merge_enabled"`
	RequireApproval     bool                `json:"require_approval"`
	Labels              map[string][]string `json:"labels"` // threat type -> labels
	DraftPRs            bool                `json:"draft_prs"`
	DeleteBranchOnMerge bool                `json:"delete_branch_on_merge"`
}

// PullRequestSpec specification for creating a pull request
type PullRequestSpec struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	BaseBranch  string   `json:"base_branch"`
	HeadBranch  string   `json:"head_branch"`
	Labels      []string `json:"labels"`
	Assignees   []string `json:"assignees"`
	Reviewers   []string `json:"reviewers"`
	Draft       bool     `json:"draft"`
}

// NewDefaultPullRequestGenerator creates a new PR generator
func NewDefaultPullRequestGenerator(
	gitProvider GitProvider,
	templateStore TemplateStore,
	config *PRGeneratorConfig,
) *DefaultPullRequestGenerator {
	if config == nil {
		config = &PRGeneratorConfig{
			BranchPrefix:        "typosentinel",
			AutoMergeEnabled:    false,
			RequireApproval:     true,
			DraftPRs:            false,
			DeleteBranchOnMerge: true,
			Labels: map[string][]string{
				"typosquatting":        {"security", "typosquatting", "urgent"},
				"malicious":            {"security", "malicious", "critical"},
				"vulnerable":           {"security", "vulnerability", "high-priority"},
				"dependency_confusion": {"security", "dependency-confusion", "urgent"},
				"supply_chain":         {"security", "supply-chain", "medium-priority"},
				"suspicious":           {"security", "suspicious", "review-needed"},
			},
		}
	}

	return &DefaultPullRequestGenerator{
		gitProvider:   gitProvider,
		templateStore: templateStore,
		config:        config,
	}
}

// CreateRemediationPR creates a pull request for remediation
func (g *DefaultPullRequestGenerator) CreateRemediationPR(ctx context.Context, request *PRRequest) (*PRResult, error) {
	// Get repository
	repo := request.Repository
	if repo == nil {
		return nil, fmt.Errorf("repository is required")
	}

	// Generate branch name
	branchName := g.generateBranchName(request.ThreatType, request.Violation)

	// Create branch
	err := g.gitProvider.CreateBranch(ctx, repo, branchName, repo.DefaultBranch)
	if err != nil {
		return nil, fmt.Errorf("failed to create branch: %w", err)
	}

	// Commit changes
	commitMessage := g.generateCommitMessage(request.ThreatType, request.Violation)
	err = g.gitProvider.CommitFiles(ctx, repo, branchName, request.Changes, commitMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to commit changes: %w", err)
	}

	// Get PR template
	template := g.GetPRTemplate(request.ThreatType)

	// Create PR specification
	prSpec := &PullRequestSpec{
		Title:       g.generatePRTitle(request, template),
		Description: g.generatePRDescription(request, template),
		BaseBranch:  repo.DefaultBranch,
		HeadBranch:  branchName,
		Labels:      g.getPRLabels(request.ThreatType),
		Assignees:   g.getPRAssignees(request),
		Reviewers:   g.getPRReviewers(request),
		Draft:       g.config.DraftPRs,
	}

	// Create pull request
	result, err := g.gitProvider.CreatePullRequest(ctx, repo, prSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create pull request: %w", err)
	}

	return result, nil
}

// GetPRTemplate returns a PR template for the given threat type
func (g *DefaultPullRequestGenerator) GetPRTemplate(threatType types.ThreatType) *PRTemplate {
	// Try to get from template store first
	if g.templateStore != nil {
		if template, err := g.templateStore.GetTemplate(threatType); err == nil {
			return template
		}
	}

	// Fall back to default templates
	return g.getDefaultTemplate(threatType)
}

// Helper methods

func (g *DefaultPullRequestGenerator) generateBranchName(threatType types.ThreatType, violation *auth.PolicyViolation) string {
	timestamp := time.Now().Format("20060102-150405")
	packageName := "unknown"

	if violation.Metadata != nil {
		if name, ok := violation.Metadata["package_name"].(string); ok {
			packageName = strings.ReplaceAll(name, "/", "-")
		}
	}

	return fmt.Sprintf("%s/%s/%s-%s", g.config.BranchPrefix, threatType, packageName, timestamp)
}

func (g *DefaultPullRequestGenerator) generateCommitMessage(threatType types.ThreatType, violation *auth.PolicyViolation) string {
	packageName := "unknown package"
	if violation.Metadata != nil {
		if name, ok := violation.Metadata["package_name"].(string); ok {
			packageName = name
		}
	}

	switch threatType {
	case types.ThreatTypeTyposquatting:
		return fmt.Sprintf("security: replace typosquatting package %s", packageName)
	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return fmt.Sprintf("security: remove malicious package %s", packageName)
	case types.ThreatTypeVulnerable:
		return fmt.Sprintf("security: update vulnerable package %s", packageName)
	case types.ThreatTypeDependencyConfusion:
		return fmt.Sprintf("security: fix dependency confusion for %s", packageName)
	case types.ThreatTypeSupplyChainRisk, types.ThreatTypeSupplyChain:
		return fmt.Sprintf("security: mitigate supply chain risk in %s", packageName)
	default:
		return fmt.Sprintf("security: remediate threat in %s", packageName)
	}
}

func (g *DefaultPullRequestGenerator) generatePRTitle(request *PRRequest, template *PRTemplate) string {
	if request.Title != "" {
		return request.Title
	}

	if template != nil && template.Title != "" {
		return g.interpolateTemplate(template.Title, request)
	}

	// Default title generation
	packageName := "unknown package"
	if request.Violation.Metadata != nil {
		if name, ok := request.Violation.Metadata["package_name"].(string); ok {
			packageName = name
		}
	}

	switch request.ThreatType {
	case types.ThreatTypeTyposquatting:
		return fmt.Sprintf("🔒 Security: Replace typosquatting package %s", packageName)
	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return fmt.Sprintf("🚨 Security: Remove malicious package %s", packageName)
	case types.ThreatTypeVulnerable:
		return fmt.Sprintf("🔧 Security: Update vulnerable package %s", packageName)
	case types.ThreatTypeDependencyConfusion:
		return fmt.Sprintf("⚠️ Security: Fix dependency confusion for %s", packageName)
	case types.ThreatTypeSupplyChainRisk, types.ThreatTypeSupplyChain:
		return fmt.Sprintf("🔗 Security: Mitigate supply chain risk in %s", packageName)
	default:
		return fmt.Sprintf("🛡️ Security: Remediate threat in %s", packageName)
	}
}

func (g *DefaultPullRequestGenerator) generatePRDescription(request *PRRequest, template *PRTemplate) string {
	if request.Description != "" {
		return request.Description
	}

	if template != nil && template.Description != "" {
		return g.interpolateTemplate(template.Description, request)
	}

	// Default description generation
	return g.getDefaultDescription(request)
}

func (g *DefaultPullRequestGenerator) getDefaultDescription(request *PRRequest) string {
	packageName := "unknown"
	packageVersion := "unknown"
	threatDescription := "Security threat detected"

	if request.Violation.Metadata != nil {
		if name, ok := request.Violation.Metadata["package_name"].(string); ok {
			packageName = name
		}
		if version, ok := request.Violation.Metadata["package_version"].(string); ok {
			packageVersion = version
		}
		if desc, ok := request.Violation.Metadata["threat_description"].(string); ok {
			threatDescription = desc
		}
	}

	var description strings.Builder

	description.WriteString("## 🔒 Security Remediation\n\n")
	description.WriteString(fmt.Sprintf("**Threat Type:** %s\n", request.ThreatType))
	description.WriteString(fmt.Sprintf("**Package:** %s@%s\n", packageName, packageVersion))
	description.WriteString(fmt.Sprintf("**Description:** %s\n\n", threatDescription))

	switch request.ThreatType {
	case types.ThreatTypeTyposquatting:
		description.WriteString("### 🎯 Typosquatting Detected\n\n")
		description.WriteString("This package appears to be a typosquatting attempt targeting a legitimate package.\n\n")
		description.WriteString("**Actions taken:**\n")
		description.WriteString("- ✅ Identified legitimate alternative\n")
		description.WriteString("- ✅ Updated dependency references\n")
		description.WriteString("- ✅ Verified compatibility\n\n")

	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		description.WriteString("### 🚨 Malicious Package Detected\n\n")
		description.WriteString("This package has been identified as malicious and poses a security risk.\n\n")
		description.WriteString("**Actions taken:**\n")
		description.WriteString("- ✅ Package quarantined\n")
		description.WriteString("- ✅ Removed from dependencies\n")
		description.WriteString("- ✅ Security team notified\n\n")

	case types.ThreatTypeVulnerable:
		description.WriteString("### 🔧 Vulnerability Remediation\n\n")
		description.WriteString("This package contains known security vulnerabilities.\n\n")
		description.WriteString("**Actions taken:**\n")
		description.WriteString("- ✅ Identified safe version\n")
		description.WriteString("- ✅ Updated to patched version\n")
		description.WriteString("- ✅ Verified compatibility\n\n")

	case types.ThreatTypeDependencyConfusion:
		description.WriteString("### ⚠️ Dependency Confusion Attack\n\n")
		description.WriteString("This package may be part of a dependency confusion attack.\n\n")
		description.WriteString("**Actions taken:**\n")
		description.WriteString("- ✅ Verified package source\n")
		description.WriteString("- ✅ Updated to legitimate package\n")
		description.WriteString("- ✅ Added registry restrictions\n\n")

	default:
		description.WriteString("### 🛡️ Security Threat Remediation\n\n")
		description.WriteString("A security threat has been detected and remediated.\n\n")
	}

	description.WriteString("### 📋 Review Checklist\n\n")
	description.WriteString("- [ ] Verify the changes are correct\n")
	description.WriteString("- [ ] Run security scans\n")
	description.WriteString("- [ ] Test application functionality\n")
	description.WriteString("- [ ] Update documentation if needed\n\n")

	description.WriteString("### 🤖 Automated Remediation\n\n")
	description.WriteString("This pull request was automatically generated by TypoSentinel's remediation engine.\n")
	description.WriteString("Please review the changes carefully before merging.\n\n")

	description.WriteString("---\n")
	description.WriteString("*Generated by TypoSentinel Security Remediation Engine*")

	return description.String()
}

func (g *DefaultPullRequestGenerator) getPRLabels(threatType types.ThreatType) []string {
	if labels, ok := g.config.Labels[string(threatType)]; ok {
		return labels
	}
	return []string{"security", "automated"}
}

func (g *DefaultPullRequestGenerator) getPRAssignees(request *PRRequest) []string {
	if len(request.Assignees) > 0 {
		return request.Assignees
	}
	return g.config.DefaultAssignees
}

func (g *DefaultPullRequestGenerator) getPRReviewers(request *PRRequest) []string {
	if len(request.Reviewers) > 0 {
		return request.Reviewers
	}
	return g.config.DefaultReviewers
}

func (g *DefaultPullRequestGenerator) interpolateTemplate(template string, request *PRRequest) string {
	// Simple template interpolation
	result := template

	if request.Violation.Metadata != nil {
		for key, value := range request.Violation.Metadata {
			placeholder := fmt.Sprintf("{{%s}}", key)
			if str, ok := value.(string); ok {
				result = strings.ReplaceAll(result, placeholder, str)
			}
		}
	}

	// Replace common placeholders
	result = strings.ReplaceAll(result, "{{threat_type}}", string(request.ThreatType))
	result = strings.ReplaceAll(result, "{{timestamp}}", time.Now().Format("2006-01-02 15:04:05"))

	return result
}

func (g *DefaultPullRequestGenerator) getDefaultTemplate(threatType types.ThreatType) *PRTemplate {
	switch threatType {
	case types.ThreatTypeTyposquatting:
		return &PRTemplate{
			Title:       "🔒 Security: Replace typosquatting package {{package_name}}",
			Description: "Automated remediation for typosquatting threat in {{package_name}}",
			Labels:      []string{"security", "typosquatting", "urgent"},
		}

	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return &PRTemplate{
			Title:       "🚨 Security: Remove malicious package {{package_name}}",
			Description: "Automated remediation for malicious package {{package_name}}",
			Labels:      []string{"security", "malicious", "critical"},
		}

	case types.ThreatTypeVulnerable:
		return &PRTemplate{
			Title:       "🔧 Security: Update vulnerable package {{package_name}}",
			Description: "Automated security update for vulnerable package {{package_name}}",
			Labels:      []string{"security", "vulnerability", "high-priority"},
		}

	default:
		return &PRTemplate{
			Title:       "🛡️ Security: Remediate threat in {{package_name}}",
			Description: "Automated security remediation for {{package_name}}",
			Labels:      []string{"security", "automated"},
		}
	}
}

// DefaultTemplateStore provides default PR templates
type DefaultTemplateStore struct {
	templates map[types.ThreatType]*PRTemplate
}

// NewDefaultTemplateStore creates a new template store
func NewDefaultTemplateStore() *DefaultTemplateStore {
	return &DefaultTemplateStore{
		templates: make(map[types.ThreatType]*PRTemplate),
	}
}

// GetTemplate returns a template for the given threat type
func (s *DefaultTemplateStore) GetTemplate(threatType types.ThreatType) (*PRTemplate, error) {
	if template, ok := s.templates[threatType]; ok {
		return template, nil
	}
	return nil, fmt.Errorf("template not found for threat type: %s", threatType)
}

// GetCustomTemplate returns a custom template by ID
func (s *DefaultTemplateStore) GetCustomTemplate(templateID string) (*PRTemplate, error) {
	return nil, fmt.Errorf("custom template not found: %s", templateID)
}

// SetTemplate sets a template for a threat type
func (s *DefaultTemplateStore) SetTemplate(threatType types.ThreatType, template *PRTemplate) {
	s.templates[threatType] = template
}
