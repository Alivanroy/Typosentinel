package events

import (
	"context"
	"time"
)

// EventType represents the type of security event
type EventType string

const (
	EventTypeThreatDetected  EventType = "threat_detected"
	EventTypePackageBlocked  EventType = "package_blocked"
	EventTypePolicyViolation EventType = "policy_violation"
	EventTypeSystemAlert     EventType = "system_alert"
)

// Severity represents the severity level of an event
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SecurityEvent represents a security event in the system
type SecurityEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      EventType         `json:"type"`
	Severity  Severity          `json:"severity"`
	Source    string            `json:"source"`
	Package   PackageInfo       `json:"package"`
	Threat    ThreatInfo        `json:"threat"`
	Metadata  EventMetadata     `json:"metadata"`
	Context   map[string]string `json:"context,omitempty"`
}

// PackageInfo contains information about the package involved in the event
type PackageInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Registry string `json:"registry"`
	Hash     string `json:"hash,omitempty"`
	Path     string `json:"path,omitempty"`
}

// ThreatInfo contains information about the detected threat
type ThreatInfo struct {
	Type        string            `json:"type"`
	Confidence  float64           `json:"confidence"`
	RiskScore   float64           `json:"risk_score"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Mitigations []string          `json:"mitigations,omitempty"`
}

// EventMetadata contains additional metadata about the event
type EventMetadata struct {
	DetectionMethod string            `json:"detection_method"`
	Tags           []string          `json:"tags,omitempty"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
}

// EventSubscriber defines the interface for event subscribers
type EventSubscriber interface {
	Handle(ctx context.Context, event *SecurityEvent) error
	GetID() string
}

// EventFilter defines criteria for filtering events
type EventFilter struct {
	EventTypes   []EventType `json:"event_types,omitempty"`
	MinSeverity  Severity    `json:"min_severity,omitempty"`
	Sources      []string    `json:"sources,omitempty"`
	ThreatTypes  []string    `json:"threat_types,omitempty"`
	PackageNames []string    `json:"package_names,omitempty"`
}

// MatchesFilter checks if an event matches the given filter criteria
func (e *SecurityEvent) MatchesFilter(filter *EventFilter) bool {
	if filter == nil {
		return true
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if e.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check minimum severity
	if filter.MinSeverity != "" {
		if !e.meetsSeverityThreshold(filter.MinSeverity) {
			return false
		}
	}

	// Check sources
	if len(filter.Sources) > 0 {
		found := false
		for _, source := range filter.Sources {
			if e.Source == source {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check threat types
	if len(filter.ThreatTypes) > 0 {
		found := false
		for _, threatType := range filter.ThreatTypes {
			if e.Threat.Type == threatType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check package names
	if len(filter.PackageNames) > 0 {
		found := false
		for _, packageName := range filter.PackageNames {
			if e.Package.Name == packageName {
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

// meetsSeverityThreshold checks if the event severity meets the minimum threshold
func (e *SecurityEvent) meetsSeverityThreshold(minSeverity Severity) bool {
	severityLevels := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}

	eventLevel, exists := severityLevels[e.Severity]
	if !exists {
		return false
	}

	minLevel, exists := severityLevels[minSeverity]
	if !exists {
		return false
	}

	return eventLevel >= minLevel
}