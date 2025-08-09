package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryViolationStore is a simple in-memory implementation of ViolationStore
type MemoryViolationStore struct {
	violations map[string]*PolicyViolation
	mu         sync.RWMutex
}

// NewMemoryViolationStore creates a new in-memory violation store
func NewMemoryViolationStore() *MemoryViolationStore {
	return &MemoryViolationStore{
		violations: make(map[string]*PolicyViolation),
	}
}

// CreateViolation stores a new policy violation
func (mvs *MemoryViolationStore) CreateViolation(ctx context.Context, violation *PolicyViolation) error {
	if violation == nil {
		return fmt.Errorf("violation cannot be nil")
	}
	
	if violation.ID == "" {
		return fmt.Errorf("violation ID cannot be empty")
	}

	mvs.mu.Lock()
	defer mvs.mu.Unlock()

	// Check if violation already exists
	if _, exists := mvs.violations[violation.ID]; exists {
		return fmt.Errorf("violation with ID %s already exists", violation.ID)
	}

	// Store the violation
	mvs.violations[violation.ID] = violation
	return nil
}

// GetViolation retrieves a policy violation by ID
func (mvs *MemoryViolationStore) GetViolation(ctx context.Context, id string) (*PolicyViolation, error) {
	if id == "" {
		return nil, fmt.Errorf("violation ID cannot be empty")
	}

	mvs.mu.RLock()
	defer mvs.mu.RUnlock()

	violation, exists := mvs.violations[id]
	if !exists {
		return nil, fmt.Errorf("violation with ID %s not found", id)
	}

	return violation, nil
}

// UpdateViolationStatus updates the status of a policy violation
func (mvs *MemoryViolationStore) UpdateViolationStatus(ctx context.Context, id string, status ViolationStatus, userID string, reason string) error {
	if id == "" {
		return fmt.Errorf("violation ID cannot be empty")
	}

	mvs.mu.Lock()
	defer mvs.mu.Unlock()

	violation, exists := mvs.violations[id]
	if !exists {
		return fmt.Errorf("violation with ID %s not found", id)
	}

	// Update the violation status
	violation.Status = status
	
	// Add approval record if this is an approval/rejection
	if status == ViolationStatusApproved || status == ViolationStatusRejected {
		approval := PolicyApproval{
			ID:         fmt.Sprintf("approval-%d", time.Now().UnixNano()),
			ApproverID: userID,
			Approver:   userID, // In a real implementation, this would be the user's name
			Decision:   string(status),
			Reason:     reason,
			ApprovedAt: time.Now(),
		}
		violation.Approvals = append(violation.Approvals, approval)
	}

	// Set resolved time if the violation is resolved
	if status == ViolationStatusApproved || status == ViolationStatusRejected || 
	   status == ViolationStatusRemediated || status == ViolationStatusIgnored {
		now := time.Now()
		violation.ResolvedAt = &now
	}

	return nil
}

// ListViolations returns all violations (helper method for testing/debugging)
func (mvs *MemoryViolationStore) ListViolations(ctx context.Context) ([]*PolicyViolation, error) {
	mvs.mu.RLock()
	defer mvs.mu.RUnlock()

	violations := make([]*PolicyViolation, 0, len(mvs.violations))
	for _, violation := range mvs.violations {
		violations = append(violations, violation)
	}

	return violations, nil
}

// Clear removes all violations (helper method for testing)
func (mvs *MemoryViolationStore) Clear() {
	mvs.mu.Lock()
	defer mvs.mu.Unlock()
	mvs.violations = make(map[string]*PolicyViolation)
}