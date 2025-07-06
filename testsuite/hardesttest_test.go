package testsuite

import "testing"

// TestRunAdvancedTestSuite is a proper Go test function that runs the advanced test suite
func TestRunAdvancedTestSuite(t *testing.T) {
	suite := NewAdvancedTestSuite()

	t.Log("🚀 Starting Advanced Real-World Security Test Suite for Typosentinel...")

	// Run all advanced test categories
	suite.TestAdvancedTyposquattingAttacks(t)
	suite.TestDependencyConfusionAttacks(t)
	suite.TestEnterpriseSecurityScenarios(t)
	suite.TestAdvancedMLEvasion(t)
	suite.TestStressAndPerformance(t)
	suite.TestZeroDaySimulation(t)

	// Generate comprehensive report
	suite.GenerateComprehensiveReport()
}