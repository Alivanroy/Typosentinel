//go:build realworld

package realworld

import "testing"

func TestRealWorldSuite(t *testing.T){
    TestE2EDevTeamOnboardingNewProject(t)
    TestE2ECICDPipelineIntegration(t)
    TestE2ESecurityIncidentResponse(t)
    TestE2EEnterpriseMultiTeamScanning(t)
    TestE2EFileBasedProjectScanning(t)
    TestE2EWebhookTriggeredScan(t)
}

