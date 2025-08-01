// Jenkins Pipeline Template for Typosentinel
// This template provides automated security scanning for your repositories

pipeline {
    agent any
    
    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['full', 'incremental', 'targeted'],
            description: 'Type of scan to perform'
        )
        choice(
            name: 'SEVERITY_THRESHOLD',
            choices: ['low', 'medium', 'high', 'critical'],
            description: 'Minimum severity level to report'
        )
        booleanParam(
            name: 'BLOCK_ON_CRITICAL',
            defaultValue: true,
            description: 'Block pipeline on critical threats'
        )
        booleanParam(
            name: 'CREATE_JIRA_ISSUES',
            defaultValue: false,
            description: 'Create JIRA issues for critical threats'
        )
    }
    
    environment {
        TYPOSENTINEL_API_URL = credentials('typosentinel-api-url') ?: 'https://api.typosentinel.com'
        TYPOSENTINEL_API_KEY = credentials('typosentinel-api-key')
        SCAN_TIMEOUT = '1800'
        RESULTS_DIR = 'typosentinel-results'
        NODE_VERSION = '20'
    }
    
    options {
        timeout(time: 45, unit: 'MINUTES')
        retry(2)
        skipStagesAfterUnstable()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
    }
    
    tools {
        nodejs "${NODE_VERSION}"
    }
    
    stages {
        stage('Preparation') {
            steps {
                script {
                    echo "🔧 Preparing Typosentinel scan environment"
                    
                    // Clean workspace
                    cleanWs()
                    
                    // Checkout code
                    checkout scm
                    
                    // Install dependencies
                    sh '''
                        npm ci --audit=false
                        npm install -g @typosentinel/cli
                        mkdir -p ${RESULTS_DIR}
                    '''
                    
                    // Create configuration
                    writeFile file: '.typosentinel.yml', text: """
api:
  url: ${env.TYPOSENTINEL_API_URL}
  key: ${env.TYPOSENTINEL_API_KEY}
  timeout: ${env.SCAN_TIMEOUT}

scan:
  type: ${params.SCAN_TYPE}
  severity_threshold: ${params.SEVERITY_THRESHOLD}
  include_dev_dependencies: true
  max_depth: 5
  parallel_scans: 4

reporting:
  formats:
    - json
    - junit
    - html
  output_dir: ./${env.RESULTS_DIR}
  upload_artifacts: true

policies:
  block_on_critical: ${params.BLOCK_ON_CRITICAL}
  block_on_high: false
  require_approval_on_medium: true
  auto_quarantine: true

integrations:
  jenkins:
    create_build_status: true
    archive_artifacts: true
    publish_test_results: true
  jira:
    create_issues: ${params.CREATE_JIRA_ISSUES}
    project_key: SEC
  slack:
    webhook_url: ${env.SLACK_WEBHOOK_URL}
    notify_on_threats: true
"""
                }
            }
        }
        
        stage('Security Scan') {
            parallel {
                stage('Full Scan') {
                    when {
                        anyOf {
                            expression { params.SCAN_TYPE == 'full' }
                            branch 'main'
                            branch 'master'
                        }
                    }
                    steps {
                        script {
                            echo "🔍 Starting full Typosentinel security scan"
                            
                            def scanResult = sh(
                                script: """
                                    typosentinel scan \
                                        --config .typosentinel.yml \
                                        --type full \
                                        --output-format json,junit,html \
                                        --output-dir ${env.RESULTS_DIR} \
                                        --verbose || echo "SCAN_FAILED=true"
                                """,
                                returnStatus: true
                            )
                            
                            env.SCAN_EXIT_CODE = scanResult
                            
                            // Parse results
                            if (fileExists("${env.RESULTS_DIR}/scan-results.json")) {
                                def results = readJSON file: "${env.RESULTS_DIR}/scan-results.json"
                                env.THREAT_COUNT = results.summary?.total_threats ?: 0
                                env.CRITICAL_COUNT = results.summary?.critical_threats ?: 0
                                env.HIGH_COUNT = results.summary?.high_threats ?: 0
                                env.MEDIUM_COUNT = results.summary?.medium_threats ?: 0
                                env.LOW_COUNT = results.summary?.low_threats ?: 0
                                
                                if (env.CRITICAL_COUNT.toInteger() > 0) {
                                    env.SCAN_STATUS = 'failed'
                                    echo "❌ Critical security threats detected!"
                                } else if (env.HIGH_COUNT.toInteger() > 0) {
                                    env.SCAN_STATUS = 'warning'
                                    echo "⚠️ High severity threats detected"
                                } else {
                                    env.SCAN_STATUS = 'passed'
                                    echo "✅ No critical threats detected"
                                }
                            } else {
                                env.SCAN_STATUS = 'error'
                                echo "❌ Scan failed to complete"
                            }
                        }
                    }
                }
                
                stage('Incremental Scan') {
                    when {
                        anyOf {
                            expression { params.SCAN_TYPE == 'incremental' }
                            changeRequest()
                        }
                    }
                    steps {
                        script {
                            echo "🔍 Starting incremental Typosentinel security scan"
                            
                            def baseRef = env.CHANGE_TARGET ?: 'main'
                            def headRef = env.GIT_COMMIT
                            
                            def scanResult = sh(
                                script: """
                                    typosentinel scan \
                                        --config .typosentinel.yml \
                                        --type incremental \
                                        --base-ref origin/${baseRef} \
                                        --head-ref ${headRef} \
                                        --output-format json,junit,html \
                                        --output-dir ${env.RESULTS_DIR} \
                                        --verbose || echo "SCAN_FAILED=true"
                                """,
                                returnStatus: true
                            )
                            
                            env.SCAN_EXIT_CODE = scanResult
                            
                            // Parse results
                            if (fileExists("${env.RESULTS_DIR}/scan-results.json")) {
                                def results = readJSON file: "${env.RESULTS_DIR}/scan-results.json"
                                env.THREAT_COUNT = results.summary?.total_threats ?: 0
                                env.CRITICAL_COUNT = results.summary?.critical_threats ?: 0
                                env.HIGH_COUNT = results.summary?.high_threats ?: 0
                                
                                if (env.CRITICAL_COUNT.toInteger() > 0) {
                                    env.SCAN_STATUS = 'failed'
                                    echo "❌ Critical security threats detected in PR!"
                                    if (params.BLOCK_ON_CRITICAL) {
                                        error("Critical threats detected - blocking pipeline")
                                    }
                                } else if (env.HIGH_COUNT.toInteger() > 0) {
                                    env.SCAN_STATUS = 'warning'
                                    echo "⚠️ High severity threats detected in PR"
                                } else {
                                    env.SCAN_STATUS = 'passed'
                                    echo "✅ No critical threats detected in PR"
                                }
                            } else {
                                env.SCAN_STATUS = 'error'
                                echo "❌ Incremental scan failed to complete"
                                error("Scan failed to complete")
                            }
                        }
                    }
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                script {
                    echo "📊 Generating comprehensive security reports"
                    
                    // Generate HTML report
                    writeFile file: "${env.RESULTS_DIR}/security-report.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Typosentinel Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .status-passed { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-failed { color: #dc3545; }
        .threat-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .threat-table th, .threat-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .threat-table th { background-color: #f2f2f2; }
        .critical { background-color: #f8d7da; }
        .high { background-color: #fff3cd; }
        .medium { background-color: #d1ecf1; }
        .low { background-color: #d4edda; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Typosentinel Security Report</h1>
        <p><strong>Job:</strong> ${env.JOB_NAME}</p>
        <p><strong>Build:</strong> <a href="${env.BUILD_URL}">#${env.BUILD_NUMBER}</a></p>
        <p><strong>Branch:</strong> ${env.GIT_BRANCH}</p>
        <p><strong>Commit:</strong> ${env.GIT_COMMIT}</p>
        <p><strong>Scan Date:</strong> ${new Date()}</p>
        <p><strong>Status:</strong> <span class="status-${env.SCAN_STATUS}">${env.SCAN_STATUS?.toUpperCase()}</span></p>
    </div>
    
    <h2>📊 Threat Summary</h2>
    <table class="threat-table">
        <tr><th>Severity</th><th>Count</th></tr>
        <tr class="critical"><td>Critical</td><td>${env.CRITICAL_COUNT ?: 0}</td></tr>
        <tr class="high"><td>High</td><td>${env.HIGH_COUNT ?: 0}</td></tr>
        <tr class="medium"><td>Medium</td><td>${env.MEDIUM_COUNT ?: 0}</td></tr>
        <tr class="low"><td>Low</td><td>${env.LOW_COUNT ?: 0}</td></tr>
        <tr><td><strong>Total</strong></td><td><strong>${env.THREAT_COUNT ?: 0}</strong></td></tr>
    </table>
    
    <h2>📋 Detailed Results</h2>
    <p>For detailed scan results, please check the build artifacts or view the JSON report.</p>
    
    <footer>
        <p><em>Generated by <a href="https://typosentinel.com">Typosentinel</a></em></p>
    </footer>
</body>
</html>
"""
                    
                    // Generate Jenkins summary
                    def summaryText = """
🛡️ **Typosentinel Security Scan Results**

**Status:** ${env.SCAN_STATUS == 'passed' ? '✅ Passed' : env.SCAN_STATUS == 'warning' ? '⚠️ Warning' : '❌ Failed'}
**Total Threats:** ${env.THREAT_COUNT ?: 0}

| Severity | Count |
|----------|-------|
| Critical | ${env.CRITICAL_COUNT ?: 0} |
| High | ${env.HIGH_COUNT ?: 0} |
| Medium | ${env.MEDIUM_COUNT ?: 0} |
| Low | ${env.LOW_COUNT ?: 0} |

${env.CRITICAL_COUNT?.toInteger() > 0 ? '🚨 **Critical threats detected!** This build should not be deployed until resolved.' : ''}
${env.HIGH_COUNT?.toInteger() > 0 ? '⚠️ **High severity threats detected.** Please review before deployment.' : ''}

---
*Scan performed by [Typosentinel](https://typosentinel.com) at ${new Date()}*
"""
                    
                    writeFile file: "${env.RESULTS_DIR}/jenkins-summary.md", text: summaryText
                    
                    // Set build description
                    currentBuild.description = "Threats: ${env.THREAT_COUNT ?: 0} (${env.CRITICAL_COUNT ?: 0} critical)"
                }
            }
        }
        
        stage('Publish Results') {
            parallel {
                stage('Archive Artifacts') {
                    steps {
                        script {
                            echo "📦 Archiving scan artifacts"
                            
                            archiveArtifacts artifacts: "${env.RESULTS_DIR}/**/*", allowEmptyArchive: true
                            
                            // Publish test results if available
                            if (fileExists("${env.RESULTS_DIR}/junit-report.xml")) {
                                publishTestResults testResultsPattern: "${env.RESULTS_DIR}/junit-report.xml"
                            }
                            
                            // Publish HTML reports
                            publishHTML([
                                allowMissing: false,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: env.RESULTS_DIR,
                                reportFiles: 'security-report.html',
                                reportName: 'Typosentinel Security Report',
                                reportTitles: 'Security Scan Results'
                            ])
                        }
                    }
                }
                
                stage('Update Build Status') {
                    steps {
                        script {
                            echo "📊 Updating build status"
                            
                            def status = 'SUCCESS'
                            def message = 'No threats detected'
                            
                            if (env.SCAN_STATUS == 'failed') {
                                status = 'FAILURE'
                                message = "${env.CRITICAL_COUNT} critical threats detected"
                            } else if (env.SCAN_STATUS == 'warning') {
                                status = 'UNSTABLE'
                                message = "${env.THREAT_COUNT} threats detected (review recommended)"
                            } else if (env.SCAN_STATUS == 'error') {
                                status = 'FAILURE'
                                message = 'Scan failed to complete'
                            }
                            
                            currentBuild.result = status
                            
                            // Add badge
                            if (env.CRITICAL_COUNT?.toInteger() > 0) {
                                addBadge icon: 'error.gif', text: "${env.CRITICAL_COUNT} Critical Threats"
                            } else if (env.HIGH_COUNT?.toInteger() > 0) {
                                addBadge icon: 'warning.gif', text: "${env.HIGH_COUNT} High Threats"
                            } else {
                                addBadge icon: 'green.gif', text: 'Security Scan Passed'
                            }
                        }
                    }
                }
            }
        }
        
        stage('Notifications') {
            parallel {
                stage('Slack Notification') {
                    when {
                        expression { env.SLACK_WEBHOOK_URL != null }
                    }
                    steps {
                        script {
                            echo "📢 Sending Slack notification"
                            
                            def color = 'good'
                            if (env.SCAN_STATUS == 'failed') {
                                color = 'danger'
                            } else if (env.SCAN_STATUS == 'warning') {
                                color = 'warning'
                            }
                            
                            slackSend(
                                channel: '#security',
                                color: color,
                                message: """
🛡️ *Typosentinel Security Scan Results*

*Job:* ${env.JOB_NAME}
*Build:* <${env.BUILD_URL}|#${env.BUILD_NUMBER}>
*Branch:* ${env.GIT_BRANCH}
*Status:* ${env.SCAN_STATUS?.toUpperCase()}
*Threats:* ${env.THREAT_COUNT ?: 0} total, ${env.CRITICAL_COUNT ?: 0} critical

${env.CRITICAL_COUNT?.toInteger() > 0 ? '🚨 Critical threats detected!' : env.HIGH_COUNT?.toInteger() > 0 ? '⚠️ High severity threats detected' : '✅ No critical threats detected'}
"""
                            )
                        }
                    }
                }
                
                stage('Email Notification') {
                    when {
                        anyOf {
                            expression { env.SCAN_STATUS == 'failed' }
                            expression { env.SCAN_STATUS == 'error' }
                        }
                    }
                    steps {
                        script {
                            echo "📧 Sending email notification"
                            
                            emailext(
                                subject: "🚨 Typosentinel Security Alert - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                                body: """
<h2>🛡️ Typosentinel Security Scan Alert</h2>

<p><strong>Critical security threats have been detected in your build.</strong></p>

<h3>Build Details:</h3>
<ul>
    <li><strong>Job:</strong> ${env.JOB_NAME}</li>
    <li><strong>Build:</strong> <a href="${env.BUILD_URL}">#${env.BUILD_NUMBER}</a></li>
    <li><strong>Branch:</strong> ${env.GIT_BRANCH}</li>
    <li><strong>Commit:</strong> ${env.GIT_COMMIT}</li>
</ul>

<h3>Threat Summary:</h3>
<ul>
    <li><strong>Total Threats:</strong> ${env.THREAT_COUNT ?: 0}</li>
    <li><strong>Critical:</strong> ${env.CRITICAL_COUNT ?: 0}</li>
    <li><strong>High:</strong> ${env.HIGH_COUNT ?: 0}</li>
    <li><strong>Medium:</strong> ${env.MEDIUM_COUNT ?: 0}</li>
    <li><strong>Low:</strong> ${env.LOW_COUNT ?: 0}</li>
</ul>

<p><strong>Immediate action required:</strong> Please review the scan results and address all critical threats before deploying to production.</p>

<p>View the full report: <a href="${env.BUILD_URL}Typosentinel_Security_Report/">Security Report</a></p>

<p><em>This alert was automatically generated by Typosentinel security scanning.</em></p>
""",
                                to: '${env.SECURITY_TEAM_EMAIL}',
                                mimeType: 'text/html'
                            )
                        }
                    }
                }
            }
        }
        
        stage('Security Policy Enforcement') {
            when {
                expression { env.CRITICAL_COUNT?.toInteger() > 0 }
            }
            steps {
                script {
                    echo "🚨 Enforcing security policy for critical threats"
                    
                    // Create JIRA issue if enabled
                    if (params.CREATE_JIRA_ISSUES) {
                        def issueData = [
                            fields: [
                                project: [key: 'SEC'],
                                summary: "🚨 Critical Security Threats - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                                description: """
Critical security threats detected by Typosentinel:

*Build Details:*
- Job: ${env.JOB_NAME}
- Build: ${env.BUILD_URL}
- Branch: ${env.GIT_BRANCH}
- Commit: ${env.GIT_COMMIT}

*Threat Summary:*
- Total threats: ${env.THREAT_COUNT}
- Critical threats: ${env.CRITICAL_COUNT}

*Action Required:*
- Review scan results immediately
- Address all critical threats
- Do not deploy to production until resolved

View full report: ${env.BUILD_URL}Typosentinel_Security_Report/
""",
                                issuetype: [name: 'Bug'],
                                priority: [name: 'Critical'],
                                labels: ['security', 'typosentinel', 'critical']
                            ]
                        ]
                        
                        // This would require JIRA plugin configuration
                        echo "Would create JIRA issue: ${issueData}"
                    }
                    
                    // Block deployment if configured
                    if (params.BLOCK_ON_CRITICAL) {
                        echo "❌ Blocking pipeline due to critical threats"
                        error("Critical security threats detected - pipeline blocked")
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo "🧹 Cleaning up scan environment"
                
                // Clean up sensitive files
                sh "rm -f .typosentinel.yml"
                
                // Archive final status
                writeFile file: 'scan-status.txt', text: """
Scan Status: ${env.SCAN_STATUS}
Total Threats: ${env.THREAT_COUNT ?: 0}
Critical Threats: ${env.CRITICAL_COUNT ?: 0}
High Threats: ${env.HIGH_COUNT ?: 0}
Scan Date: ${new Date()}
Build: ${env.BUILD_NUMBER}
"""
                
                archiveArtifacts artifacts: 'scan-status.txt', allowEmptyArchive: true
            }
        }
        
        success {
            echo "✅ Pipeline completed successfully"
        }
        
        failure {
            echo "❌ Pipeline failed"
        }
        
        unstable {
            echo "⚠️ Pipeline completed with warnings"
        }
        
        cleanup {
            // Clean workspace
            cleanWs()
        }
    }
}

// Helper functions
def getChangeTarget() {
    if (env.CHANGE_TARGET) {
        return env.CHANGE_TARGET
    }
    return 'main'
}

def shouldBlockOnThreats() {
    return params.BLOCK_ON_CRITICAL && env.CRITICAL_COUNT?.toInteger() > 0
}

def getScanSummary() {
    return "Threats: ${env.THREAT_COUNT ?: 0} (${env.CRITICAL_COUNT ?: 0} critical, ${env.HIGH_COUNT ?: 0} high)"
}