// Jenkins Pipeline for TypoSentinel Security Scanning
// This pipeline provides comprehensive security scanning with TypoSentinel
// across different environments and project types.

pipeline {
    agent any
    
    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['quick', 'comprehensive', 'enterprise'],
            description: 'Type of security scan to perform'
        )
        choice(
            name: 'PROJECT_TYPE',
            choices: ['auto-detect', 'nodejs', 'go', 'python', 'java', 'generic'],
            description: 'Project type override (auto-detect recommended)'
        )
        booleanParam(
            name: 'FAIL_ON_HIGH',
            defaultValue: true,
            description: 'Fail pipeline on high/critical severity threats'
        )
        booleanParam(
            name: 'NOTIFY_SECURITY',
            defaultValue: false,
            description: 'Send notifications to security team'
        )
    }
    
    environment {
        TYPOSENTINEL_VERSION = 'latest'
        SCAN_TIMEOUT = '600'
        WORKSPACE_CLEAN = 'true'
        // Security notification settings
        SLACK_WEBHOOK = credentials('slack-security-webhook')
        EMAIL_RECIPIENTS = 'security-team@company.com'
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }
    
    triggers {
        // Daily security scan at 2 AM
        cron('0 2 * * *')
        // Scan on SCM changes for main branches
        pollSCM('H/15 * * * *')
    }
    
    stages {
        stage('🔍 Environment Setup') {
            steps {
                script {
                    echo "🚀 Starting TypoSentinel Security Pipeline"
                    echo "📊 Build: ${env.BUILD_NUMBER}"
                    echo "🌿 Branch: ${env.BRANCH_NAME}"
                    echo "📦 Scan Type: ${params.SCAN_TYPE}"
                    echo "🔧 Project Type: ${params.PROJECT_TYPE}"
                    
                    // Set build description
                    currentBuild.description = "TypoSentinel ${params.SCAN_TYPE} scan"
                    
                    // Clean workspace if needed
                    if (env.WORKSPACE_CLEAN == 'true') {
                        cleanWs()
                    }
                }
            }
        }
        
        stage('📥 Checkout & Prepare') {
            steps {
                checkout scm
                
                script {
                    // Store commit info for reporting
                    env.GIT_COMMIT_SHORT = sh(
                        script: 'git rev-parse --short HEAD',
                        returnStdout: true
                    ).trim()
                    
                    env.GIT_AUTHOR = sh(
                        script: 'git log -1 --pretty=format:"%an"',
                        returnStdout: true
                    ).trim()
                    
                    echo "📝 Commit: ${env.GIT_COMMIT_SHORT}"
                    echo "👤 Author: ${env.GIT_AUTHOR}"
                }
            }
        }
        
        stage('🔍 Project Detection') {
            steps {
                script {
                    echo "🔍 Detecting project type..."
                    
                    def projectType = params.PROJECT_TYPE
                    def scanArgs = ""
                    def excludePatterns = []
                    
                    if (projectType == 'auto-detect') {
                        // Auto-detect project type
                        if (fileExists('package.json')) {
                            projectType = 'nodejs'
                            excludePatterns = ['node_modules/', 'dist/', 'build/']
                        } else if (fileExists('go.mod')) {
                            projectType = 'go'
                            excludePatterns = ['vendor/', 'bin/']
                        } else if (fileExists('requirements.txt') || fileExists('pyproject.toml') || fileExists('setup.py')) {
                            projectType = 'python'
                            excludePatterns = ['__pycache__/', 'venv/', '.venv/', 'dist/', 'build/']
                        } else if (fileExists('pom.xml') || fileExists('build.gradle') || fileExists('build.gradle.kts')) {
                            projectType = 'java'
                            excludePatterns = ['target/', 'build/', '.gradle/']
                        } else if (fileExists('Cargo.toml')) {
                            projectType = 'rust'
                            excludePatterns = ['target/', 'Cargo.lock']
                        } else if (fileExists('composer.json')) {
                            projectType = 'php'
                            excludePatterns = ['vendor/', 'cache/']
                        } else {
                            projectType = 'generic'
                            excludePatterns = ['.git/', 'node_modules/', 'vendor/']
                        }
                    }
                    
                    // Set scan arguments based on project type
                    if (projectType != 'generic') {
                        scanArgs = "--project-type ${projectType}"
                    }
                    
                    // Store for later stages
                    env.DETECTED_PROJECT_TYPE = projectType
                    env.SCAN_ARGS = scanArgs
                    env.EXCLUDE_PATTERNS = excludePatterns.join(',')
                    
                    echo "✅ Project Type: ${projectType}"
                    echo "🔧 Scan Args: ${scanArgs}"
                    echo "🚫 Exclude Patterns: ${excludePatterns.join(', ')}"
                }
            }
        }
        
        stage('📥 Install TypoSentinel') {
            steps {
                script {
                    echo "📥 Installing TypoSentinel..."
                    
                    // Determine architecture
                    def arch = sh(
                        script: 'uname -m',
                        returnStdout: true
                    ).trim()
                    
                    if (arch == 'x86_64') {
                        arch = 'amd64'
                    } else if (arch == 'aarch64') {
                        arch = 'arm64'
                    }
                    
                    // Determine OS
                    def os = 'linux'
                    if (isUnix()) {
                        def osName = sh(
                            script: 'uname -s',
                            returnStdout: true
                        ).trim().toLowerCase()
                        
                        if (osName.contains('darwin')) {
                            os = 'darwin'
                        }
                    } else {
                        os = 'windows'
                        arch = 'amd64'
                    }
                    
                    // Download and install
                    def binaryName = "typosentinel-${os}-${arch}"
                    if (os == 'windows') {
                        binaryName += '.exe'
                    }
                    
                    sh """
                        mkdir -p \${WORKSPACE}/tools
                        curl -L "https://github.com/typosentinel/typosentinel/releases/latest/download/${binaryName}" \\
                             -o \${WORKSPACE}/tools/typosentinel
                        chmod +x \${WORKSPACE}/tools/typosentinel
                        
                        # Verify installation
                        \${WORKSPACE}/tools/typosentinel version
                    """
                    
                    env.TYPOSENTINEL_PATH = "${env.WORKSPACE}/tools/typosentinel"
                }
            }
        }
        
        stage('🛡️ Security Scan') {
            steps {
                script {
                    echo "🛡️ Running TypoSentinel security scan..."
                    
                    // Build scan command
                    def scanCmd = "${env.TYPOSENTINEL_PATH} scan"
                    
                    // Add preset
                    scanCmd += " --preset ${params.SCAN_TYPE}"
                    
                    // Add project-specific arguments
                    if (env.SCAN_ARGS) {
                        scanCmd += " ${env.SCAN_ARGS}"
                    }
                    
                    // Add exclude patterns
                    if (env.EXCLUDE_PATTERNS) {
                        def patterns = env.EXCLUDE_PATTERNS.split(',')
                        patterns.each { pattern ->
                            scanCmd += " --exclude ${pattern.trim()}"
                        }
                    }
                    
                    // Add output options
                    scanCmd += " --output json --output-file typosentinel-results.json"
                    scanCmd += " --output sarif --output-file typosentinel-results.sarif"
                    scanCmd += " --output table --output-file typosentinel-report.txt"
                    scanCmd += " --timeout ${env.SCAN_TIMEOUT}s"
                    scanCmd += " --verbose"
                    
                    echo "🔧 Executing: ${scanCmd}"
                    
                    // Run scan with timeout
                    timeout(time: Integer.parseInt(env.SCAN_TIMEOUT), unit: 'SECONDS') {
                        def exitCode = sh(
                            script: scanCmd,
                            returnStatus: true
                        )
                        
                        env.SCAN_EXIT_CODE = exitCode.toString()
                        
                        if (exitCode != 0) {
                            echo "⚠️ Scan completed with exit code: ${exitCode}"
                        } else {
                            echo "✅ Scan completed successfully"
                        }
                    }
                }
            }
            post {
                always {
                    // Archive scan results
                    archiveArtifacts(
                        artifacts: 'typosentinel-*.json,typosentinel-*.sarif,typosentinel-*.txt',
                        allowEmptyArchive: true,
                        fingerprint: true
                    )
                }
            }
        }
        
        stage('📊 Process Results') {
            steps {
                script {
                    echo "📊 Processing scan results..."
                    
                    if (fileExists('typosentinel-results.json')) {
                        // Parse results
                        def results = readJSON file: 'typosentinel-results.json'
                        def summary = results.summary ?: [:]
                        
                        env.TOTAL_PACKAGES = summary.total_packages ?: '0'
                        env.THREATS_FOUND = summary.threats_found ?: '0'
                        env.CRITICAL_THREATS = summary.severity_breakdown?.critical ?: '0'
                        env.HIGH_THREATS = summary.severity_breakdown?.high ?: '0'
                        env.MEDIUM_THREATS = summary.severity_breakdown?.medium ?: '0'
                        env.LOW_THREATS = summary.severity_breakdown?.low ?: '0'
                        
                        echo "📦 Total packages scanned: ${env.TOTAL_PACKAGES}"
                        echo "⚠️ Threats found: ${env.THREATS_FOUND}"
                        echo "🔴 Critical: ${env.CRITICAL_THREATS}"
                        echo "🟠 High: ${env.HIGH_THREATS}"
                        echo "🟡 Medium: ${env.MEDIUM_THREATS}"
                        echo "🟢 Low: ${env.LOW_THREATS}"
                        
                        // Generate summary report
                        def reportContent = """
# 🛡️ TypoSentinel Security Report

**Repository:** ${env.JOB_NAME}  
**Branch:** ${env.BRANCH_NAME}  
**Build:** #${env.BUILD_NUMBER}  
**Commit:** ${env.GIT_COMMIT_SHORT}  
**Project Type:** ${env.DETECTED_PROJECT_TYPE}  
**Scan Type:** ${params.SCAN_TYPE}  
**Scan Date:** ${new Date().format('yyyy-MM-dd HH:mm:ss UTC')}

## 📊 Executive Summary
- **Total Packages Scanned:** ${env.TOTAL_PACKAGES}
- **Security Threats Found:** ${env.THREATS_FOUND}
- **Scan Duration:** ${currentBuild.durationString}

## 🎯 Severity Breakdown
| Severity | Count |
|----------|-------|
| Critical | ${env.CRITICAL_THREATS} |
| High     | ${env.HIGH_THREATS} |
| Medium   | ${env.MEDIUM_THREATS} |
| Low      | ${env.LOW_THREATS} |

## 🔗 Resources
- [Build Details](${env.BUILD_URL})
- [Console Output](${env.BUILD_URL}console)
- [Artifacts](${env.BUILD_URL}artifact/)
"""
                        
                        writeFile file: 'security-summary.md', text: reportContent
                        
                        // Set build result based on findings
                        if (Integer.parseInt(env.CRITICAL_THREATS) > 0) {
                            currentBuild.result = 'FAILURE'
                            echo "❌ Build marked as FAILURE due to critical threats"
                        } else if (Integer.parseInt(env.HIGH_THREATS) > 0 && params.FAIL_ON_HIGH) {
                            currentBuild.result = 'UNSTABLE'
                            echo "⚠️ Build marked as UNSTABLE due to high severity threats"
                        } else if (Integer.parseInt(env.THREATS_FOUND) > 0) {
                            currentBuild.result = 'UNSTABLE'
                            echo "⚠️ Build marked as UNSTABLE due to security threats"
                        } else {
                            echo "✅ No security threats detected"
                        }
                        
                    } else {
                        echo "❌ No results file found"
                        currentBuild.result = 'FAILURE'
                        env.SCAN_ERROR = 'true'
                    }
                }
            }
            post {
                always {
                    archiveArtifacts(
                        artifacts: 'security-summary.md',
                        allowEmptyArchive: true
                    )
                }
            }
        }
        
        stage('📋 Publish Results') {
            parallel {
                stage('SARIF Upload') {
                    when {
                        expression { fileExists('typosentinel-results.sarif') }
                    }
                    steps {
                        // Upload SARIF results to security dashboard
                        publishSarif(
                            sarif: 'typosentinel-results.sarif',
                            category: 'typosentinel'
                        )
                    }
                }
                
                stage('Test Results') {
                    when {
                        expression { fileExists('typosentinel-results.json') }
                    }
                    steps {
                        script {
                            // Convert results to JUnit format for trend analysis
                            def results = readJSON file: 'typosentinel-results.json'
                            def threats = results.threats ?: []
                            
                            def junitXml = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="TypoSentinel Security Scan" tests="${threats.size()}" failures="${threats.size()}" time="0">
"""
                            
                            threats.each { threat ->
                                junitXml += """
    <testcase name="${threat.package_name}" classname="Security.${threat.severity}">
        <failure message="${threat.description}" type="${threat.threat_type}">
Package: ${threat.package_name}
Severity: ${threat.severity}
Confidence: ${threat.confidence}
Description: ${threat.description}
        </failure>
    </testcase>
"""
                            }
                            
                            junitXml += "</testsuite>"
                            
                            writeFile file: 'typosentinel-junit.xml', text: junitXml
                        }
                        
                        publishTestResults(
                            testResultsPattern: 'typosentinel-junit.xml',
                            allowEmptyResults: true
                        )
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo "🏁 Pipeline completed with result: ${currentBuild.result ?: 'SUCCESS'}"
                
                // Clean up temporary files
                sh 'rm -f typosentinel-junit.xml'
            }
        }
        
        success {
            script {
                if (env.THREATS_FOUND && Integer.parseInt(env.THREATS_FOUND) == 0) {
                    echo "✅ Security scan passed - no threats detected"
                    
                    // Send success notification for scheduled builds
                    if (env.BUILD_CAUSE?.contains('TimerTrigger')) {
                        emailext(
                            subject: "✅ TypoSentinel Daily Scan - Clean",
                            body: """
Security scan completed successfully with no threats detected.

Repository: ${env.JOB_NAME}
Branch: ${env.BRANCH_NAME}
Build: #${env.BUILD_NUMBER}
Packages Scanned: ${env.TOTAL_PACKAGES ?: 'N/A'}

View Details: ${env.BUILD_URL}
                            """,
                            to: env.EMAIL_RECIPIENTS
                        )
                    }
                }
            }
        }
        
        unstable {
            script {
                echo "⚠️ Security threats detected but build continues"
                
                emailext(
                    subject: "⚠️ TypoSentinel Security Alert - ${env.JOB_NAME}",
                    body: """
Security threats have been detected in your repository.

Repository: ${env.JOB_NAME}
Branch: ${env.BRANCH_NAME}
Build: #${env.BUILD_NUMBER}
Commit: ${env.GIT_COMMIT_SHORT}

Threat Summary:
- Total Threats: ${env.THREATS_FOUND ?: '0'}
- Critical: ${env.CRITICAL_THREATS ?: '0'}
- High: ${env.HIGH_THREATS ?: '0'}
- Medium: ${env.MEDIUM_THREATS ?: '0'}
- Low: ${env.LOW_THREATS ?: '0'}

Please review the detailed report and address the security issues.

View Details: ${env.BUILD_URL}
Download Report: ${env.BUILD_URL}artifact/
                    """,
                    to: env.EMAIL_RECIPIENTS
                )
            }
        }
        
        failure {
            script {
                echo "❌ Pipeline failed"
                
                def subject = "🚨 TypoSentinel Critical Security Alert - ${env.JOB_NAME}"
                def body = """
CRITICAL security threats have been detected in your repository.

Repository: ${env.JOB_NAME}
Branch: ${env.BRANCH_NAME}
Build: #${env.BUILD_NUMBER}
Commit: ${env.GIT_COMMIT_SHORT}
Author: ${env.GIT_AUTHOR}

Threat Summary:
- Critical Threats: ${env.CRITICAL_THREATS ?: '0'}
- High Threats: ${env.HIGH_THREATS ?: '0'}
- Total Threats: ${env.THREATS_FOUND ?: '0'}

IMMEDIATE ACTION REQUIRED:
1. Review the detailed security report
2. Address critical and high severity threats
3. Update dependencies and packages
4. Re-run the security scan

View Details: ${env.BUILD_URL}
Console Output: ${env.BUILD_URL}console
Download Report: ${env.BUILD_URL}artifact/

This build has been marked as FAILED due to critical security threats.
                """
                
                // Send email notification
                emailext(
                    subject: subject,
                    body: body,
                    to: env.EMAIL_RECIPIENTS,
                    attachmentsPattern: 'security-summary.md,typosentinel-report.txt'
                )
                
                // Send Slack notification if configured
                if (params.NOTIFY_SECURITY && env.SLACK_WEBHOOK) {
                    script {
                        def slackMessage = [
                            text: "🚨 TypoSentinel Critical Security Alert",
                            attachments: [[
                                color: "danger",
                                title: "Critical Security Threats Detected",
                                fields: [
                                    [title: "Repository", value: env.JOB_NAME, short: true],
                                    [title: "Branch", value: env.BRANCH_NAME, short: true],
                                    [title: "Critical Threats", value: env.CRITICAL_THREATS ?: '0', short: true],
                                    [title: "High Threats", value: env.HIGH_THREATS ?: '0', short: true]
                                ],
                                actions: [[
                                    type: "button",
                                    text: "View Build",
                                    url: env.BUILD_URL
                                ]]
                            ]]
                        ]
                        
                        httpRequest(
                            httpMode: 'POST',
                            url: env.SLACK_WEBHOOK,
                            contentType: 'APPLICATION_JSON',
                            requestBody: groovy.json.JsonOutput.toJson(slackMessage)
                        )
                    }
                }
            }
        }
        
        cleanup {
            // Clean workspace on completion
            cleanWs(
                cleanWhenAborted: true,
                cleanWhenFailure: true,
                cleanWhenNotBuilt: true,
                cleanWhenSuccess: true,
                cleanWhenUnstable: true,
                deleteDirs: true
            )
        }
    }
}