// TypoSentinel Jenkins Pipeline

pipeline {
    agent any
    
    stages {
        stage('Setup TypoSentinel') {
            steps {
                sh 'curl -sSL https://install.typosentinel.com | bash'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'typosentinel scan --format json --output scan-results.json'
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'scan-results.json',
                reportName: 'TypoSentinel Security Report'
            ])
        }
    }
}
