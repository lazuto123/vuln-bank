pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Secret Scanning') {
            steps {
                sh '''
                    echo "=== Running TruffleHog Secret Scanning ==="
                    docker run --rm \
                        -v $WORKSPACE:/repo \
                        trufflesecurity/trufflehog:latest git /repo --json > trufflehog_report.json || true

                    echo "=== Scan finished. Report saved to trufflehog_report.json ==="
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trufflehog_report.json', allowEmptyArchive: true
                }
                failure {
                    echo "Secret scanning failed."
                }
            }
        }
        stage('Deploy') {
            steps {
                sshagent(['DeploymentSSHKey']) {
                    sh '''
                        ssh -o StrictHostKeyChecking=no deployment@192.168.0.115 "
                          cd ~/vuln-bank || git clone -b main https://github.com/lazuto123/vuln-bank ~/vuln-bank
                          cd ~/vuln-bank && git pull origin main
                          docker-compose down || true
                          docker-compose up -d --build
                        "
                    '''
                }
            }
        }
    }
}
