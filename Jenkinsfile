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
                echo "=== Running TruffleHog Secret Scanning (Remote Repo)==="
                docker run --rm trufflesecurity/trufflehog:latest \
                git https://github.com/lazuto123/vuln-bank --json > trufflehog_report.json || true
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

        stage('SCA Snyk Test') {
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                script {
                    sh '''
                        echo "=== Running Snyk SCA Analysis ==="
                        docker run --rm \
                            -e SNYK_TOKEN=$SNYK_TOKEN \
                            -v $(pwd):/app \
                            -w /app \
                            snyk/snyk:python test --file=requirements.txt --package-manager=pip --json > snyk_report.json
                        echo "=== Snyk scan finished. Report saved to snyk_report.json ==="
                    '''
                }
                archiveArtifacts artifacts: 'snyk_report.json'
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
