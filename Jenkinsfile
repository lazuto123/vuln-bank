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
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_TOKEN --entrypoint='
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Preparing CI requirements (patched install) ==="
                      cp requirements.txt requirements.ci.txt
                      sed -i 's/psycopg2-binary==2.9.9/psycopg2-binary==2.9.10/g' requirements.ci.txt
        
                      echo "=== Installing dependencies from requirements.ci.txt ==="
                      pip install --no-cache-dir -r requirements.ci.txt || true
        
                      echo "=== Running Snyk SCA Test against original requirements.txt ==="
                      snyk test --file=requirements.txt --package-manager=pip --json > snyk-scan-report.json || true
        
                      cat snyk-scan-report.json
                      echo "=== Snyk scan finished. Report saved to snyk-scan-report.json ==="
                    '''
                }
                archiveArtifacts artifacts: 'snyk-scan-report.json'
            }
        }

        stage('SAST Snyk Code') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_TOKEN --entrypoint='
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running Snyk SAST (Code Analysis) ==="
                      snyk code test --json > snyk-sast-report.json || true
        
                      cat snyk-sast-report.json
                      echo "=== Snyk SAST scan finished. Report saved to snyk-sast-report.json ==="
                    '''
                }
                archiveArtifacts artifacts: 'snyk-sast-report.json'
            }
        }

        stage('Dockerfile Misconfig (Hadolint)') {
            agent any
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running Hadolint on Dockerfile ==="
                      docker run --rm -v "$PWD":/data hadolint/hadolint:latest \
                        hadolint /data/Dockerfile -f json > hadolint-report.json || true
                      echo "=== Hadolint finished. Report saved to hadolint-report.json ==="
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'hadolint-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Compose Misconfig (KICS)') {
            agent any
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running KICS on docker-compose.yml ==="
                      mkdir -p kics-out
                      docker run --rm -v "$PWD":/src checkmarx/kics:latest \
                        scan --path /src/docker-compose.yml --output-path /src/kics-out --report-formats json || true
        
                      # ambil salah satu hasil JSON agar konsisten
                      if [ -f kics-out/results.json ]; then
                        mv kics-out/results.json kics-report.json
                      else
                        # fallback jika nama filenya lain
                        cat kics-out/*.json > kics-report.json 2>/dev/null || echo '{"ok":false,"error":"no output"}' > kics-report.json
                      fi
                      echo "=== KICS finished. Report saved to kics-report.json ==="
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'kics-report.json', allowEmptyArchive: true
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
